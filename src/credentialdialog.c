#include "config.h"

#include <string.h>

#include <glib/gi18n.h>

#include "credentialdialog.h"
#include "credentialstatuspage.h"
#include "qrcodepaintable.h"

/* At or below this, the remaining attempts are shown up front. */
#define ATTEMPTS_WARNING 3

struct _CredentialDialog
{
  AdwWindow parent;

  AdwToastOverlay *toast_overlay;
  AdwNavigationView *navigation_view;

  AdwNavigationPage *choose_page;
  GtkLabel *choose_title;
  GtkLabel *choose_description;
  GtkWidget *other_device_row;
  GtkWidget *security_key_row;

  GtkLabel *qr_description;
  GtkStack *qr_stack;
  GtkPicture *qr_picture;

  CredentialStatusPage *other_device_page;
  CredentialStatusPage *connect_key_page;

  AdwPasswordEntryRow *pin_row;
  GtkLabel *pin_status;

  GtkLabel *set_pin_description;
  AdwPasswordEntryRow *new_pin_row;
  AdwPasswordEntryRow *confirm_pin_row;
  GtkWidget *set_pin_button;

  CredentialStatusPage *touch_page;

  GtkLabel *passkey_description;
  GtkListBox *passkey_list;

  AdwNavigationPage *error_page;
  GtkLabel *error_title;
  GtkLabel *error_description;

  char *rp_id;
  gboolean has_hybrid;
  gboolean has_security_key;
  /* Tag of the first page: the transport chooser unless there is only one. */
  const char *root_tag;

  gboolean discovery_requested;
  gboolean pin_submitted;
  gboolean finished;
  guint discovery_idle_id;
  guint done_idle_id;
};

enum
{
  DISCOVERY_REQUESTED,
  PIN_ENTERED,
  NEW_PIN_ENTERED,
  CREDENTIAL_SELECTED,
  CANCELLED,
  DONE,
  N_SIGNALS,
};

static guint signals[N_SIGNALS];

G_DEFINE_FINAL_TYPE (CredentialDialog, credential_dialog, ADW_TYPE_WINDOW)

static const char * const security_key_tags[] = {
  "connect-key", "pin", "set-pin", "touch", "choose-passkey", NULL,
};

static const char * const hybrid_tags[] = {
  "qr", "connecting", "other-device", NULL,
};

static const char *
get_visible_tag (CredentialDialog *self)
{
  AdwNavigationPage *page = adw_navigation_view_get_visible_page (self->navigation_view);
  const char *tag = page ? adw_navigation_page_get_tag (page) : NULL;

  return tag ? tag : "";
}

/* Replaces the navigation stack with the root page followed by the given
 * tags, so the back button always leads towards the transport chooser. */
static void
navigate (CredentialDialog *self,
          const char       *first_tag,
          ...)
{
  g_autoptr(GPtrArray) tags = g_ptr_array_new ();
  const char *tag;
  va_list args;

  g_ptr_array_add (tags, (gpointer) self->root_tag);

  va_start (args, first_tag);
  for (tag = first_tag; tag != NULL; tag = va_arg (args, const char *))
    {
      if (!g_str_equal (tag, self->root_tag))
        g_ptr_array_add (tags, (gpointer) tag);
    }
  va_end (args);

  adw_navigation_view_replace_with_tags (self->navigation_view,
                                         (const char * const *) tags->pdata,
                                         tags->len);
}

/* For pages reached through a security key. */
static void
navigate_security_key (CredentialDialog *self,
                       const char       *tag)
{
  navigate (self, "connect-key", tag, NULL);
}

/* @format has a single %s for the website, which is shown in bold.
 * Returns Pango markup. */
static char *
format_with_rp_id (const char *format,
                   const char *rp_id)
{
  g_autofree char *escaped_format = g_markup_escape_text (format, -1);
  g_autofree char *bold = g_markup_printf_escaped ("<b>%s</b>", rp_id);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  return g_strdup_printf (escaped_format, bold);
#pragma GCC diagnostic pop
}

static void
set_markup_with_rp_id (GtkLabel   *label,
                       const char *format,
                       const char *rp_id)
{
  g_autofree char *markup = format_with_rp_id (format, rp_id);

  gtk_label_set_markup (label, markup);
}

static void
set_page_description_with_rp_id (CredentialStatusPage *page,
                                 const char           *format,
                                 const char           *rp_id)
{
  g_autofree char *markup = format_with_rp_id (format, rp_id);

  credential_status_page_set_description (page, markup);
}

/* For the icons that aren't in the icon theme. */
static void
load_icons (void)
{
  static gsize initialized = FALSE;

  if (g_once_init_enter (&initialized))
    {
      GtkIconTheme *default_theme = gtk_icon_theme_get_for_display (gdk_display_get_default ());

      gtk_icon_theme_add_resource_path (default_theme, "/org/freedesktop/portal/desktop/gnome/icons/");

      g_once_init_leave (&initialized, TRUE);
    }
}

static void
show_toast (CredentialDialog *self,
            const char       *title)
{
  adw_toast_overlay_add_toast (self->toast_overlay, adw_toast_new (title));
}

static void
clear_qr_code (CredentialDialog *self)
{
  gtk_picture_set_paintable (self->qr_picture, NULL);
  gtk_stack_set_visible_child_name (self->qr_stack, "waiting");
}

/* @format is a translated ngettext() string with a single %u. */
static char *
format_attempts_left (const char *format,
                      guint32     attempts_left)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  return g_strdup_printf (format, attempts_left);
#pragma GCC diagnostic pop
}

static gboolean
credential_dialog_close_request (GtkWindow *window)
{
  CredentialDialog *self = CREDENTIAL_DIALOG (window);

  if (self->finished)
    g_signal_emit (self, signals[DONE], 0);
  else
    g_signal_emit (self, signals[CANCELLED], 0);

  /* The owner destroys the dialog in response to the signal. */
  return TRUE;
}

static gboolean
emit_discovery_requested (gpointer user_data)
{
  CredentialDialog *self = user_data;

  self->discovery_idle_id = 0;
  g_signal_emit (self, signals[DISCOVERY_REQUESTED], 0);

  return G_SOURCE_REMOVE;
}

static void
credential_dialog_map (GtkWidget *widget)
{
  CredentialDialog *self = CREDENTIAL_DIALOG (widget);

  GTK_WIDGET_CLASS (credential_dialog_parent_class)->map (widget);

  /* credentialsd starts every transport at once, so discovery doesn't wait
   * for the user to pick one in the chooser. */
  if (!self->discovery_requested)
    {
      self->discovery_requested = TRUE;
      self->discovery_idle_id = g_idle_add (emit_discovery_requested, self);
    }
}

static gboolean
emit_done (gpointer user_data)
{
  CredentialDialog *self = user_data;

  self->done_idle_id = 0;
  g_signal_emit (self, signals[DONE], 0);

  return G_SOURCE_REMOVE;
}

/* Template callbacks */

static void
on_transport_row_activated_cb (CredentialDialog *self,
                               GtkListBoxRow    *row)
{
  if (GTK_WIDGET (row) == self->other_device_row)
    adw_navigation_view_push_by_tag (self->navigation_view, "qr");
  else if (GTK_WIDGET (row) == self->security_key_row)
    adw_navigation_view_push_by_tag (self->navigation_view, "connect-key");
}

static void
on_pin_page_shown_cb (CredentialDialog *self)
{
  gtk_widget_grab_focus (GTK_WIDGET (self->pin_row));
}

static void
on_pin_submitted_cb (CredentialDialog *self)
{
  const char *pin = gtk_editable_get_text (GTK_EDITABLE (self->pin_row));

  if (*pin == '\0' || !gtk_widget_get_sensitive (GTK_WIDGET (self->pin_row)))
    return;

  if (strlen (pin) > CREDENTIAL_MAX_PIN_LENGTH)
    {
      gtk_label_set_label (self->pin_status, _("The PIN is too long"));
      gtk_widget_add_css_class (GTK_WIDGET (self->pin_status), "error");
      gtk_widget_set_visible (GTK_WIDGET (self->pin_status), TRUE);
      return;
    }

  g_signal_emit (self, signals[PIN_ENTERED], 0, pin);

  gtk_editable_set_text (GTK_EDITABLE (self->pin_row), "");
  /* Stays insensitive until the daemon reports how it went. */
  gtk_widget_set_sensitive (GTK_WIDGET (self->pin_row), FALSE);
  self->pin_submitted = TRUE;
}

static void
on_set_pin_page_shown_cb (CredentialDialog *self)
{
  gtk_widget_grab_focus (GTK_WIDGET (self->new_pin_row));
}

static gboolean
new_pin_too_long (CredentialDialog *self)
{
  const char *new_pin = gtk_editable_get_text (GTK_EDITABLE (self->new_pin_row));

  return strlen (new_pin) > CREDENTIAL_MAX_PIN_LENGTH;
}

static gboolean
new_pins_match (CredentialDialog *self)
{
  const char *new_pin = gtk_editable_get_text (GTK_EDITABLE (self->new_pin_row));
  const char *confirm_pin = gtk_editable_get_text (GTK_EDITABLE (self->confirm_pin_row));

  return *new_pin != '\0' && g_str_equal (new_pin, confirm_pin);
}

static void
on_new_pin_changed_cb (CredentialDialog *self)
{
  const char *confirm_pin = gtk_editable_get_text (GTK_EDITABLE (self->confirm_pin_row));
  gboolean match = new_pins_match (self);
  gboolean too_long = new_pin_too_long (self);

  gtk_widget_set_sensitive (self->set_pin_button, match && !too_long);

  if (too_long)
    gtk_widget_add_css_class (GTK_WIDGET (self->new_pin_row), "error");
  else
    gtk_widget_remove_css_class (GTK_WIDGET (self->new_pin_row), "error");

  if (*confirm_pin != '\0' && !match)
    gtk_widget_add_css_class (GTK_WIDGET (self->confirm_pin_row), "error");
  else
    gtk_widget_remove_css_class (GTK_WIDGET (self->confirm_pin_row), "error");
}

static void
on_new_pin_submitted_cb (CredentialDialog *self)
{
  if (!new_pins_match (self) || new_pin_too_long (self) ||
      !gtk_widget_get_sensitive (GTK_WIDGET (self->new_pin_row)))
    return;

  g_signal_emit (self, signals[NEW_PIN_ENTERED], 0,
                 gtk_editable_get_text (GTK_EDITABLE (self->new_pin_row)));

  gtk_editable_set_text (GTK_EDITABLE (self->new_pin_row), "");
  gtk_editable_set_text (GTK_EDITABLE (self->confirm_pin_row), "");
  gtk_widget_set_sensitive (GTK_WIDGET (self->new_pin_row), FALSE);
  gtk_widget_set_sensitive (GTK_WIDGET (self->confirm_pin_row), FALSE);
}

static void
on_passkey_row_activated_cb (CredentialDialog *self,
                             GtkListBoxRow    *row)
{
  const char *id = g_object_get_data (G_OBJECT (row), "credential-id");

  if (id == NULL)
    return;

  g_signal_emit (self, signals[CREDENTIAL_SELECTED], 0, id);
  gtk_widget_set_sensitive (GTK_WIDGET (self->passkey_list), FALSE);
}

/* GObject */

static void
credential_dialog_dispose (GObject *object)
{
  CredentialDialog *self = CREDENTIAL_DIALOG (object);

  g_clear_handle_id (&self->discovery_idle_id, g_source_remove);
  g_clear_handle_id (&self->done_idle_id, g_source_remove);

  gtk_widget_dispose_template (GTK_WIDGET (self), CREDENTIAL_TYPE_DIALOG);

  G_OBJECT_CLASS (credential_dialog_parent_class)->dispose (object);
}

static void
credential_dialog_finalize (GObject *object)
{
  CredentialDialog *self = CREDENTIAL_DIALOG (object);

  g_clear_pointer (&self->rp_id, g_free);

  G_OBJECT_CLASS (credential_dialog_parent_class)->finalize (object);
}

static void
credential_dialog_class_init (CredentialDialogClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);
  GtkWindowClass *window_class = GTK_WINDOW_CLASS (klass);

  object_class->dispose = credential_dialog_dispose;
  object_class->finalize = credential_dialog_finalize;

  widget_class->map = credential_dialog_map;

  window_class->close_request = credential_dialog_close_request;

  g_type_ensure (CREDENTIAL_TYPE_STATUS_PAGE);

  gtk_widget_class_set_template_from_resource (widget_class, "/org/freedesktop/portal/desktop/gnome/credentialdialog.ui");

  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, toast_overlay);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, navigation_view);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, choose_page);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, choose_title);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, choose_description);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, other_device_row);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, security_key_row);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, qr_description);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, qr_stack);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, qr_picture);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, other_device_page);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, connect_key_page);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, pin_row);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, pin_status);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, set_pin_description);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, new_pin_row);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, confirm_pin_row);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, set_pin_button);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, touch_page);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, passkey_description);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, passkey_list);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, error_page);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, error_title);
  gtk_widget_class_bind_template_child (widget_class, CredentialDialog, error_description);

  gtk_widget_class_bind_template_callback (widget_class, on_transport_row_activated_cb);
  gtk_widget_class_bind_template_callback (widget_class, on_pin_page_shown_cb);
  gtk_widget_class_bind_template_callback (widget_class, on_pin_submitted_cb);
  gtk_widget_class_bind_template_callback (widget_class, on_set_pin_page_shown_cb);
  gtk_widget_class_bind_template_callback (widget_class, on_new_pin_changed_cb);
  gtk_widget_class_bind_template_callback (widget_class, on_new_pin_submitted_cb);
  gtk_widget_class_bind_template_callback (widget_class, on_passkey_row_activated_cb);

  signals[DISCOVERY_REQUESTED] =
    g_signal_new ("discovery-requested", G_TYPE_FROM_CLASS (klass),
                  G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                  G_TYPE_NONE, 0);
  signals[PIN_ENTERED] =
    g_signal_new ("pin-entered", G_TYPE_FROM_CLASS (klass),
                  G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                  G_TYPE_NONE, 1, G_TYPE_STRING | G_SIGNAL_TYPE_STATIC_SCOPE);
  signals[NEW_PIN_ENTERED] =
    g_signal_new ("new-pin-entered", G_TYPE_FROM_CLASS (klass),
                  G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                  G_TYPE_NONE, 1, G_TYPE_STRING | G_SIGNAL_TYPE_STATIC_SCOPE);
  signals[CREDENTIAL_SELECTED] =
    g_signal_new ("credential-selected", G_TYPE_FROM_CLASS (klass),
                  G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                  G_TYPE_NONE, 1, G_TYPE_STRING);
  signals[CANCELLED] =
    g_signal_new ("cancelled", G_TYPE_FROM_CLASS (klass),
                  G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                  G_TYPE_NONE, 0);
  signals[DONE] =
    g_signal_new ("done", G_TYPE_FROM_CLASS (klass),
                  G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
                  G_TYPE_NONE, 0);
}

static void
credential_dialog_init (CredentialDialog *self)
{
  load_icons ();
  gtk_widget_init_template (GTK_WIDGET (self));
}

static void
parse_sources (CredentialDialog *self,
               GVariant         *sources)
{
  GVariantIter iter;
  const char *transport;

  if (sources == NULL)
    return;

  g_variant_iter_init (&iter, sources);
  while (g_variant_iter_next (&iter, "(&s&s)", NULL, &transport))
    {
      if (g_str_equal (transport, "HybridQr") || g_str_equal (transport, "HybridLinked"))
        self->has_hybrid = TRUE;
      else if (g_str_equal (transport, "Usb") || g_str_equal (transport, "Nfc"))
        self->has_security_key = TRUE;
      else
        g_debug ("Ignoring unsupported credential transport %s", transport);
    }
}

CredentialDialog *
credential_dialog_new (CredentialOperation  operation,
                       const char          *app_name,
                       const char          *rp_id,
                       GVariant            *sources)
{
  CredentialDialog *self = g_object_new (CREDENTIAL_TYPE_DIALOG, NULL);
  gboolean create = operation == CREDENTIAL_OPERATION_CREATE;

  self->rp_id = g_strdup (rp_id);
  parse_sources (self, sources);

  /* The pages talk about the website, which is what the user recognises;
   * the requesting app is only named in the window title. */
  if (app_name != NULL && *app_name != '\0')
    {
      g_autofree char *title = NULL;

      if (create)
        /* Translators: %s is an application name */
        title = g_strdup_printf (_("Create Passkey – %s"), app_name);
      else
        /* Translators: %s is an application name */
        title = g_strdup_printf (_("Sign In with Passkey – %s"), app_name);
      gtk_window_set_title (GTK_WINDOW (self), title);
    }
  else
    {
      gtk_window_set_title (GTK_WINDOW (self),
                            create ? _("Create Passkey") : _("Sign In with Passkey"));
    }

  adw_navigation_page_set_title (self->choose_page,
                                 create ? _("Create Passkey") : _("Choose How to Sign In"));
  gtk_label_set_label (self->choose_title, adw_navigation_page_get_title (self->choose_page));

  if (create)
    {
      set_markup_with_rp_id (self->choose_description,
                             /* Translators: %s is a website, e.g. "example.org" */
                             _("Choose where to save your passkey for %s. Your choice determines how you sign in."),
                             rp_id);
      set_markup_with_rp_id (self->qr_description,
                             /* Translators: %s is a website, e.g. "example.org" */
                             _("Scan this QR code with a compatible device to save your passkey for %s"),
                             rp_id);
      set_page_description_with_rp_id (self->other_device_page,
                                       /* Translators: %s is a website, e.g. "example.org" */
                                       _("Follow the instructions on your other device to save your passkey for %s"),
                                       rp_id);
      set_page_description_with_rp_id (self->connect_key_page,
                                       /* Translators: %s is a website, e.g. "example.org" */
                                       _("Connect and activate your security key to continue saving your passkey for %s"),
                                       rp_id);
    }
  else
    {
      set_markup_with_rp_id (self->choose_description,
                             /* Translators: %s is a website, e.g. "example.org" */
                             _("Choose how to sign in to %s."),
                             rp_id);
      set_markup_with_rp_id (self->qr_description,
                             /* Translators: %s is a website, e.g. "example.org" */
                             _("Scan this QR code with a compatible device to sign in to %s"),
                             rp_id);
      set_page_description_with_rp_id (self->other_device_page,
                                       /* Translators: %s is a website, e.g. "example.org" */
                                       _("Follow the instructions on your other device to sign in to %s"),
                                       rp_id);
      set_page_description_with_rp_id (self->connect_key_page,
                                       /* Translators: %s is a website, e.g. "example.org" */
                                       _("Connect and activate your security key to continue signing in to %s"),
                                       rp_id);
    }

  set_markup_with_rp_id (self->passkey_description,
                         /* Translators: %s is a website, e.g. "example.org" */
                         _("Choose how to sign in to %s."),
                         rp_id);

  gtk_widget_set_visible (self->other_device_row, self->has_hybrid);
  gtk_widget_set_visible (self->security_key_row, self->has_security_key);

  /* With a single transport there is nothing to choose. */
  if (self->has_hybrid && !self->has_security_key)
    self->root_tag = "qr";
  else if (self->has_security_key && !self->has_hybrid)
    self->root_tag = "connect-key";
  else
    self->root_tag = "choose";

  navigate (self, NULL);

  return self;
}

void
credential_dialog_show_needs_pin (CredentialDialog *self,
                                  guint32           attempts_left)
{
  gboolean known = attempts_left != CREDENTIAL_ATTEMPTS_UNKNOWN;
  g_autofree char *status = NULL;

  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  /* Being asked again right after submitting means the PIN was wrong. */
  if (self->pin_submitted)
    {
      if (known)
        status = format_attempts_left (ngettext ("Incorrect PIN. %u attempt left.",
                                                 "Incorrect PIN. %u attempts left.",
                                                 attempts_left),
                                       attempts_left);
      else
        status = g_strdup (_("Incorrect PIN"));

      gtk_widget_add_css_class (GTK_WIDGET (self->pin_status), "error");
    }
  else if (known && attempts_left <= ATTEMPTS_WARNING)
    {
      status = format_attempts_left (ngettext ("%u attempt left", "%u attempts left", attempts_left),
                                     attempts_left);
      gtk_widget_remove_css_class (GTK_WIDGET (self->pin_status), "error");
    }

  self->pin_submitted = FALSE;

  gtk_label_set_label (self->pin_status, status);
  gtk_widget_set_visible (GTK_WIDGET (self->pin_status), status != NULL);

  gtk_editable_set_text (GTK_EDITABLE (self->pin_row), "");
  gtk_widget_set_sensitive (GTK_WIDGET (self->pin_row), TRUE);

  if (g_str_equal (get_visible_tag (self), "pin"))
    gtk_widget_grab_focus (GTK_WIDGET (self->pin_row));
  else
    navigate_security_key (self, "pin");
}

void
credential_dialog_show_pin_not_set (CredentialDialog *self,
                                    const char       *error)
{
  const char *description;

  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  if (g_strcmp0 (error, "PinTooShort") == 0)
    description = _("The PIN is too short. Choose a longer PIN.");
  else if (g_strcmp0 (error, "PinTooLong") == 0)
    description = _("The PIN is too long. Choose a shorter PIN.");
  else if (g_strcmp0 (error, "PinPolicyViolation") == 0)
    description = _("The PIN does not meet the security key’s requirements. Choose a different PIN.");
  else if (g_strcmp0 (error, "PinChangeRequired") == 0)
    description = _("The security key requires a new PIN. Choose a new PIN to continue.");
  else
    description = _("This security key needs a PIN. Choose a PIN to continue.");

  gtk_label_set_label (self->set_pin_description, description);

  gtk_editable_set_text (GTK_EDITABLE (self->new_pin_row), "");
  gtk_editable_set_text (GTK_EDITABLE (self->confirm_pin_row), "");
  gtk_widget_set_sensitive (GTK_WIDGET (self->new_pin_row), TRUE);
  gtk_widget_set_sensitive (GTK_WIDGET (self->confirm_pin_row), TRUE);

  if (g_str_equal (get_visible_tag (self), "set-pin"))
    gtk_widget_grab_focus (GTK_WIDGET (self->new_pin_row));
  else
    navigate_security_key (self, "set-pin");
}

static void
show_touch (CredentialDialog *self,
            const char       *icon_name,
            const char       *title,
            const char       *description)
{
  g_autofree char *markup = g_markup_escape_text (description, -1);

  self->pin_submitted = FALSE;

  adw_navigation_page_set_title (ADW_NAVIGATION_PAGE (self->touch_page), title);
  credential_status_page_set_description (self->touch_page, markup);
  credential_status_page_set_icon_name (self->touch_page, icon_name);

  navigate_security_key (self, "touch");
}

void
credential_dialog_show_needs_user_verification (CredentialDialog *self,
                                                guint32           attempts_left)
{
  g_autofree char *description = NULL;

  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  if (attempts_left != CREDENTIAL_ATTEMPTS_UNKNOWN && attempts_left <= ATTEMPTS_WARNING)
    description = format_attempts_left (ngettext ("Use the fingerprint sensor on your security key to proceed. %u attempt left.",
                                                  "Use the fingerprint sensor on your security key to proceed. %u attempts left.",
                                                  attempts_left),
                                        attempts_left);
  else
    description = g_strdup (_("Use the fingerprint sensor on your security key to proceed"));

  show_touch (self, "auth-fingerprint-symbolic", _("Verify with Security Key"), description);
}

void
credential_dialog_show_needs_user_presence (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  show_touch (self, "credential-touch-symbolic", _("Touch Security Key"), _("Touch your device to proceed"));
}

void
credential_dialog_show_select_credential (CredentialDialog *self,
                                          GVariant         *credentials)
{
  GVariantIter iter;
  GVariant *credential;

  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  self->pin_submitted = FALSE;

  gtk_list_box_remove_all (self->passkey_list);
  gtk_widget_set_sensitive (GTK_WIDGET (self->passkey_list), TRUE);

  g_variant_iter_init (&iter, credentials);
  while (g_variant_iter_next (&iter, "@a{sv}", &credential))
    {
      g_autoptr(GVariant) owned = credential;
      const char *id = NULL;
      const char *name = NULL;
      const char *display_name = NULL;
      GtkWidget *row;

      if (!g_variant_lookup (credential, "id", "&s", &id))
        continue;
      g_variant_lookup (credential, "name", "&s", &name);
      g_variant_lookup (credential, "display_name", "&s", &display_name);

      if (display_name == NULL || *display_name == '\0')
        display_name = name;
      if (display_name == NULL || *display_name == '\0')
        display_name = _("Unnamed Passkey");

      row = adw_action_row_new ();
      /* Names come from the website, so never interpret them as markup. */
      adw_preferences_row_set_use_markup (ADW_PREFERENCES_ROW (row), FALSE);
      adw_preferences_row_set_title (ADW_PREFERENCES_ROW (row), display_name);

      if (name != NULL && *name != '\0')
        {
          g_autofree char *subtitle = NULL;

          /* Translators: %s is an account name, e.g. "jdoe@example.org" */
          subtitle = g_strdup_printf (_("Passkey for %s saved on this security key"), name);
          adw_action_row_set_subtitle (ADW_ACTION_ROW (row), subtitle);
        }

      adw_action_row_add_suffix (ADW_ACTION_ROW (row),
                                 g_object_new (GTK_TYPE_IMAGE,
                                               "icon-name", "go-next-symbolic",
                                               "accessible-role", GTK_ACCESSIBLE_ROLE_PRESENTATION,
                                               NULL));
      gtk_list_box_row_set_activatable (GTK_LIST_BOX_ROW (row), TRUE);
      g_object_set_data_full (G_OBJECT (row), "credential-id", g_strdup (id), g_free);

      gtk_list_box_append (self->passkey_list, row);
    }

  navigate_security_key (self, "choose-passkey");
}

void
credential_dialog_show_hybrid_qr (CredentialDialog *self,
                                  const char       *qr_data)
{
  g_autoptr(QrCodePaintable) paintable = NULL;

  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  paintable = qr_code_paintable_new (qr_data);
  if (paintable == NULL)
    {
      g_warning ("Could not encode the hybrid QR code");
      clear_qr_code (self);
      return;
    }

  /* The user reaches the QR page through the chooser, so only update it. */
  gtk_picture_set_paintable (self->qr_picture, GDK_PAINTABLE (paintable));
  gtk_stack_set_visible_child_name (self->qr_stack, "code");
}

void
credential_dialog_show_hybrid_connecting (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  navigate (self, "connecting", NULL);
}

void
credential_dialog_show_hybrid_connected (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  navigate (self, "other-device", NULL);
}

void
credential_dialog_show_usb_connected (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  /* The next notification says what the key needs; until then keep asking
   * the user to activate it. */
  if (!g_strv_contains (security_key_tags, get_visible_tag (self)))
    navigate (self, "connect-key", NULL);
}

void
credential_dialog_show_nfc_connected (CredentialDialog *self)
{
  credential_dialog_show_usb_connected (self);
}

void
credential_dialog_show_hybrid_restarting (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  /* A new QR code follows. */
  clear_qr_code (self);

  if (g_strv_contains (hybrid_tags, get_visible_tag (self)))
    {
      navigate (self, "qr", NULL);
      show_toast (self, _("Could not connect to the other device. Try again."));
    }
}

static void
show_security_key_restarting (CredentialDialog *self)
{
  self->pin_submitted = FALSE;

  if (g_strv_contains (security_key_tags, get_visible_tag (self)))
    {
      navigate (self, "connect-key", NULL);
      show_toast (self, _("Could not use the security key. Try again."));
    }
}

void
credential_dialog_show_usb_restarting (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  show_security_key_restarting (self);
}

void
credential_dialog_show_nfc_restarting (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  show_security_key_restarting (self);
}

void
credential_dialog_show_completed (CredentialDialog *self)
{
  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  if (self->finished)
    return;

  /* The app shows the result; there is nothing left to tell the user. */
  self->finished = TRUE;
  self->done_idle_id = g_idle_add (emit_done, self);
}

void
credential_dialog_show_error (CredentialDialog *self,
                              CredentialError   error)
{
  const char *title;
  const char *description;

  g_return_if_fail (CREDENTIAL_IS_DIALOG (self));

  switch (error)
    {
    case CREDENTIAL_ERROR_TIMED_OUT:
      title = _("Request Timed Out");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("Try again to continue with %s.");
      break;
    case CREDENTIAL_ERROR_CANCELLED:
      title = _("Request Cancelled");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("The request from %s was cancelled.");
      break;
    case CREDENTIAL_ERROR_AUTHENTICATOR:
      title = _("Security Key Error");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("The security key could not complete the request from %s.");
      break;
    case CREDENTIAL_ERROR_NO_CREDENTIALS:
      title = _("No Passkeys Found");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("There are no passkeys for %s on this security key.");
      break;
    case CREDENTIAL_ERROR_CREDENTIAL_EXCLUDED:
      title = _("Passkey Already Exists");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("This security key already has a passkey for %s.");
      break;
    case CREDENTIAL_ERROR_PIN_ATTEMPTS_EXHAUSTED:
      title = _("Security Key Locked");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("Too many incorrect PIN attempts. The security key can’t be used for %s until it is reset.");
      break;
    case CREDENTIAL_ERROR_PIN_NOT_SET:
      title = _("PIN Required");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("Set a PIN on this security key to use it with %s.");
      break;
    case CREDENTIAL_ERROR_INTERNAL:
    default:
      title = _("Something Went Wrong");
      /* Translators: %s is a website, e.g. "example.org" */
      description = _("The request from %s could not be completed.");
      break;
    }

  self->finished = TRUE;

  /* Whatever was being retried no longer matters. */
  adw_toast_overlay_dismiss_all (self->toast_overlay);

  adw_navigation_page_set_title (self->error_page, title);
  gtk_label_set_label (self->error_title, title);
  set_markup_with_rp_id (self->error_description, description, self->rp_id);

  adw_navigation_view_replace_with_tags (self->navigation_view,
                                         (const char *[]) { "error" }, 1);
}

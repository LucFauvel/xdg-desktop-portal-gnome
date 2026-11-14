/*
 * Backend for the experimental Credential portal, driven by credentialsd.
 *
 * Event loop for one ceremony:
 *
 *   credentialsd                       this backend                 CredentialDialog
 *   ────────────                       ────────────                 ────────────────
 *   CreateSession(handle, …)  ───────► export Session at handle ──► new + present
 *                                                                   map
 *   ◄─────── DiscoveryRequested  ◄──── unicast signal  ◄─────────── discovery-requested
 *   Notify*(handle, …)        ───────► validate sender ───────────► show_*()
 *   ◄─────── ClientPinEntered(fd) ◄─── PIN → memfd_secret ◄──────── pin-entered
 *   ◄─────── CredentialSelected  ◄──── unicast signal  ◄─────────── credential-selected
 *   NotifyCeremonyCompleted   ───────►                 ───────────► show_completed
 *                                      tear down       ◄─────────── done
 *   ◄─────── Session.Closed      ◄──── unicast signal  ◄─────────── cancelled
 *   Session.Close()           ───────► tear down (no Closed)
 *   caller leaves the bus     ───────► tear down (no Closed)
 *
 * Every outgoing signal is unicast to the session's caller: they can carry
 * secrets (PIN fds), and credentialsd only matches signals addressed to it.
 */

#define _GNU_SOURCE 1

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <glib/gi18n.h>
#include <gio/gdesktopappinfo.h>
#include <gio/gunixfdlist.h>
#include <glib/gstdio.h>
#include <gxdp.h>

#include "xdg-desktop-portal-dbus.h"

#include "credential.h"
#include "credentialdialog.h"
#include "session.h"
#include "utils.h"

#define CREDENTIAL_INTERFACE "org.freedesktop.impl.portal.experimental.Credential"
#define SESSION_INTERFACE "org.freedesktop.impl.portal.Session"

/* QR payloads are well under a page; refuse anything unreasonable. */
#define MAX_QR_DATA_LENGTH 4096

typedef struct _CredentialSession
{
  Session parent;

  GDBusConnection *connection;
  guint peer_watch_id;

  CredentialDialog *dialog;
  GtkWindow *fake_parent;
  GxdpExternalWindow *external_parent;

  gboolean completed;
} CredentialSession;

typedef struct _CredentialSessionClass
{
  SessionClass parent_class;
} CredentialSessionClass;

static GType credential_session_get_type (void);
G_DEFINE_TYPE (CredentialSession, credential_session, session_get_type ())

static gboolean
is_credential_session (Session *session)
{
  return G_TYPE_CHECK_INSTANCE_TYPE (session, credential_session_get_type ());
}

/* Outgoing signals */

static gboolean
send_unicast_signal (CredentialSession  *self,
                     const char         *path,
                     const char         *interface,
                     const char         *signal,
                     GVariant           *body,
                     GUnixFDList        *fd_list,
                     GError            **error)
{
  Session *session = (Session *) self;
  g_autoptr(GDBusMessage) message = NULL;

  message = g_dbus_message_new_signal (path, interface, signal);
  g_dbus_message_set_destination (message, session_get_peer_name (session));
  g_dbus_message_set_body (message, body);
  if (fd_list)
    g_dbus_message_set_unix_fd_list (message, fd_list);

  return g_dbus_connection_send_message (self->connection,
                                         message,
                                         G_DBUS_SEND_MESSAGE_FLAGS_NONE,
                                         NULL,
                                         error);
}

static void
emit_user_interacted (CredentialSession *self,
                      const char        *signal,
                      GVariant          *body,
                      GUnixFDList       *fd_list)
{
  g_autoptr(GError) error = NULL;

  if (!send_unicast_signal (self, DESKTOP_PORTAL_OBJECT_PATH, CREDENTIAL_INTERFACE,
                            signal, body, fd_list, &error))
    g_warning ("Failed to emit %s for %s: %s",
               signal, session_get_id ((Session *) self), error->message);
}

static void
emit_session_closed (CredentialSession *self)
{
  g_autoptr(GError) error = NULL;
  Session *session = (Session *) self;

  if (!send_unicast_signal (self, session_get_id (session), SESSION_INTERFACE,
                            "Closed", NULL, NULL, &error))
    g_warning ("Failed to emit Closed for %s: %s",
               session_get_id (session), error->message);
}

/* Secret transfer */

/*
 * Copies @pin into a memfd_secret so it never sits in a regular, swappable
 * file, matching what credentialsd expects. Returns -1 and sets @error on
 * failure; the caller owns the returned fd.
 */
static int
write_pin_to_secret_fd (const char  *pin,
                        GError     **error)
{
  size_t len = strlen (pin);
  void *mem;
  int fd;

  if (len == 0 || len > CREDENTIAL_MAX_PIN_LENGTH)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "PIN must be between 1 and %d bytes", CREDENTIAL_MAX_PIN_LENGTH);
      return -1;
    }

#ifdef SYS_memfd_secret
  fd = syscall (SYS_memfd_secret, O_CLOEXEC);
#else
  fd = -1;
  errno = ENOSYS;
#endif
  if (fd < 0)
    {
      int saved_errno = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved_errno),
                   "memfd_secret failed: %s", g_strerror (saved_errno));
      return -1;
    }

  if (ftruncate (fd, len) < 0)
    {
      int saved_errno = errno;
      close (fd);
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved_errno),
                   "ftruncate failed: %s", g_strerror (saved_errno));
      return -1;
    }

  mem = mmap (NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mem == MAP_FAILED)
    {
      int saved_errno = errno;
      close (fd);
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved_errno),
                   "mmap failed: %s", g_strerror (saved_errno));
      return -1;
    }

  memcpy (mem, pin, len);
  munmap (mem, len);

  return fd;
}

/* Reads the QR payload credentialsd sends with NotifyHybridStarted. */
static char *
read_qr_data_from_fd (GUnixFDList  *fd_list,
                      GVariant     *handle,
                      GError      **error)
{
  g_autofd int fd = -1;
  struct stat st;
  char *data;
  void *mem;

  if (fd_list == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "No file descriptors were sent");
      return NULL;
    }

  fd = g_unix_fd_list_get (fd_list, g_variant_get_handle (handle), error);
  if (fd < 0)
    return NULL;

  if (fstat (fd, &st) < 0)
    {
      int saved_errno = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved_errno),
                   "fstat failed: %s", g_strerror (saved_errno));
      return NULL;
    }

  if (st.st_size <= 0 || st.st_size > MAX_QR_DATA_LENGTH)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Unexpected QR data length %" G_GINT64_FORMAT,
                   (gint64) st.st_size);
      return NULL;
    }

  /* memfd_secret only supports mmap, not read(). */
  mem = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (mem == MAP_FAILED)
    {
      int saved_errno = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved_errno),
                   "mmap failed: %s", g_strerror (saved_errno));
      return NULL;
    }

  data = g_strndup (mem, st.st_size);
  munmap (mem, st.st_size);

  if (!g_utf8_validate (data, -1, NULL))
    {
      g_free (data);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "QR data is not valid UTF-8");
      return NULL;
    }

  return data;
}

/* Teardown */

static void
credential_session_teardown (CredentialSession *self,
                             gboolean           notify_peer)
{
  Session *session = (Session *) self;

  if (session->closed)
    return;

  g_debug ("Closing credential session %s (notify peer: %d)",
           session_get_id (session), notify_peer);

  if (notify_peer)
    emit_session_closed (self);

  /* Closed was sent unicast above; don't let Session broadcast it. */
  session_close (session, FALSE);
}

static void
credential_session_close (Session *session)
{
  CredentialSession *self = (CredentialSession *) session;

  g_clear_handle_id (&self->peer_watch_id, g_bus_unwatch_name);

  if (self->dialog)
    {
      g_signal_handlers_disconnect_by_data (self->dialog, self);
      gtk_window_destroy (GTK_WINDOW (self->dialog));
      g_clear_object (&self->dialog);
    }

  g_clear_pointer (&self->fake_parent, gtk_window_destroy);
  g_clear_object (&self->external_parent);
}

static void
on_peer_vanished (GDBusConnection *connection,
                  const char      *name,
                  gpointer         user_data)
{
  CredentialSession *self = user_data;

  g_debug ("Credential session caller %s left the bus", name);
  credential_session_teardown (self, FALSE);
}

/* Dialog → caller */

static void
on_dialog_discovery_requested (CredentialDialog  *dialog,
                               CredentialSession *self)
{
  emit_user_interacted (self, "DiscoveryRequested",
                        g_variant_new ("(o@a{sv})",
                                       session_get_id ((Session *) self),
                                       g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0)),
                        NULL);
}

static void
send_pin (CredentialSession *self,
          const char        *signal,
          const char        *pin)
{
  g_autoptr(GUnixFDList) fd_list = NULL;
  g_autoptr(GError) error = NULL;
  int fd;
  int handle;

  fd = write_pin_to_secret_fd (pin, &error);
  if (fd < 0)
    {
      g_warning ("Failed to prepare PIN for %s: %s",
                 session_get_id ((Session *) self), error->message);
      credential_dialog_show_error (self->dialog, CREDENTIAL_ERROR_INTERNAL);
      return;
    }

  fd_list = g_unix_fd_list_new ();
  handle = g_unix_fd_list_append (fd_list, fd, &error);
  close (fd);
  if (handle < 0)
    {
      g_warning ("Failed to attach PIN fd: %s", error->message);
      credential_dialog_show_error (self->dialog, CREDENTIAL_ERROR_INTERNAL);
      return;
    }

  emit_user_interacted (self, signal,
                        g_variant_new ("(oh@a{sv})",
                                       session_get_id ((Session *) self),
                                       handle,
                                       g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0)),
                        fd_list);
}

static void
on_dialog_pin_entered (CredentialDialog  *dialog,
                       const char        *pin,
                       CredentialSession *self)
{
  send_pin (self, "ClientPinEntered", pin);
}

static void
on_dialog_new_pin_entered (CredentialDialog  *dialog,
                           const char        *pin,
                           CredentialSession *self)
{
  send_pin (self, "SetDevicePin", pin);
}

static void
on_dialog_credential_selected (CredentialDialog  *dialog,
                               const char        *id,
                               CredentialSession *self)
{
  emit_user_interacted (self, "CredentialSelected",
                        g_variant_new ("(os@a{sv})",
                                       session_get_id ((Session *) self),
                                       id,
                                       g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0)),
                        NULL);
}

static void
on_dialog_cancelled (CredentialDialog  *dialog,
                     CredentialSession *self)
{
  credential_session_teardown (self, TRUE);
}

static void
on_dialog_done (CredentialDialog  *dialog,
                CredentialSession *self)
{
  /* After success credentialsd already has its answer. After an error, tell
   * it the user dismissed the dialog so it does not wait on us. */
  credential_session_teardown (self, !self->completed);
}

/* Caller → dialog */

static CredentialSession *
lookup_credential_session (GDBusMethodInvocation *invocation,
                           const char            *session_handle)
{
  Session *session = lookup_session (session_handle);

  if (session == NULL || !is_credential_session (session) || session->closed)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_FOUND,
                                             "No session exists at %s",
                                             session_handle);
      return NULL;
    }

  /* Only the caller that created a session may drive it. */
  if (g_strcmp0 (session_get_peer_name (session),
                 g_dbus_method_invocation_get_sender (invocation)) != 0)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_NOT_ALLOWED,
                                             "Session %s belongs to another caller",
                                             session_handle);
      return NULL;
    }

  return (CredentialSession *) session;
}

static char *
lookup_app_name (const char *app_id)
{
  g_autoptr(GDesktopAppInfo) info = NULL;
  g_autofree char *desktop_id = NULL;

  if (app_id == NULL || *app_id == '\0')
    return NULL;

  desktop_id = g_strconcat (app_id, ".desktop", NULL);
  info = g_desktop_app_info_new (desktop_id);
  if (info == NULL)
    {
      g_debug ("No desktop file for %s, showing the app ID", app_id);
      return g_strdup (app_id);
    }

  return g_strdup (g_app_info_get_display_name (G_APP_INFO (info)));
}

static gboolean
handle_create_session (XdpImplExperimentalCredential *object,
                       GDBusMethodInvocation         *invocation,
                       const char                    *arg_session_handle,
                       const char                    *arg_parent_window,
                       const char                    *arg_origin,
                       guint                          arg_type,
                       GVariant                      *arg_sources,
                       const char                    *arg_app_id,
                       guint                          arg_app_pid,
                       GVariant                      *arg_options)
{
  g_autoptr(GError) error = NULL;
  g_autofree char *app_name = NULL;
  g_auto(GVariantDict) options = G_VARIANT_DICT_INIT (arg_options);
  GDBusConnection *connection = g_dbus_method_invocation_get_connection (invocation);
  const char *sender = g_dbus_method_invocation_get_sender (invocation);
  const char *rp_id = NULL;
  const char *activation_token = NULL;
  CredentialSession *self;
  GdkSurface *surface;

  if (arg_type != CREDENTIAL_OPERATION_CREATE && arg_type != CREDENTIAL_OPERATION_GET)
    {
      g_dbus_method_invocation_return_error (invocation, XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                                             "Unknown credential type %u", arg_type);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (!g_variant_dict_lookup (&options, "rp_id", "&s", &rp_id) || *rp_id == '\0')
    {
      g_dbus_method_invocation_return_error (invocation, XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                                             "rp_id is required for public key credential requests");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  if (lookup_session (arg_session_handle) != NULL)
    {
      g_warning ("Caller %s requested session %s that already exists",
                 sender, arg_session_handle);
      g_dbus_method_invocation_return_error (invocation, XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_EXISTS,
                                             "Session %s already exists", arg_session_handle);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  g_variant_dict_lookup (&options, "activation_token", "&s", &activation_token);

  g_debug ("Creating credential session %s for %s (rp %s, origin %s, pid %u)",
           arg_session_handle, arg_app_id, rp_id, arg_origin, arg_app_pid);

  self = g_object_new (credential_session_get_type (),
                       "id", arg_session_handle,
                       "peer-name", sender,
                       NULL);
  self->connection = g_object_ref (connection);

  if (!session_export ((Session *) self, connection, &error))
    {
      g_warning ("Failed to export credential session: %s", error->message);
      g_dbus_method_invocation_return_error (invocation, XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_FAILED,
                                             "Could not create session");
      session_close ((Session *) self, FALSE);
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  self->peer_watch_id = g_bus_watch_name_on_connection (connection,
                                                        sender,
                                                        G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                        NULL,
                                                        on_peer_vanished,
                                                        self,
                                                        NULL);

  app_name = lookup_app_name (arg_app_id);

  self->dialog = g_object_ref_sink (credential_dialog_new (arg_type, app_name, rp_id, arg_sources));
  g_signal_connect (self->dialog, "discovery-requested",
                    G_CALLBACK (on_dialog_discovery_requested), self);
  g_signal_connect (self->dialog, "pin-entered",
                    G_CALLBACK (on_dialog_pin_entered), self);
  g_signal_connect (self->dialog, "new-pin-entered",
                    G_CALLBACK (on_dialog_new_pin_entered), self);
  g_signal_connect (self->dialog, "credential-selected",
                    G_CALLBACK (on_dialog_credential_selected), self);
  g_signal_connect (self->dialog, "cancelled",
                    G_CALLBACK (on_dialog_cancelled), self);
  g_signal_connect (self->dialog, "done",
                    G_CALLBACK (on_dialog_done), self);

  if (arg_parent_window && *arg_parent_window)
    {
      self->external_parent = gxdp_external_window_new_from_handle (arg_parent_window);
      if (!self->external_parent)
        g_warning ("Failed to associate portal window with parent window %s",
                   arg_parent_window);
    }

  self->fake_parent = g_object_new (GTK_TYPE_WINDOW, NULL);
  gtk_window_set_transient_for (GTK_WINDOW (self->dialog), self->fake_parent);

  if (activation_token && *activation_token)
    gtk_window_set_startup_id (GTK_WINDOW (self->dialog), activation_token);

  gtk_widget_realize (GTK_WIDGET (self->dialog));
  surface = gtk_native_get_surface (GTK_NATIVE (self->dialog));
  if (self->external_parent)
    gxdp_external_window_set_parent_of (self->external_parent, surface);

  gtk_window_present (GTK_WINDOW (self->dialog));

  xdp_impl_experimental_credential_complete_create_session (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/*
 * Most Notify* methods only carry the session handle. This expands to a
 * handler that looks up the session and calls the matching dialog function.
 */
#define DEFINE_SIMPLE_NOTIFY(method, dialog_fn)                                 \
  static gboolean                                                               \
  handle_##method (XdpImplExperimentalCredential *object,                       \
                   GDBusMethodInvocation         *invocation,                   \
                   const char                    *arg_session_handle,           \
                   GVariant                      *arg_options)                  \
  {                                                                             \
    CredentialSession *self =                                                   \
      lookup_credential_session (invocation, arg_session_handle);               \
    if (self == NULL)                                                           \
      return G_DBUS_METHOD_INVOCATION_HANDLED;                                  \
    dialog_fn (self->dialog);                                                   \
    xdp_impl_experimental_credential_complete_##method (object, invocation);    \
    return G_DBUS_METHOD_INVOCATION_HANDLED;                                    \
  }

DEFINE_SIMPLE_NOTIFY (notify_needs_user_presence, credential_dialog_show_needs_user_presence)
DEFINE_SIMPLE_NOTIFY (notify_hybrid_connecting, credential_dialog_show_hybrid_connecting)
DEFINE_SIMPLE_NOTIFY (notify_hybrid_connected, credential_dialog_show_hybrid_connected)
DEFINE_SIMPLE_NOTIFY (notify_nfc_connected, credential_dialog_show_nfc_connected)
DEFINE_SIMPLE_NOTIFY (notify_usb_connected, credential_dialog_show_usb_connected)
DEFINE_SIMPLE_NOTIFY (notify_hybrid_restarting, credential_dialog_show_hybrid_restarting)
DEFINE_SIMPLE_NOTIFY (notify_usb_restarting, credential_dialog_show_usb_restarting)
DEFINE_SIMPLE_NOTIFY (notify_nfc_restarting, credential_dialog_show_nfc_restarting)

#undef DEFINE_SIMPLE_NOTIFY

static gboolean
handle_notify_needs_pin (XdpImplExperimentalCredential *object,
                         GDBusMethodInvocation         *invocation,
                         const char                    *arg_session_handle,
                         guint                          arg_attempts_left,
                         GVariant                      *arg_options)
{
  CredentialSession *self = lookup_credential_session (invocation, arg_session_handle);

  if (self == NULL)
    return G_DBUS_METHOD_INVOCATION_HANDLED;

  credential_dialog_show_needs_pin (self->dialog, arg_attempts_left);
  xdp_impl_experimental_credential_complete_notify_needs_pin (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_notify_pin_not_set (XdpImplExperimentalCredential *object,
                           GDBusMethodInvocation         *invocation,
                           const char                    *arg_session_handle,
                           const char                    *arg_error,
                           GVariant                      *arg_options)
{
  CredentialSession *self = lookup_credential_session (invocation, arg_session_handle);

  if (self == NULL)
    return G_DBUS_METHOD_INVOCATION_HANDLED;

  credential_dialog_show_pin_not_set (self->dialog, arg_error);
  xdp_impl_experimental_credential_complete_notify_pin_not_set (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_notify_needs_user_verification (XdpImplExperimentalCredential *object,
                                       GDBusMethodInvocation         *invocation,
                                       const char                    *arg_session_handle,
                                       guint                          arg_attempts_left,
                                       GVariant                      *arg_options)
{
  CredentialSession *self = lookup_credential_session (invocation, arg_session_handle);

  if (self == NULL)
    return G_DBUS_METHOD_INVOCATION_HANDLED;

  credential_dialog_show_needs_user_verification (self->dialog, arg_attempts_left);
  xdp_impl_experimental_credential_complete_notify_needs_user_verification (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_notify_selecting_credential (XdpImplExperimentalCredential *object,
                                    GDBusMethodInvocation         *invocation,
                                    const char                    *arg_session_handle,
                                    GVariant                      *arg_credentials,
                                    GVariant                      *arg_options)
{
  CredentialSession *self = lookup_credential_session (invocation, arg_session_handle);

  if (self == NULL)
    return G_DBUS_METHOD_INVOCATION_HANDLED;

  credential_dialog_show_select_credential (self->dialog, arg_credentials);
  xdp_impl_experimental_credential_complete_notify_selecting_credential (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_notify_hybrid_started (XdpImplExperimentalCredential *object,
                              GDBusMethodInvocation         *invocation,
                              GUnixFDList                   *fd_list,
                              const char                    *arg_session_handle,
                              GVariant                      *arg_invocation_data,
                              GVariant                      *arg_options)
{
  g_autoptr(GError) error = NULL;
  g_autofree char *qr_data = NULL;
  CredentialSession *self = lookup_credential_session (invocation, arg_session_handle);

  if (self == NULL)
    return G_DBUS_METHOD_INVOCATION_HANDLED;

  qr_data = read_qr_data_from_fd (fd_list, arg_invocation_data, &error);
  if (qr_data == NULL)
    {
      g_warning ("Failed to read hybrid QR data for %s: %s",
                 arg_session_handle, error->message);
      g_dbus_method_invocation_return_error (invocation, XDG_DESKTOP_PORTAL_ERROR,
                                             XDG_DESKTOP_PORTAL_ERROR_INVALID_ARGUMENT,
                                             "Could not read QR data");
      return G_DBUS_METHOD_INVOCATION_HANDLED;
    }

  credential_dialog_show_hybrid_qr (self->dialog, qr_data);
  xdp_impl_experimental_credential_complete_notify_hybrid_started (object, invocation, NULL);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_notify_ceremony_completed (XdpImplExperimentalCredential *object,
                                  GDBusMethodInvocation         *invocation,
                                  const char                    *arg_session_handle)
{
  CredentialSession *self = lookup_credential_session (invocation, arg_session_handle);

  if (self == NULL)
    return G_DBUS_METHOD_INVOCATION_HANDLED;

  self->completed = TRUE;
  credential_dialog_show_completed (self->dialog);
  xdp_impl_experimental_credential_complete_notify_ceremony_completed (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
handle_notify_error_occurred (XdpImplExperimentalCredential *object,
                              GDBusMethodInvocation         *invocation,
                              const char                    *arg_session_handle,
                              guint                          arg_error)
{
  CredentialSession *self = lookup_credential_session (invocation, arg_session_handle);

  if (self == NULL)
    return G_DBUS_METHOD_INVOCATION_HANDLED;

  /* Unknown codes, e.g. from a newer frontend, get a generic message. */

  credential_dialog_show_error (self->dialog, arg_error);
  xdp_impl_experimental_credential_complete_notify_error_occurred (object, invocation);

  return G_DBUS_METHOD_INVOCATION_HANDLED;
}

/* GObject */

static void
credential_session_finalize (GObject *object)
{
  CredentialSession *self = (CredentialSession *) object;

  g_clear_object (&self->connection);

  G_OBJECT_CLASS (credential_session_parent_class)->finalize (object);
}

static void
credential_session_init (CredentialSession *self)
{
}

static void
credential_session_class_init (CredentialSessionClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  SessionClass *session_class = (SessionClass *) klass;

  object_class->finalize = credential_session_finalize;
  session_class->close = credential_session_close;
}

gboolean
credential_init (GDBusConnection  *bus,
                 GError          **error)
{
  GDBusInterfaceSkeleton *helper;

  helper = G_DBUS_INTERFACE_SKELETON (xdp_impl_experimental_credential_skeleton_new ());

  g_signal_connect (helper, "handle-create-session",
                    G_CALLBACK (handle_create_session), NULL);
  g_signal_connect (helper, "handle-notify-needs-pin",
                    G_CALLBACK (handle_notify_needs_pin), NULL);
  g_signal_connect (helper, "handle-notify-pin-not-set",
                    G_CALLBACK (handle_notify_pin_not_set), NULL);
  g_signal_connect (helper, "handle-notify-needs-user-verification",
                    G_CALLBACK (handle_notify_needs_user_verification), NULL);
  g_signal_connect (helper, "handle-notify-needs-user-presence",
                    G_CALLBACK (handle_notify_needs_user_presence), NULL);
  g_signal_connect (helper, "handle-notify-selecting-credential",
                    G_CALLBACK (handle_notify_selecting_credential), NULL);
  g_signal_connect (helper, "handle-notify-hybrid-started",
                    G_CALLBACK (handle_notify_hybrid_started), NULL);
  g_signal_connect (helper, "handle-notify-hybrid-connecting",
                    G_CALLBACK (handle_notify_hybrid_connecting), NULL);
  g_signal_connect (helper, "handle-notify-hybrid-connected",
                    G_CALLBACK (handle_notify_hybrid_connected), NULL);
  g_signal_connect (helper, "handle-notify-nfc-connected",
                    G_CALLBACK (handle_notify_nfc_connected), NULL);
  g_signal_connect (helper, "handle-notify-usb-connected",
                    G_CALLBACK (handle_notify_usb_connected), NULL);
  g_signal_connect (helper, "handle-notify-hybrid-restarting",
                    G_CALLBACK (handle_notify_hybrid_restarting), NULL);
  g_signal_connect (helper, "handle-notify-usb-restarting",
                    G_CALLBACK (handle_notify_usb_restarting), NULL);
  g_signal_connect (helper, "handle-notify-nfc-restarting",
                    G_CALLBACK (handle_notify_nfc_restarting), NULL);
  g_signal_connect (helper, "handle-notify-ceremony-completed",
                    G_CALLBACK (handle_notify_ceremony_completed), NULL);
  g_signal_connect (helper, "handle-notify-error-occurred",
                    G_CALLBACK (handle_notify_error_occurred), NULL);

  xdp_impl_experimental_credential_set_version (XDP_IMPL_EXPERIMENTAL_CREDENTIAL (helper), 1);

  if (!g_dbus_interface_skeleton_export (helper,
                                         bus,
                                         DESKTOP_PORTAL_OBJECT_PATH,
                                         error))
    return FALSE;

  g_debug ("providing %s", g_dbus_interface_skeleton_get_info (helper)->name);

  return TRUE;
}

#include "config.h"

#include "credentialstatuspage.h"

/* A page that only tells the user what is going on: its title as the
 * heading, a description and an icon. */
struct _CredentialStatusPage
{
  AdwNavigationPage parent;

  GtkImage *icon;
  GtkLabel *description;
};

enum
{
  PROP_0,
  PROP_ICON_NAME,
  PROP_DESCRIPTION,
  N_PROPS,
};

static GParamSpec *properties[N_PROPS];

G_DEFINE_FINAL_TYPE (CredentialStatusPage, credential_status_page, ADW_TYPE_NAVIGATION_PAGE)

static void
credential_status_page_get_property (GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
  CredentialStatusPage *self = CREDENTIAL_STATUS_PAGE (object);

  switch (prop_id)
    {
    case PROP_ICON_NAME:
      g_value_set_string (value, gtk_image_get_icon_name (self->icon));
      break;

    case PROP_DESCRIPTION:
      g_value_set_string (value, gtk_label_get_label (self->description));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
credential_status_page_set_property (GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
  CredentialStatusPage *self = CREDENTIAL_STATUS_PAGE (object);

  switch (prop_id)
    {
    case PROP_ICON_NAME:
      credential_status_page_set_icon_name (self, g_value_get_string (value));
      break;

    case PROP_DESCRIPTION:
      credential_status_page_set_description (self, g_value_get_string (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
credential_status_page_class_init (CredentialStatusPageClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

  object_class->get_property = credential_status_page_get_property;
  object_class->set_property = credential_status_page_set_property;

  properties[PROP_ICON_NAME] =
    g_param_spec_string ("icon-name", NULL, NULL, NULL,
                         G_PARAM_READWRITE | G_PARAM_EXPLICIT_NOTIFY | G_PARAM_STATIC_STRINGS);
  properties[PROP_DESCRIPTION] =
    g_param_spec_string ("description", NULL, NULL, NULL,
                         G_PARAM_READWRITE | G_PARAM_EXPLICIT_NOTIFY | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties (object_class, N_PROPS, properties);

  gtk_widget_class_set_template_from_resource (widget_class, "/org/freedesktop/portal/desktop/gnome/credentialstatuspage.ui");

  gtk_widget_class_bind_template_child (widget_class, CredentialStatusPage, icon);
  gtk_widget_class_bind_template_child (widget_class, CredentialStatusPage, description);
}

static void
credential_status_page_init (CredentialStatusPage *self)
{
  gtk_widget_init_template (GTK_WIDGET (self));
}

void
credential_status_page_set_icon_name (CredentialStatusPage *self,
                                      const char           *icon_name)
{
  g_return_if_fail (CREDENTIAL_IS_STATUS_PAGE (self));

  if (g_strcmp0 (gtk_image_get_icon_name (self->icon), icon_name) == 0)
    return;

  gtk_image_set_from_icon_name (self->icon, icon_name);
  gtk_widget_set_visible (GTK_WIDGET (self->icon), icon_name != NULL);

  g_object_notify_by_pspec (G_OBJECT (self), properties[PROP_ICON_NAME]);
}

void
credential_status_page_set_description (CredentialStatusPage *self,
                                        const char           *description)
{
  g_return_if_fail (CREDENTIAL_IS_STATUS_PAGE (self));

  if (g_strcmp0 (gtk_label_get_label (self->description), description) == 0)
    return;

  gtk_label_set_markup (self->description, description ? description : "");

  g_object_notify_by_pspec (G_OBJECT (self), properties[PROP_DESCRIPTION]);
}

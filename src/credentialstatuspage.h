#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

#define CREDENTIAL_TYPE_STATUS_PAGE (credential_status_page_get_type ())
G_DECLARE_FINAL_TYPE (CredentialStatusPage, credential_status_page, CREDENTIAL, STATUS_PAGE, AdwNavigationPage)

void credential_status_page_set_icon_name (CredentialStatusPage *self,
                                           const char           *icon_name);

/* @description is Pango markup. */
void credential_status_page_set_description (CredentialStatusPage *self,
                                             const char           *description);

G_END_DECLS

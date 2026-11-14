#pragma once

#include <adwaita.h>

G_BEGIN_DECLS

/*
 * CredentialDialog is the view for one credential ceremony. credential.c owns
 * the D-Bus side and drives the dialog through the functions below; the
 * dialog reports user input back through its signals:
 *
 *   discovery-requested ()        dialog is ready, start looking for authenticators
 *   pin-entered (const char *pin) user entered the client PIN
 *   new-pin-entered (const char*) user chose a new device PIN
 *   credential-selected (const char *id)
 *   cancelled ()                  user dismissed the dialog before completion
 *   done ()                       dialog finished (after completion/error) and can be destroyed
 *
 * PIN strings passed to the signals are only valid for the duration of the
 * emission. Handlers must not keep copies.
 */

typedef enum
{
  CREDENTIAL_OPERATION_CREATE = 0,
  CREDENTIAL_OPERATION_GET = 1,
} CredentialOperation;

typedef enum
{
  CREDENTIAL_ERROR_INTERNAL = 0x80000001,
  CREDENTIAL_ERROR_TIMED_OUT = 0x80000002,
  CREDENTIAL_ERROR_CANCELLED = 0x80000003,
  CREDENTIAL_ERROR_AUTHENTICATOR = 0x80000004,
  CREDENTIAL_ERROR_NO_CREDENTIALS = 0x80000005,
  CREDENTIAL_ERROR_CREDENTIAL_EXCLUDED = 0x80000006,
  CREDENTIAL_ERROR_PIN_ATTEMPTS_EXHAUSTED = 0x80000007,
  CREDENTIAL_ERROR_PIN_NOT_SET = 0x80000008,
} CredentialError;

/* Passed for attempts_left when the authenticator does not report it. */
#define CREDENTIAL_ATTEMPTS_UNKNOWN G_MAXUINT32

/* Longest PIN CTAP allows, in bytes of UTF-8. */
#define CREDENTIAL_MAX_PIN_LENGTH 63

#define CREDENTIAL_TYPE_DIALOG (credential_dialog_get_type ())
G_DECLARE_FINAL_TYPE (CredentialDialog, credential_dialog, CREDENTIAL, DIALOG, AdwWindow)

CredentialDialog *credential_dialog_new (CredentialOperation  operation,
                                         const char          *app_name,
                                         const char          *rp_id,
                                         GVariant            *devices);

void credential_dialog_show_needs_pin (CredentialDialog *self,
                                       guint32           attempts_left);

/* @error is the PinNotSetError string from credentialsd. */
void credential_dialog_show_pin_not_set (CredentialDialog *self,
                                         const char       *error);

void credential_dialog_show_needs_user_verification (CredentialDialog *self,
                                                     guint32           attempts_left);

void credential_dialog_show_needs_user_presence (CredentialDialog *self);

/* @credentials is aa{sv} with id, name and optional display_name. */
void credential_dialog_show_select_credential (CredentialDialog *self,
                                               GVariant         *credentials);

void credential_dialog_show_hybrid_qr (CredentialDialog *self,
                                       const char       *qr_data);

void credential_dialog_show_hybrid_connecting (CredentialDialog *self);

void credential_dialog_show_hybrid_connected (CredentialDialog *self);

void credential_dialog_show_usb_connected (CredentialDialog *self);

void credential_dialog_show_nfc_connected (CredentialDialog *self);

/* A transport failed in a non-terminal way and is retrying. */
void credential_dialog_show_hybrid_restarting (CredentialDialog *self);

void credential_dialog_show_usb_restarting (CredentialDialog *self);

void credential_dialog_show_nfc_restarting (CredentialDialog *self);

void credential_dialog_show_completed (CredentialDialog *self);

void credential_dialog_show_error (CredentialDialog *self,
                                   CredentialError   error);

G_END_DECLS

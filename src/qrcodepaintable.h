#pragma once

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define QR_CODE_TYPE_PAINTABLE (qr_code_paintable_get_type ())
G_DECLARE_FINAL_TYPE (QrCodePaintable, qr_code_paintable, QR_CODE, PAINTABLE, GObject)

/* Returns NULL if @text cannot be encoded. */
QrCodePaintable *qr_code_paintable_new (const char *text);

G_END_DECLS

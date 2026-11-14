#include "config.h"

#include <math.h>
#include <qrencode.h>

#include "qrcodepaintable.h"

/* Light margin around the code, in modules, as required by the QR spec. */
#define QUIET_ZONE 4

/* Pixels per module at the natural size. */
#define MODULE_SIZE 4

struct _QrCodePaintable
{
  GObject parent;

  int width;      /* modules per side, without quiet zone */
  guint8 *modules; /* width * width, non-zero for dark modules */
};

static void qr_code_paintable_paintable_init (GdkPaintableInterface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (QrCodePaintable, qr_code_paintable, G_TYPE_OBJECT,
                               G_IMPLEMENT_INTERFACE (GDK_TYPE_PAINTABLE,
                                                      qr_code_paintable_paintable_init))

static void
qr_code_paintable_snapshot (GdkPaintable *paintable,
                            GdkSnapshot  *snapshot,
                            double        width,
                            double        height)
{
  QrCodePaintable *self = QR_CODE_PAINTABLE (paintable);
  /* Scanners need dark-on-light, so don't follow the style. */
  const GdkRGBA light = { 1, 1, 1, 1 };
  const GdkRGBA dark = { 0, 0, 0, 1 };
  int total = self->width + 2 * QUIET_ZONE;
  double size = MIN (width, height);
  /* Whole pixels per module keep the edges sharp. */
  double module = MAX (1.0, floor (size / total));
  double offset_x = floor ((width - module * total) / 2);
  double offset_y = floor ((height - module * total) / 2);

  gtk_snapshot_append_color (GTK_SNAPSHOT (snapshot), &light,
                             &GRAPHENE_RECT_INIT (offset_x, offset_y,
                                                  module * total, module * total));

  for (int y = 0; y < self->width; y++)
    {
      for (int x = 0; x < self->width; x++)
        {
          if (!self->modules[y * self->width + x])
            continue;

          gtk_snapshot_append_color (GTK_SNAPSHOT (snapshot), &dark,
                                     &GRAPHENE_RECT_INIT (offset_x + (x + QUIET_ZONE) * module,
                                                          offset_y + (y + QUIET_ZONE) * module,
                                                          module, module));
        }
    }
}

static GdkPaintableFlags
qr_code_paintable_get_flags (GdkPaintable *paintable)
{
  return GDK_PAINTABLE_STATIC_CONTENTS | GDK_PAINTABLE_STATIC_SIZE;
}

static int
qr_code_paintable_get_intrinsic_size (GdkPaintable *paintable)
{
  QrCodePaintable *self = QR_CODE_PAINTABLE (paintable);

  return (self->width + 2 * QUIET_ZONE) * MODULE_SIZE;
}

static double
qr_code_paintable_get_intrinsic_aspect_ratio (GdkPaintable *paintable)
{
  return 1.0;
}

static void
qr_code_paintable_paintable_init (GdkPaintableInterface *iface)
{
  iface->snapshot = qr_code_paintable_snapshot;
  iface->get_flags = qr_code_paintable_get_flags;
  iface->get_intrinsic_width = qr_code_paintable_get_intrinsic_size;
  iface->get_intrinsic_height = qr_code_paintable_get_intrinsic_size;
  iface->get_intrinsic_aspect_ratio = qr_code_paintable_get_intrinsic_aspect_ratio;
}

static void
qr_code_paintable_finalize (GObject *object)
{
  QrCodePaintable *self = QR_CODE_PAINTABLE (object);

  g_free (self->modules);

  G_OBJECT_CLASS (qr_code_paintable_parent_class)->finalize (object);
}

static void
qr_code_paintable_class_init (QrCodePaintableClass *klass)
{
  G_OBJECT_CLASS (klass)->finalize = qr_code_paintable_finalize;
}

static void
qr_code_paintable_init (QrCodePaintable *self)
{
}

QrCodePaintable *
qr_code_paintable_new (const char *text)
{
  QrCodePaintable *self;
  QRcode *code;

  g_return_val_if_fail (text != NULL, NULL);

  code = QRcode_encodeString (text, 0, QR_ECLEVEL_L, QR_MODE_8, TRUE);
  if (code == NULL)
    return NULL;

  self = g_object_new (QR_CODE_TYPE_PAINTABLE, NULL);
  self->width = code->width;
  self->modules = g_new (guint8, code->width * code->width);
  /* Bit 0 of each byte is the module colour; the rest is metadata. */
  for (int i = 0; i < code->width * code->width; i++)
    self->modules[i] = code->data[i] & 1;

  QRcode_free (code);

  return self;
}

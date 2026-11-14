#pragma once

#include <gio/gio.h>

gboolean credential_init (GDBusConnection  *bus,
                          GError          **error);

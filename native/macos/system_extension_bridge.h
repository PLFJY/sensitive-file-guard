#ifndef GUARD_SYSTEM_EXTENSION_BRIDGE_H
#define GUARD_SYSTEM_EXTENSION_BRIDGE_H

#include <stddef.h>

int guard_system_extension_activate(const char *identifier, char *error, size_t error_len);
int guard_system_extension_deactivate(const char *identifier, char *error, size_t error_len);
int guard_system_extension_refresh(const char *identifier, char *error, size_t error_len);
int guard_system_extension_status(const char *identifier, char *diagnostic, size_t diagnostic_len);
int guard_has_entitlement(const char *entitlement, char *error, size_t error_len);
int guard_path_has_entitlement(const char *path, const char *entitlement,
                               char *error, size_t error_len);

#endif

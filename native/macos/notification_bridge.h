#ifndef GUARD_NOTIFICATION_BRIDGE_H
#define GUARD_NOTIFICATION_BRIDGE_H

#include <stddef.h>

int guard_user_notification(const char *title,
                            const char *body,
                            char *error_buffer,
                            size_t error_buffer_length);

#endif

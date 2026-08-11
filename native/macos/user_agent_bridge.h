#ifndef GUARD_USER_AGENT_BRIDGE_H
#define GUARD_USER_AGENT_BRIDGE_H

#include <stddef.h>

// Values match GuardUserAgentStatus in platform-macos. Negative values are
// bridge/configuration failures with a diagnostic copied into error_buffer.
int guard_user_agent_status(const char *plist_name,
                            char *error_buffer,
                            size_t error_buffer_length);
int guard_user_agent_register(const char *plist_name,
                              char *error_buffer,
                              size_t error_buffer_length);
int guard_user_agent_unregister(const char *plist_name,
                                char *error_buffer,
                                size_t error_buffer_length);
void guard_user_agent_open_settings(void);

#endif

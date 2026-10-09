#ifndef OPENFORTIVPN_MANAGER_CONTROL_H
#define OPENFORTIVPN_MANAGER_CONTROL_H
#include <stddef.h>
struct tunnel;
/* Experimental private stdin protocol; never multiplex with cookie-on-stdin. */
int manager_control_init(const char *attempt_id);
int manager_control_enabled(void);
const char *manager_control_attempt(void);
int manager_control_decode(const char *line, const char *request_id,
                           const char *action, char *response, size_t capacity);
int manager_control_otp(const char *prompt, char *response, size_t capacity);
int manager_control_network_gate(struct tunnel *tunnel);
int manager_control_network_apply(struct tunnel *tunnel);
int manager_control_network_release(struct tunnel *tunnel);
int manager_control_network_interface_up(struct tunnel *tunnel);
/* Separate startup barrier; no credentials or administrative input. */
int manager_launch_init(const char *descriptor);
int manager_launch_wait(void);
#endif

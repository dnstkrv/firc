#ifndef FIRC_IFADDR_H
#define FIRC_IFADDR_H

#include <stddef.h>

/* Writes the first IPv4 address of interface name as text; 0, or -1 when it has none. */
int firc_iface_ipv4(const char *name, char *out, size_t cap);

#endif

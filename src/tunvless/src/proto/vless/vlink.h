#ifndef STEER_VLINK_H
#define STEER_VLINK_H
#include <stddef.h>
#include "vless.h"

size_t vless_node_link(const struct vless_node *n, char *out, size_t cap);

#define VLESS_CTL_NAME_MAX 100
#define VLESS_CTL_NODES_MAX ((size_t)4 << 20)
void vless_name_cut(char *name);

#endif

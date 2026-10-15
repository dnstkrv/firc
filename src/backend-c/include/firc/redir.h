#ifndef FIRC_REDIR_H
#define FIRC_REDIR_H

#include <stddef.h>
#include <stdint.h>

#include "firc/err.h"
#include "firc/iptables.h"

#define FIRC_REDIR_CHAIN_SUFFIX "REDIR"

typedef struct {
    uint32_t mark;
    uint16_t port;
} firc_redir_group_t;

/* Stages <prefix>REDIR, one REDIRECT per group, and its jump at nat/PREROUTING 1 (TCP, handled bit, destination not
   local); n == 0 stages nothing, so the write drops both. A v4 engine only: v6 refuses REDIRECT. */
firc_err_t firc_redir_build_rules(firc_ipt_t *ipt4, const char *chain_prefix, const firc_redir_group_t *g, size_t n);

/* N of a canonical tunvless<N> with N 0..99, else -1. */
int firc_redir_device(const char *iface);

#endif

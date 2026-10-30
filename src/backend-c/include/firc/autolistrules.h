#ifndef FIRC_AUTOLISTRULES_H
#define FIRC_AUTOLISTRULES_H

#include <stddef.h>

#include "firc/err.h"
#include "firc/fakeip.h"
#include "firc/iptables.h"
#include "firc/taprules.h"

#define FIRC_AUTOLIST_GROUP_HELLO 6
#define FIRC_AUTOLIST_GROUP_RESET 7
#define FIRC_AUTOLIST_GROUP_WORKS 8

#define FIRC_AUTOLIST_RESET_BYTES "0:4096"
#define FIRC_AUTOLIST_WORKS_BYTES "4097:16384"

#define FIRC_AUTOLIST_CHAIN_SUFFIX "AUTO"
#define FIRC_AUTOLIST_PROBE_SUFFIX "PROBE"

firc_err_t firc_autolist_rules_build(const firc_fakeip_t *pool, const char *const *lan, size_t n_lan,
                                     firc_tap_rule_fn fn, void *ud);

firc_err_t firc_autolist_rules_install(firc_ipt_t *ipt, const char *chain_prefix, const firc_fakeip_t *pool,
                                       const char *const *lan, size_t n_lan);

firc_err_t firc_autolist_rules_supported(firc_ipt_t *ipt, const char *chain_prefix, const firc_fakeip_t *pool,
                                         const char *const *lan, size_t n_lan);

#endif

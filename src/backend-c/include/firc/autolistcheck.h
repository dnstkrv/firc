#ifndef FIRC_AUTOLISTCHECK_H
#define FIRC_AUTOLISTCHECK_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/autolist.h"
#include "firc/id.h"
#include "firc/loop.h"
#include "firc/sub_fetch.h"

typedef enum {
    FIRC_AUTOLIST_UNKNOWN = 0,
    FIRC_AUTOLIST_REACHABLE,
    FIRC_AUTOLIST_BLOCKED,
} firc_autolist_verdict_t;

typedef struct firc_autolist_result {
    uint8_t verdict;
    uint8_t why;
    bool short_body;
    uint32_t bytes;
    char error[160];
} firc_autolist_result_t;

typedef struct firc_autolist_probe {
    firc_id_t group;
    firc_id_t rule;
    char host[FIRC_AUTOLIST_NAME_MAX];
    firc_autolist_result_t result;
} firc_autolist_probe_t;

typedef struct firc_autolist_check_opts {
    char iface[16];
    char dns[64];
    uint16_t dns_port;
    uint32_t timeout_s;
} firc_autolist_check_opts_t;

typedef void (*firc_autolist_probe_fn)(const char *host, const firc_autolist_check_opts_t *o, _Atomic bool *stop,
                                      firc_autolist_result_t *out);

typedef void (*firc_autolist_checked_fn)(void *ud, uint64_t gen, const firc_autolist_probe_t *probes, size_t n);

typedef struct firc_autolist_check firc_autolist_check_t;

/* Judges one probe from how far it got; why is a firc_al_why_t, 0 unless blocked. Pure. */
void firc_autolist_classify(const firc_sub_fetch_info_t *info, uint32_t bytes, bool stalled, bool complete,
                            firc_autolist_result_t *out);

/* Fetches https://host/ through o and judges it into out. */
void firc_autolist_probe_once(const char *host, const firc_autolist_check_opts_t *o, _Atomic bool *stop,
                              firc_autolist_result_t *out);

firc_autolist_check_t *firc_autolist_check_start(firc_loop_t *loop, const firc_autolist_check_opts_t *o,
                                                 const firc_autolist_probe_t *probes, size_t n, uint64_t gen,
                                                 firc_autolist_probe_fn probe, firc_autolist_checked_fn done,
                                                 void *ud);

void firc_autolist_check_free(firc_autolist_check_t *c);

typedef firc_err_t (*firc_autolist_post_fn)(firc_loop_t *loop, firc_post_cb cb, void *ud, firc_post_drop_cb drop);

/* NULL restores firc_loop_post_with_drop. */
void firc_autolist_check_set_post_for_test(firc_autolist_post_fn post);

#endif

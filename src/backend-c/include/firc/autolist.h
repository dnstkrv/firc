#ifndef FIRC_AUTOLIST_H
#define FIRC_AUTOLIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/fakeip.h"

#define FIRC_AUTOLIST_FLOWS 1024
#define FIRC_AUTOLIST_HOSTS 512
#define FIRC_AUTOLIST_HINTS 512
#define FIRC_AUTOLIST_FLOW_SECS 60
#define FIRC_AUTOLIST_HINT_SECS 600
#define FIRC_AUTOLIST_NAME_MAX 254

#define FIRC_AUTOLIST_FAIL_THRESHOLD 3
#define FIRC_AUTOLIST_FAIL_SECS 60
#define FIRC_AUTOLIST_RETRANS_THRESHOLD 3

typedef struct firc_autolist firc_autolist_t;

typedef struct firc_autolist_params {
    uint32_t fail_threshold;
    uint32_t fail_secs;
    uint32_t retrans_threshold;
} firc_autolist_params_t;

typedef struct firc_autolist_flow {
    firc_ip_t client, server;
    uint16_t client_port, server_port;
} firc_autolist_flow_t;

typedef enum {
    FIRC_AUTOLIST_RETRANS = 1,
    FIRC_AUTOLIST_RESET,
} firc_autolist_why_t;

typedef struct firc_autolist_failure {
    char host[FIRC_AUTOLIST_NAME_MAX];
    firc_ip_t client;
    uint32_t fails;
    uint8_t why;
    bool listed;
} firc_autolist_failure_t;

firc_autolist_t *firc_autolist_new(void);
void firc_autolist_free(firc_autolist_t *a);

void firc_autolist_set_params(firc_autolist_t *a, const firc_autolist_params_t *p);

void firc_autolist_hint(firc_autolist_t *a, const firc_ip_t *client, const char *name, const firc_ip_t *reals,
                        size_t n_reals, int64_t now);

bool firc_autolist_hello(firc_autolist_t *a, const firc_autolist_flow_t *f, uint32_t seq, const char *sni,
                         int64_t now, firc_autolist_failure_t *out);

bool firc_autolist_reply(firc_autolist_t *a, const firc_autolist_flow_t *f, bool rst, int64_t now,
                         firc_autolist_failure_t *out);

size_t firc_autolist_counting(const firc_autolist_t *a, int64_t now);

#endif

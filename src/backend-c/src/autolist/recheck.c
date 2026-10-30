#include "firc/autolistcheck.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "firc/ifcheck.h"
#include "firc/log.h"
#include "firc/sub_fetch.h"

struct firc_autolist_check {
    firc_loop_t *loop;
    firc_autolist_check_opts_t opts;
    firc_autolist_probe_t *probes;
    size_t n;
    uint64_t gen;
    firc_autolist_probe_fn probe;
    firc_autolist_checked_fn done;
    void *ud;
    _Atomic bool stop;
    pthread_t thread;
    bool started;
};

typedef struct {
    firc_autolist_checked_fn done;
    void *ud;
    uint64_t gen;
    firc_autolist_probe_t *probes;
    size_t n;
} result_t;

static bool first_bytes_only(void *ud, const uint8_t *data, size_t len) {
    (void)ud;
    (void)data;
    (void)len;
    return false;
}

static bool keep_going(void *ud, size_t bytes, size_t total) {
    (void)bytes;
    (void)total;
    _Atomic bool *stop = ud;
    return stop == NULL || !atomic_load(stop);
}

firc_autolist_verdict_t firc_autolist_probe_once(const char *host, const firc_autolist_check_opts_t *o,
                                                 _Atomic bool *stop, char *error, size_t cap) {
    char url[FIRC_AUTOLIST_NAME_MAX + 16], addr[64] = "", pin[FIRC_AUTOLIST_NAME_MAX + 80];
    char curl_err[256] = "";
    if (host == NULL || o == NULL) { return FIRC_AUTOLIST_UNKNOWN; }
    snprintf(url, sizeof(url), "https://%s/", host);
    firc_err_t err = firc_ifcheck_resolve(o->dns, o->dns_port, url, o->timeout_s, addr, sizeof(addr), stop);
    if (err != FIRC_OK || addr[0] == '\0') {
        snprintf(error, cap, "not resolved: %s", firc_err_str(err));
        return FIRC_AUTOLIST_UNKNOWN;
    }
    snprintf(pin, sizeof(pin), "%s:443:%s", host, addr);
    firc_sub_fetch_opts_t fo = {.timeout_s = (long)o->timeout_s,
                                .no_redirects = true,
                                .progress = keep_going,
                                .progress_ud = stop,
                                .errbuf = curl_err,
                                .errbuf_cap = sizeof(curl_err),
                                .resolve = pin,
                                .interface = o->iface[0] != '\0' ? o->iface : NULL};
    long status = 0;
    err = firc_sub_fetch_to(url, &fo, first_bytes_only, NULL, &status);
    if (stop != NULL && atomic_load(stop)) {
        snprintf(error, cap, "stopped");
        return FIRC_AUTOLIST_UNKNOWN;
    }
    if (status > 0) {
        error[0] = '\0';
        return FIRC_AUTOLIST_REACHABLE;
    }
    if (err == FIRC_ERR_IO) {
        snprintf(error, cap, "%s", curl_err[0] != '\0' ? curl_err : "the request failed");
        return FIRC_AUTOLIST_BLOCKED;
    }
    snprintf(error, cap, "%s", firc_err_str(err));
    return FIRC_AUTOLIST_UNKNOWN;
}

static void deliver(firc_loop_t *loop, void *ud) {
    (void)loop;
    result_t *r = ud;
    r->done(r->ud, r->gen, r->probes, r->n);
    free(r->probes);
    free(r);
}

static void drop(void *ud) {
    result_t *r = ud;
    free(r->probes);
    free(r);
}

static void *run(void *arg) {
    firc_autolist_check_t *c = arg;
    for (size_t i = 0; i < c->n && !atomic_load(&c->stop); i++) {
        firc_autolist_probe_t *p = &c->probes[i];
        p->verdict = (uint8_t)c->probe(p->host, &c->opts, &c->stop, p->error, sizeof(p->error));
    }
    if (atomic_load(&c->stop)) { return NULL; }
    result_t *r = calloc(1, sizeof(*r));
    firc_autolist_probe_t *copy = c->n > 0 ? malloc(c->n * sizeof(*copy)) : NULL;
    if (r == NULL || (c->n > 0 && copy == NULL)) {
        free(r);
        free(copy);
        FIRC_WARN("autolist: the check's results were lost: out of memory");
        return NULL;
    }
    if (c->n > 0) { memcpy(copy, c->probes, c->n * sizeof(*copy)); }
    *r = (result_t){c->done, c->ud, c->gen, copy, c->n};
    while (!atomic_load(&c->stop) && firc_loop_post_with_drop(c->loop, deliver, r, drop) != FIRC_OK) {
        struct timespec ts = {0, 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    if (atomic_load(&c->stop)) { drop(r); }
    return NULL;
}

firc_autolist_check_t *firc_autolist_check_start(firc_loop_t *loop, const firc_autolist_check_opts_t *o,
                                                 const firc_autolist_probe_t *probes, size_t n, uint64_t gen,
                                                 firc_autolist_probe_fn probe, firc_autolist_checked_fn done,
                                                 void *ud) {
    if (loop == NULL || o == NULL || done == NULL || (n > 0 && probes == NULL)) { return NULL; }
    firc_autolist_check_t *c = calloc(1, sizeof(*c));
    if (c == NULL) { return NULL; }
    c->probes = n > 0 ? malloc(n * sizeof(*c->probes)) : NULL;
    if (n > 0 && c->probes == NULL) {
        free(c);
        return NULL;
    }
    if (n > 0) { memcpy(c->probes, probes, n * sizeof(*c->probes)); }
    c->loop = loop;
    c->opts = *o;
    c->n = n;
    c->gen = gen;
    c->probe = probe != NULL ? probe : firc_autolist_probe_once;
    c->done = done;
    c->ud = ud;
    atomic_init(&c->stop, false);
    if (pthread_create(&c->thread, NULL, run, c) != 0) {
        free(c->probes);
        free(c);
        return NULL;
    }
    c->started = true;
    return c;
}

void firc_autolist_check_free(firc_autolist_check_t *c) {
    if (c == NULL) { return; }
    atomic_store(&c->stop, true);
    if (c->started) { pthread_join(c->thread, NULL); }
    free(c->probes);
    free(c);
}

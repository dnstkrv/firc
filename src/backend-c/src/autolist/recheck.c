#include "firc/autolistcheck.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <curl/curl.h>

#include "firc/autolistcand.h"
#include "firc/ifcheck.h"
#include "firc/log.h"
#include "firc/regdomain.h"
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

#define PROBE_CAP 65536
#define PROBE_STALL_S 5
#define PROBE_REDIRECTS 3

void firc_autolist_classify(const firc_sub_fetch_info_t *info, uint32_t bytes, bool stalled, bool complete,
                            firc_autolist_result_t *out) {
    memset(out, 0, sizeof(*out));
    out->bytes = bytes;
    if (info == NULL || !info->connected) { return; }
    if (!info->tls_done) {
        if (info->reset) {
            out->verdict = FIRC_AUTOLIST_BLOCKED;
            out->why = FIRC_AL_WHY_RESET;
        } else if (info->timed_out) {
            out->verdict = FIRC_AUTOLIST_BLOCKED;
            out->why = FIRC_AL_WHY_NO_ANSWER;
        }
        return;
    }
    if (bytes > FIRC_AUTOLIST_STALL_MAX_BYTES || complete) {
        out->verdict = FIRC_AUTOLIST_REACHABLE;
        out->short_body = complete && bytes <= FIRC_AUTOLIST_STALL_MAX_BYTES;
        return;
    }
    if (stalled && bytes >= FIRC_AUTOLIST_STALL_MIN_BYTES) {
        out->verdict = FIRC_AUTOLIST_BLOCKED;
        out->why = FIRC_AL_WHY_FREEZE;
    }
}

typedef struct {
    _Atomic bool *stop;
    char regdomain[FIRC_AUTOLIST_NAME_MAX];
    size_t sunk;
    size_t seen;
    bool armed;
    struct timespec last;
    bool capped;
    bool stalled;
} probe_t;

static double since(const struct timespec *t) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - t->tv_sec) + (double)(now.tv_nsec - t->tv_nsec) / 1e9;
}

static bool probe_sink(void *ud, const uint8_t *data, size_t len) {
    (void)data;
    probe_t *p = ud;
    p->sunk += len;
    if (p->sunk >= PROBE_CAP) {
        p->capped = true;
        return false;
    }
    return true;
}

static bool probe_progress(void *ud, size_t bytes, size_t total) {
    (void)total;
    probe_t *p = ud;
    if (p->stop != NULL && atomic_load(p->stop)) { return false; }
    if (bytes != p->seen) {
        p->seen = bytes;
        p->armed = bytes > 0;
        clock_gettime(CLOCK_MONOTONIC, &p->last);
    }
    if (bytes >= PROBE_CAP) {
        p->capped = true;
        return false;
    }
    if (p->armed && since(&p->last) >= PROBE_STALL_S) {
        p->stalled = true;
        return false;
    }
    return true;
}

static bool same_regdomain(void *ud, const char *url) {
    const probe_t *p = ud;
    CURLU *u = curl_url();
    if (u == NULL) { return false; }
    char *host = NULL;
    bool ok = false;
    char rd[FIRC_AUTOLIST_NAME_MAX];
    if (curl_url_set(u, CURLUPART_URL, url, 0) == CURLUE_OK && curl_url_get(u, CURLUPART_HOST, &host, 0) == CURLUE_OK) {
        if (!firc_regdomain(host, rd, sizeof(rd))) { snprintf(rd, sizeof(rd), "%s", host); }
        ok = strcasecmp(rd, p->regdomain) == 0;
    }
    curl_free(host);
    curl_url_cleanup(u);
    return ok;
}

void firc_autolist_probe_once(const char *host, const firc_autolist_check_opts_t *o, _Atomic bool *stop,
                              firc_autolist_result_t *out) {
    char url[FIRC_AUTOLIST_NAME_MAX + 16], addr[64] = "", pin[FIRC_AUTOLIST_NAME_MAX + 80];
    char curl_err[256] = "";
    memset(out, 0, sizeof(*out));
    if (host == NULL || o == NULL) { return; }
    snprintf(url, sizeof(url), "https://%s/", host);
    firc_err_t err = firc_ifcheck_resolve(o->dns, o->dns_port, url, o->timeout_s, addr, sizeof(addr), stop);
    if (err != FIRC_OK || addr[0] == '\0') {
        snprintf(out->error, sizeof(out->error), "not resolved: %s", firc_err_str(err));
        return;
    }
    probe_t p = {.stop = stop};
    if (!firc_regdomain(host, p.regdomain, sizeof(p.regdomain))) {
        snprintf(p.regdomain, sizeof(p.regdomain), "%s", host);
    }
    snprintf(pin, sizeof(pin), "%s:443:%s", host, addr);
    firc_sub_fetch_info_t info = {0};
    firc_sub_fetch_opts_t fo = {.timeout_s = (long)o->timeout_s,
                                .max_redirects = PROBE_REDIRECTS,
                                .url_ok = same_regdomain,
                                .url_ud = &p,
                                .progress = probe_progress,
                                .progress_ud = &p,
                                .errbuf = curl_err,
                                .errbuf_cap = sizeof(curl_err),
                                .resolve = pin,
                                .interface = o->iface[0] != '\0' ? o->iface : NULL,
                                .info = &info};
    long status = 0;
    err = firc_sub_fetch_to(url, &fo, probe_sink, &p, &status);
    if (stop != NULL && atomic_load(stop)) {
        snprintf(out->error, sizeof(out->error), "stopped");
        return;
    }
    size_t got = p.sunk > p.seen ? p.sunk : p.seen;
    uint32_t bytes = got > UINT32_MAX ? UINT32_MAX : (uint32_t)got;
    bool complete = status > 0 && !p.capped && !p.stalled && err != FIRC_ERR_IO && err != FIRC_ERR_CANCELED;
    firc_autolist_classify(&info, bytes, p.stalled, complete, out);
    if (p.stalled) {
        snprintf(out->error, sizeof(out->error), "no byte for %d s after %u bytes", PROBE_STALL_S, (unsigned)bytes);
    } else if (err == FIRC_ERR_IO) {
        snprintf(out->error, sizeof(out->error), "%.*s", (int)sizeof(out->error) - 1,
                 curl_err[0] != '\0' ? curl_err : "the request failed");
    } else if (err != FIRC_OK && !p.capped && status <= 0) {
        snprintf(out->error, sizeof(out->error), "%s", firc_err_str(err));
    }
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

static firc_autolist_post_fn g_post = firc_loop_post_with_drop;

void firc_autolist_check_set_post_for_test(firc_autolist_post_fn post) {
    g_post = post != NULL ? post : firc_loop_post_with_drop;
}

static void *run(void *arg) {
    firc_autolist_check_t *c = arg;
    for (size_t i = 0; i < c->n && !atomic_load(&c->stop); i++) {
        firc_autolist_probe_t *p = &c->probes[i];
        c->probe(p->host, &c->opts, &c->stop, &p->result);
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
    while (!atomic_load(&c->stop)) {
        if (g_post(c->loop, deliver, r, drop) == FIRC_OK) { return NULL; }
        struct timespec ts = {0, 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    drop(r);
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

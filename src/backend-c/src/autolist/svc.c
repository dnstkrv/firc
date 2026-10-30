#include "firc/autolistsvc.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>

#include "firc/autolistrules.h"
#include "firc/clienthello.h"
#include "firc/log.h"
#include "firc/tappacket.h"

#define READERS 3

struct firc_autolist_svc;

typedef struct {
    struct firc_autolist_svc *svc;
    firc_nflog_t *sock;
    int which;
} reader_t;

struct firc_autolist_svc {
    firc_autolist_deps_t deps;
    firc_autolist_t *judge;
    reader_t readers[READERS];
    uint64_t failures, listed;
    bool said_broken;
};

static int64_t svc_now(const firc_autolist_svc_t *s) {
    return s->deps.now != NULL ? s->deps.now() : (int64_t)time(NULL);
}

static const char *why_name(uint8_t why) {
    return why == FIRC_AUTOLIST_RESET ? "a reset" : "the ClientHello unanswered";
}

static void addr_text(const firc_ip_t *ip, char *out, size_t cap) {
    if (inet_ntop(ip->len == 16 ? AF_INET6 : AF_INET, ip->b, out, (socklen_t)cap) == NULL) {
        snprintf(out, cap, "?");
    }
}

static void failed(firc_autolist_svc_t *s, const firc_autolist_failure_t *f) {
    s->failures++;
    char client[INET6_ADDRSTRLEN];
    addr_text(&f->client, client, sizeof(client));
    FIRC_DEBUG("autolist: %s failed for %s: %s (%u in a row)", f->host, client, why_name(f->why),
               (unsigned)f->fails);
    if (!f->listed) { return; }
    s->listed++;
    if (s->deps.listed != NULL) { s->deps.listed(s->deps.ud, f); }
}

static void on_hello(firc_autolist_svc_t *s, const uint8_t *pkt, size_t len, int64_t now) {
    firc_tap_packet_t p;
    if (!firc_tap_packet_parse(pkt, len, &p)) { return; }
    if (p.payload_len <= 5 || p.payload[0] != 0x16 || p.payload[5] != 0x01) { return; }
    if (s->deps.eligible != NULL && !s->deps.eligible(s->deps.ud, &p.src)) { return; }
    char sni[FIRC_AUTOLIST_NAME_MAX];
    if (!firc_tls_client_hello_sni(p.payload, p.payload_len, sni, sizeof(sni))) { sni[0] = '\0'; }
    firc_autolist_flow_t key = {p.src, p.dst, p.src_port, p.dst_port};
    firc_autolist_failure_t f;
    if (firc_autolist_hello(s->judge, &key, p.seq, sni, now, &f)) { failed(s, &f); }
}

static void on_reply(firc_autolist_svc_t *s, bool rst, const uint8_t *pkt, size_t len, int64_t now) {
    firc_tap_packet_t p;
    if (!firc_tap_packet_parse(pkt, len, &p)) { return; }
    if (rst && (p.flags & 0x04u) == 0) { return; }
    firc_autolist_flow_t key = {p.dst, p.src, p.dst_port, p.src_port};
    firc_autolist_failure_t f;
    if (firc_autolist_reply(s->judge, &key, rst, now, &f)) { failed(s, &f); }
}

void firc_autolist_svc_packet(firc_autolist_svc_t *s, int which, const uint8_t *pkt, size_t len) {
    if (s == NULL || pkt == NULL) { return; }
    int64_t now = svc_now(s);
    if (which == 0) {
        on_hello(s, pkt, len, now);
    } else if (which == 1 || which == 2) {
        on_reply(s, which == 1, pkt, len, now);
    }
}

typedef struct {
    firc_autolist_svc_t *s;
    int which;
} turn_t;

static void drain_one(const uint8_t *pkt, size_t len, void *ud) {
    turn_t *t = ud;
    firc_autolist_svc_packet(t->s, t->which, pkt, len);
}

firc_err_t firc_autolist_svc_drain(firc_autolist_svc_t *s, int which) {
    if (s == NULL || which < 0 || which >= READERS || s->readers[which].sock == NULL) { return FIRC_ERR_INVAL; }
    turn_t t = {s, which};
    firc_err_t e = firc_nflog_read(s->readers[which].sock, drain_one, &t);
    if (e == FIRC_ERR_LIMIT || e == FIRC_ERR_PROTO) { return FIRC_OK; }
    return e;
}

static void on_readable(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)loop;
    (void)fd;
    (void)events;
    reader_t *r = ud;
    for (int i = 0; i < 64; i++) {
        firc_err_t e = firc_autolist_svc_drain(r->svc, r->which);
        if (e == FIRC_ERR_AGAIN) { return; }
        if (e != FIRC_OK) {
            if (!r->svc->said_broken) {
                r->svc->said_broken = true;
                FIRC_WARN("autolist: reader %d failed (%s); nothing more is watched until it is switched "
                          "off and on",
                          r->which, firc_err_str(e));
            }
            if (r->svc->deps.loop != NULL) { (void)firc_loop_del_fd(r->svc->deps.loop, fd); }
            return;
        }
    }
}

firc_autolist_svc_t *firc_autolist_svc_start(const firc_autolist_deps_t *deps, firc_err_t *err) {
    firc_err_t dummy;
    if (err == NULL) { err = &dummy; }
    *err = FIRC_ERR_INVAL;
    if (deps == NULL) { return NULL; }
    firc_autolist_svc_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        *err = FIRC_ERR_NOMEM;
        return NULL;
    }
    s->deps = *deps;
    if (s->deps.nflog_open == NULL) { s->deps.nflog_open = firc_nflog_open; }
    s->judge = firc_autolist_new();
    if (s->judge == NULL) {
        free(s);
        *err = FIRC_ERR_NOMEM;
        return NULL;
    }

    static const uint16_t groups[READERS] = {FIRC_AUTOLIST_GROUP_HELLO, FIRC_AUTOLIST_GROUP_RESET,
                                             FIRC_AUTOLIST_GROUP_WORKS};
    static const uint16_t ranges[READERS] = {FIRC_TAP_COPY_RANGE, FIRC_TAP_HEAD_RANGE, FIRC_TAP_HEAD_RANGE};
    for (int w = 0; w < READERS; w++) {
        reader_t *r = &s->readers[w];
        r->svc = s;
        r->which = w;
        r->sock = s->deps.nflog_open(groups[w], ranges[w]);
        if (r->sock == NULL) {
            FIRC_WARN("autolist: could not bind NFLOG group %u", (unsigned)groups[w]);
            *err = FIRC_ERR_SYS;
            firc_autolist_svc_stop(s);
            return NULL;
        }
        if (s->deps.loop != NULL &&
            firc_loop_add_fd(s->deps.loop, firc_nflog_fd(r->sock), EPOLLIN, on_readable, r) != FIRC_OK) {
            FIRC_WARN("autolist: NFLOG group %u bound, but the event loop would not watch its socket",
                      (unsigned)groups[w]);
            firc_nflog_close(r->sock);
            r->sock = NULL;
            *err = FIRC_ERR_SYS;
            firc_autolist_svc_stop(s);
            return NULL;
        }
    }
    *err = FIRC_OK;
    return s;
}

void firc_autolist_svc_stop(firc_autolist_svc_t *s) {
    if (s == NULL) { return; }
    for (int w = 0; w < READERS; w++) {
        firc_nflog_t *sock = s->readers[w].sock;
        if (sock == NULL) { continue; }
        if (s->deps.loop != NULL) { (void)firc_loop_del_fd(s->deps.loop, firc_nflog_fd(sock)); }
        firc_nflog_close(sock);
        s->readers[w].sock = NULL;
    }
    firc_autolist_free(s->judge);
    free(s);
}

void firc_autolist_svc_set_params(firc_autolist_svc_t *s, const firc_autolist_params_t *p) {
    if (s != NULL) { firc_autolist_set_params(s->judge, p); }
}

void firc_autolist_svc_hint(firc_autolist_svc_t *s, const firc_ip_t *client, const char *name,
                            const firc_ip_t *reals, size_t n_reals) {
    if (s != NULL) { firc_autolist_hint(s->judge, client, name, reals, n_reals, svc_now(s)); }
}

void firc_autolist_svc_counts(const firc_autolist_svc_t *s, uint64_t *failures, uint64_t *listed) {
    if (failures != NULL) { *failures = s != NULL ? s->failures : 0; }
    if (listed != NULL) { *listed = s != NULL ? s->listed : 0; }
}

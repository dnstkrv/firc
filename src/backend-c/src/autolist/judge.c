#include "firc/autolist.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    bool used;
    bool judged;
    uint8_t sent;
    uint32_t hash;
    uint32_t seq;
    int64_t seen;
    int32_t host;
    uint32_t host_serial;
    firc_autolist_flow_t key;
} flow_t;

typedef struct {
    bool used;
    uint32_t hash;
    uint32_t serial;
    uint32_t fails;
    int64_t last_fail;
    int64_t seen;
    char name[FIRC_AUTOLIST_NAME_MAX];
} host_t;

typedef struct {
    bool used;
    uint32_t hash;
    int64_t at;
    firc_ip_t client, real;
    char name[FIRC_AUTOLIST_NAME_MAX];
} hint_t;

struct firc_autolist {
    firc_autolist_params_t p;
    uint32_t serial;
    flow_t flows[FIRC_AUTOLIST_FLOWS];
    host_t hosts[FIRC_AUTOLIST_HOSTS];
    hint_t hints[FIRC_AUTOLIST_HINTS];
};

#define FNV_BASIS 2166136261u
#define FNV_PRIME 16777619u

static uint32_t fnv(uint32_t h, const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= FNV_PRIME;
    }
    return h;
}

static uint32_t ip_hash(uint32_t h, const firc_ip_t *ip) {
    h = fnv(h, &ip->len, 1);
    return fnv(h, ip->b, ip->len <= 16 ? ip->len : 16);
}

static bool ip_eq(const firc_ip_t *a, const firc_ip_t *b) {
    return a->len == b->len && a->len <= 16 && memcmp(a->b, b->b, a->len) == 0;
}

static uint32_t flow_hash(const firc_autolist_flow_t *f) {
    uint32_t h = ip_hash(FNV_BASIS, &f->client);
    h = ip_hash(h, &f->server);
    h = fnv(h, &f->client_port, sizeof(f->client_port));
    return fnv(h, &f->server_port, sizeof(f->server_port));
}

static bool flow_eq(const firc_autolist_flow_t *a, const firc_autolist_flow_t *b) {
    return a->client_port == b->client_port && a->server_port == b->server_port && ip_eq(&a->client, &b->client) &&
           ip_eq(&a->server, &b->server);
}

static uint32_t name_hash(const char *s) { return fnv(FNV_BASIS, s, strlen(s)); }

static const firc_autolist_params_t defaults = {
    FIRC_AUTOLIST_FAIL_THRESHOLD,
    FIRC_AUTOLIST_FAIL_SECS,
    FIRC_AUTOLIST_RETRANS_THRESHOLD,
};

firc_autolist_t *firc_autolist_new(void) {
    firc_autolist_t *a = calloc(1, sizeof(*a));
    if (a == NULL) { return NULL; }
    a->p = defaults;
    return a;
}

void firc_autolist_free(firc_autolist_t *a) { free(a); }

void firc_autolist_set_params(firc_autolist_t *a, const firc_autolist_params_t *p) {
    if (a == NULL || p == NULL) { return; }
    a->p.fail_threshold = p->fail_threshold ? p->fail_threshold : defaults.fail_threshold;
    a->p.fail_secs = p->fail_secs ? p->fail_secs : defaults.fail_secs;
    a->p.retrans_threshold = p->retrans_threshold ? p->retrans_threshold : defaults.retrans_threshold;
}

static bool host_counting(const firc_autolist_t *a, const host_t *h, int64_t now) {
    return h->used && h->fails > 0 && now - h->last_fail <= (int64_t)a->p.fail_secs;
}

void firc_autolist_hint(firc_autolist_t *a, const firc_ip_t *client, const char *name, const firc_ip_t *reals,
                        size_t n_reals, int64_t now) {
    if (a == NULL || client == NULL || name == NULL || reals == NULL) { return; }
    size_t len = strlen(name);
    if (len == 0 || len >= FIRC_AUTOLIST_NAME_MAX) { return; }
    for (size_t r = 0; r < n_reals; r++) {
        uint32_t h = ip_hash(ip_hash(FNV_BASIS, client), &reals[r]);
        hint_t *slot = NULL, *oldest = NULL;
        for (size_t i = 0; i < FIRC_AUTOLIST_HINTS; i++) {
            hint_t *e = &a->hints[i];
            if (e->used && e->hash == h && ip_eq(&e->client, client) && ip_eq(&e->real, &reals[r])) {
                slot = e;
                break;
            }
            if (!e->used || now - e->at > FIRC_AUTOLIST_HINT_SECS) {
                if (slot == NULL) { slot = e; }
            } else if (oldest == NULL || e->at < oldest->at) {
                oldest = e;
            }
        }
        if (slot == NULL) { slot = oldest; }
        if (slot == NULL) { return; }
        slot->used = true;
        slot->hash = h;
        slot->at = now;
        slot->client = *client;
        slot->real = reals[r];
        memcpy(slot->name, name, len + 1);
    }
}

static const char *hint_for(const firc_autolist_t *a, const firc_ip_t *client, const firc_ip_t *real, int64_t now) {
    uint32_t h = ip_hash(ip_hash(FNV_BASIS, client), real);
    for (size_t i = 0; i < FIRC_AUTOLIST_HINTS; i++) {
        const hint_t *e = &a->hints[i];
        if (e->used && e->hash == h && now - e->at <= FIRC_AUTOLIST_HINT_SECS && ip_eq(&e->client, client) &&
            ip_eq(&e->real, real)) {
            return e->name;
        }
    }
    return NULL;
}

static int32_t host_take(firc_autolist_t *a, const char *name, int64_t now) {
    size_t len = strlen(name);
    if (len == 0 || len >= FIRC_AUTOLIST_NAME_MAX) { return -1; }
    uint32_t h = name_hash(name);
    int32_t free_at = -1, idle = -1, oldest = -1;
    for (size_t i = 0; i < FIRC_AUTOLIST_HOSTS; i++) {
        host_t *e = &a->hosts[i];
        if (e->used && e->hash == h && strcmp(e->name, name) == 0) {
            e->seen = now;
            return (int32_t)i;
        }
        if (!e->used) {
            if (free_at < 0) { free_at = (int32_t)i; }
        } else if (!host_counting(a, e, now)) {
            if (idle < 0 || e->seen < a->hosts[idle].seen) { idle = (int32_t)i; }
        } else if (oldest < 0 || e->seen < a->hosts[oldest].seen) {
            oldest = (int32_t)i;
        }
    }
    int32_t at = free_at >= 0 ? free_at : idle >= 0 ? idle : oldest;
    if (at < 0) { return -1; }
    host_t *e = &a->hosts[at];
    memset(e, 0, sizeof(*e));
    e->used = true;
    e->hash = h;
    e->serial = ++a->serial;
    e->seen = now;
    memcpy(e->name, name, len + 1);
    return at;
}

static host_t *host_of(firc_autolist_t *a, const flow_t *f) {
    if (f->host < 0 || f->host >= FIRC_AUTOLIST_HOSTS) { return NULL; }
    host_t *h = &a->hosts[f->host];
    return h->used && h->serial == f->host_serial ? h : NULL;
}

static flow_t *flow_find(firc_autolist_t *a, const firc_autolist_flow_t *key, uint32_t hash, int64_t now) {
    for (size_t i = 0; i < FIRC_AUTOLIST_FLOWS; i++) {
        flow_t *e = &a->flows[i];
        if (e->used && e->hash == hash && now - e->seen <= FIRC_AUTOLIST_FLOW_SECS && flow_eq(&e->key, key)) {
            return e;
        }
    }
    return NULL;
}

static flow_t *flow_slot(firc_autolist_t *a, int64_t now) {
    flow_t *oldest = NULL;
    for (size_t i = 0; i < FIRC_AUTOLIST_FLOWS; i++) {
        flow_t *e = &a->flows[i];
        if (!e->used || now - e->seen > FIRC_AUTOLIST_FLOW_SECS) { return e; }
        if (oldest == NULL || e->seen < oldest->seen) { oldest = e; }
    }
    return oldest;
}

static bool fail(firc_autolist_t *a, flow_t *f, firc_autolist_why_t why, int64_t now, firc_autolist_failure_t *out) {
    f->judged = true;
    host_t *h = host_of(a, f);
    if (h == NULL) { return false; }
    if (!host_counting(a, h, now)) { h->fails = 0; }
    h->fails++;
    h->last_fail = now;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        memcpy(out->host, h->name, sizeof(out->host));
        out->client = f->key.client;
        out->fails = h->fails;
        out->why = (uint8_t)why;
        out->listed = h->fails >= a->p.fail_threshold;
    }
    if (h->fails >= a->p.fail_threshold) { h->fails = 0; }
    return true;
}

bool firc_autolist_hello(firc_autolist_t *a, const firc_autolist_flow_t *key, uint32_t seq, const char *sni,
                         int64_t now, firc_autolist_failure_t *out) {
    if (a == NULL || key == NULL) { return false; }
    uint32_t hash = flow_hash(key);
    flow_t *f = flow_find(a, key, hash, now);
    if (f != NULL && f->seq == seq) {
        f->seen = now;
        if (f->judged) { return false; }
        if (f->sent < UINT8_MAX) { f->sent++; }
        if ((uint32_t)f->sent - 1u < a->p.retrans_threshold) { return false; }
        return fail(a, f, FIRC_AUTOLIST_RETRANS, now, out);
    }

    if (f == NULL) { f = flow_slot(a, now); }
    memset(f, 0, sizeof(*f));
    f->used = true;
    f->hash = hash;
    f->key = *key;
    f->seq = seq;
    f->sent = 1;
    f->seen = now;
    const char *name = sni != NULL && sni[0] != '\0' ? sni : hint_for(a, &key->client, &key->server, now);
    f->host = name != NULL ? host_take(a, name, now) : -1;
    f->host_serial = f->host >= 0 ? a->hosts[f->host].serial : 0;
    return false;
}

bool firc_autolist_reply(firc_autolist_t *a, const firc_autolist_flow_t *key, bool rst, int64_t now,
                         firc_autolist_failure_t *out) {
    if (a == NULL || key == NULL) { return false; }
    flow_t *f = flow_find(a, key, flow_hash(key), now);
    if (f == NULL || f->judged) { return false; }
    f->seen = now;
    if (rst) { return fail(a, f, FIRC_AUTOLIST_RESET, now, out); }
    f->judged = true;
    host_t *h = host_of(a, f);
    if (h != NULL) { h->fails = 0; }
    return false;
}

size_t firc_autolist_counting(const firc_autolist_t *a, int64_t now) {
    if (a == NULL) { return 0; }
    size_t n = 0;
    for (size_t i = 0; i < FIRC_AUTOLIST_HOSTS; i++) { n += host_counting(a, &a->hosts[i], now) ? 1u : 0u; }
    return n;
}

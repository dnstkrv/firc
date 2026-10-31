#include "firc/autolist.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    bool used;
    bool judged;
    bool bypass;
    bool finned;
    uint8_t sent;
    uint32_t hash;
    uint32_t seq;
    uint32_t ack0;
    int64_t seen;
    int64_t hello_at;
    int32_t host;
    uint32_t host_serial;
    firc_autolist_flow_t key;
} flow_t;

#define BAD_ADDRS 8

typedef struct {
    bool used;
    uint32_t hash;
    uint32_t serial;
    uint32_t fails;
    int64_t last_fail;
    int64_t seen;
    firc_ip_t bad[BAD_ADDRS];
    uint8_t n_bad;
    uint8_t next_bad;
    uint8_t n_notes;
    int64_t note_at[FIRC_AUTOLIST_NOTES];
    char name[FIRC_AUTOLIST_NAME_MAX];
} host_t;

typedef struct {
    bool used;
    uint32_t hash;
    int64_t at;
    firc_ip_t client, real;
    char name[FIRC_AUTOLIST_NAME_MAX];
} hint_t;

typedef struct {
    bool used;
    uint32_t fails;
    int64_t last;
    firc_ip_t ip;
} bypass_t;

struct firc_autolist {
    firc_autolist_params_t p;
    uint32_t serial;
    flow_t flows[FIRC_AUTOLIST_FLOWS];
    host_t hosts[FIRC_AUTOLIST_HOSTS];
    hint_t hints[FIRC_AUTOLIST_HINTS];
    bypass_t bypass[FIRC_AUTOLIST_BYPASS_CLIENTS];
    int64_t day_hour[FIRC_AUTOLIST_DAY_HOURS];
    uint32_t day_count[FIRC_AUTOLIST_DAY_HOURS];
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
            if (e->used && e->hash == h && ip_eq(&e->client, client) && ip_eq(&e->real, &reals[r]) &&
                strcmp(e->name, name) == 0) {
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

static const char *hint_for(const firc_autolist_t *a, const firc_ip_t *client, const firc_ip_t *real,
                            const char *name, int64_t now) {
    uint32_t h = ip_hash(ip_hash(FNV_BASIS, client), real);
    const hint_t *newest = NULL;
    for (size_t i = 0; i < FIRC_AUTOLIST_HINTS; i++) {
        const hint_t *e = &a->hints[i];
        if (!e->used || e->hash != h || now - e->at > FIRC_AUTOLIST_HINT_SECS || !ip_eq(&e->client, client) ||
            !ip_eq(&e->real, real)) {
            continue;
        }
        if (name != NULL) {
            if (strcmp(e->name, name) == 0) { return e->name; }
        } else if (newest == NULL || e->at > newest->at) {
            newest = e;
        }
    }
    return newest != NULL ? newest->name : NULL;
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

static void host_restart(host_t *h) {
    h->fails = 0;
    h->n_bad = 0;
    h->next_bad = 0;
}

static bool host_bad_at(const host_t *h, const firc_ip_t *server) {
    for (uint8_t i = 0; i < h->n_bad; i++) {
        if (ip_eq(&h->bad[i], server)) { return true; }
    }
    return false;
}

static void host_note_bad(host_t *h, const firc_ip_t *server) {
    if (host_bad_at(h, server)) { return; }
    if (h->n_bad < BAD_ADDRS) {
        h->bad[h->n_bad++] = *server;
        return;
    }
    h->bad[h->next_bad] = *server;
    h->next_bad = (uint8_t)((h->next_bad + 1u) % BAD_ADDRS);
}

static int64_t hour_of(int64_t now) { return now >= 0 ? now / 3600 : (now - 3599) / 3600; }

static void day_count(firc_autolist_t *a, int64_t now) {
    int64_t hour = hour_of(now);
    size_t at = (size_t)(((hour % FIRC_AUTOLIST_DAY_HOURS) + FIRC_AUTOLIST_DAY_HOURS) % FIRC_AUTOLIST_DAY_HOURS);
    if (a->day_hour[at] != hour) {
        a->day_hour[at] = hour;
        a->day_count[at] = 0;
    }
    a->day_count[at]++;
}

static uint32_t bypass_count(firc_autolist_t *a, const firc_ip_t *client, int64_t now) {
    bypass_t *slot = NULL, *spare = NULL;
    for (size_t i = 0; i < FIRC_AUTOLIST_BYPASS_CLIENTS; i++) {
        bypass_t *e = &a->bypass[i];
        if (e->used && ip_eq(&e->ip, client)) {
            slot = e;
            break;
        }
        if (!e->used) {
            if (spare == NULL || spare->used) { spare = e; }
        } else if (spare == NULL || (spare->used && e->last < spare->last)) {
            spare = e;
        }
    }
    if (slot == NULL) { slot = spare; }
    if (!slot->used || !ip_eq(&slot->ip, client) || now - slot->last >= FIRC_AUTOLIST_DAY_SECS) {
        slot->used = true;
        slot->ip = *client;
        slot->fails = 0;
    }
    slot->fails++;
    slot->last = now;
    return slot->fails;
}

static bool fail(firc_autolist_t *a, flow_t *f, firc_autolist_why_t why, int64_t now, firc_autolist_failure_t *out) {
    f->judged = true;
    if (f->bypass) {
        uint32_t fails = bypass_count(a, &f->key.client, now);
        if (out != NULL) {
            memset(out, 0, sizeof(*out));
            out->client = f->key.client;
            out->fails = fails;
            out->why = (uint8_t)why;
            out->bypass = true;
        }
        return true;
    }
    host_t *h = host_of(a, f);
    if (h == NULL) { return false; }
    if (!host_counting(a, h, now)) { host_restart(h); }
    day_count(a, now);
    h->fails++;
    h->last_fail = now;
    host_note_bad(h, &f->key.server);
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        memcpy(out->host, h->name, sizeof(out->host));
        out->client = f->key.client;
        out->fails = h->fails;
        out->why = (uint8_t)why;
        out->listed = h->fails >= a->p.fail_threshold;
    }
    if (h->fails >= a->p.fail_threshold) { host_restart(h); }
    return true;
}

bool firc_autolist_hello(firc_autolist_t *a, const firc_autolist_flow_t *key, uint32_t seq, uint32_t ack,
                         const char *sni, int64_t now, firc_autolist_failure_t *out) {
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
    f->ack0 = ack;
    f->sent = 1;
    f->seen = now;
    f->hello_at = now;
    const char *name = NULL;
    if (sni != NULL && sni[0] != '\0') {
        name = hint_for(a, &key->client, &key->server, sni, now);
        f->bypass = name == NULL;
    } else {
        name = hint_for(a, &key->client, &key->server, NULL, now);
    }
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
    if (h != NULL && host_bad_at(h, &f->key.server)) { host_restart(h); }
    return false;
}

bool firc_autolist_fin(firc_autolist_t *a, const firc_autolist_flow_t *key, uint32_t ack, int64_t now,
                       firc_autolist_nomination_t *out) {
    if (a == NULL || key == NULL) { return false; }
    flow_t *f = flow_find(a, key, flow_hash(key), now);
    if (f == NULL || f->finned) { return false; }
    f->finned = true;
    f->seen = now;
    uint32_t received = ack - f->ack0;
    if (received < FIRC_AUTOLIST_STALL_MIN_BYTES || received > FIRC_AUTOLIST_STALL_MAX_BYTES) { return false; }
    if (now - f->hello_at < FIRC_AUTOLIST_STALL_MIN_SECS) { return false; }
    host_t *h = host_of(a, f);
    if (h == NULL) { return false; }
    uint8_t kept = 0;
    for (uint8_t i = 0; i < h->n_notes; i++) {
        if (now - h->note_at[i] <= FIRC_AUTOLIST_NOTE_SECS) { h->note_at[kept++] = h->note_at[i]; }
    }
    if (kept == FIRC_AUTOLIST_NOTES) {
        memmove(h->note_at, h->note_at + 1, sizeof(h->note_at[0]) * (FIRC_AUTOLIST_NOTES - 1u));
        kept--;
    }
    h->note_at[kept++] = now;
    h->n_notes = kept;
    if (h->n_notes < FIRC_AUTOLIST_NOTES) { return false; }
    h->n_notes = 0;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        memcpy(out->host, h->name, sizeof(out->host));
        out->client = f->key.client;
        out->received = received;
    }
    return true;
}

size_t firc_autolist_bypassed(const firc_autolist_t *a, int64_t now, firc_ip_t *clients, uint32_t *fails,
                              size_t cap) {
    if (a == NULL) { return 0; }
    size_t n = 0;
    for (size_t i = 0; i < FIRC_AUTOLIST_BYPASS_CLIENTS && n < cap; i++) {
        const bypass_t *e = &a->bypass[i];
        if (!e->used || now - e->last >= FIRC_AUTOLIST_DAY_SECS) { continue; }
        if (clients != NULL) { clients[n] = e->ip; }
        if (fails != NULL) { fails[n] = e->fails; }
        n++;
    }
    return n;
}

uint32_t firc_autolist_failures_day(const firc_autolist_t *a, int64_t now) {
    if (a == NULL) { return 0; }
    int64_t hour = hour_of(now);
    uint32_t n = 0;
    for (size_t i = 0; i < FIRC_AUTOLIST_DAY_HOURS; i++) {
        if (a->day_hour[i] <= hour && hour - a->day_hour[i] < FIRC_AUTOLIST_DAY_HOURS) { n += a->day_count[i]; }
    }
    return n;
}

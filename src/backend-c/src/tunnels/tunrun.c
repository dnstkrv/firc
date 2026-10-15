#include "firc/tunrun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "firc/events.h"
#include "firc/logrep.h"
#include "firc/mark.h"
#include "firc/tunnet.h"
#include "firc/tunnodes.h"
#include "firc/tunwatch.h"

#define TUNVLESS_STDIN_MAX ((size_t)1 << 20)
#define WATCH_MS 15000

typedef struct {
    char id[16];
    char device[16];
    firc_tunnet_uplink_t u;
} drain_t;

typedef struct {
    firc_tun_src_t *src;
    size_t *row_of;
    size_t n;
    bool have;
    firc_tun_nodes_t rows;
} sent_t;

typedef struct {
    char key[FIRC_TUN_KEY_MAX + 1];
    int64_t since;
} down_t;

typedef struct {
    down_t *v;
    size_t n;
} keys_t;

typedef struct {
    firc_tun_status_t syn;
    int64_t syn_since;
    keys_t downs;
    keys_t acts;
    firc_tunwatch_t watch;
    firc_logrep_t no_node;
} ext_t;

struct firc_tunrun {
    firc_loop_t *loop;
    firc_rtnl_t *r;
    uint32_t start;
    firc_tunsup_t *sup;
    firc_tunnels_t cur;
    firc_tunnet_uplink_t *up;
    bool *ok;
    sent_t *sent;
    bool *waiting;
    ext_t *ext;
    drain_t *drains;
    size_t n_drains;
    firc_tunsubs_t *subs;
    size_t list_max;
    bool stopped;
    bool has_k;
    firc_tunrun_ktcp_t k;
    uint16_t ports[FIRC_KTCP_DEVICES];
    uint8_t drifts[FIRC_KTCP_DEVICES];
    bool ktcp_unusable;
    int watch_timer;
    int64_t (*now)(void);
};

bool firc_tun_journal_line(const firc_tev_t *ev, char *buf, size_t cap, firc_log_level_t *level)
{
    switch (ev->kind) {
    case FIRC_TEV_ACTIVE: {
        if (ev->n_active == 0) {
            return false;
        }
        *level = FIRC_LOG_INFO;
        int off = snprintf(buf, cap, "active ");
        for (size_t i = 0; i < ev->n_active && off >= 0 && (size_t)off < cap; i++) {
            off += snprintf(buf + off, cap - (size_t)off, "%s%s", i > 0 ? ", " : "", ev->active[i]);
        }
        return true;
    }
    case FIRC_TEV_NODE_DOWN:
        *level = FIRC_LOG_WARN;
        if (ev->why[0] != 0) {
            snprintf(buf, cap, "%s does not answer (%s)", ev->node, ev->why);
        } else {
            snprintf(buf, cap, "%s does not answer", ev->node);
        }
        return true;
    case FIRC_TEV_NODE_UP:
        *level = FIRC_LOG_INFO;
        snprintf(buf, cap, "%s answers again", ev->node);
        return true;
    case FIRC_TEV_NO_NODE:
        *level = FIRC_LOG_WARN;
        if (ev->retry_s > 0) {
            snprintf(buf, cap, "no node answers, retry in %d s", ev->retry_s);
        } else {
            snprintf(buf, cap, "no node answers");
        }
        return true;
    case FIRC_TEV_READY:
    case FIRC_TEV_BAD:
    default:
        return false;
    }
}

static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


static bool needs_uplink(const firc_tunnel_t *tun)
{
    return tun->enable && tun->uplink != FIRC_UPLINK_AUTO;
}

static void show_uplink(firc_tunrun_t *t, size_t i)
{
    firc_tunsup_set_uplink_ok(t->sup, t->cur.t[i].id, !needs_uplink(&t->cur.t[i]) || t->up[i].routed);
}

static void refresh(firc_tunrun_t *t, size_t i)
{
    firc_err_t err = firc_tunnet_uplink_refresh(t->r, &t->cur.t[i], &t->cur, &t->up[i]);
    if (err != FIRC_OK) {
        firc_log_from(FIRC_LOG_WARN, t->cur.t[i].device, "uplink route not rewritten: %s", firc_err_str(err));
    }
    show_uplink(t, i);
}

static ssize_t find(const firc_tunnels_t *all, const char *id);

static const down_t *key_find(const keys_t *k, const char *key)
{
    for (size_t i = 0; i < k->n; i++) {
        if (strcmp(k->v[i].key, key) == 0) {
            return &k->v[i];
        }
    }
    return NULL;
}

static void key_add(keys_t *k, const char *key)
{
    if (key_find(k, key) != NULL || k->n >= FIRC_TUN_MAX_NODES) {
        return;
    }
    down_t *g = realloc(k->v, (k->n + 1) * sizeof *g);
    if (g == NULL) {
        return;
    }
    k->v = g;
    snprintf(g[k->n].key, sizeof g[k->n].key, "%s", key);
    g[k->n].since = mono_ms();
    k->n++;
}

static void key_del_at(keys_t *k, size_t i)
{
    memmove(&k->v[i], &k->v[i + 1], (k->n - i - 1) * sizeof *k->v);
    k->n--;
}

static void key_del(keys_t *k, const char *key)
{
    for (size_t i = 0; i < k->n; i++) {
        if (strcmp(k->v[i].key, key) == 0) {
            key_del_at(k, i);
            return;
        }
    }
}

static void each_key(const sent_t *x, int pos, const char *name, keys_t *k, void (*fn)(keys_t *, const char *))
{
    if (pos >= 0 && (size_t)pos < x->n && x->row_of != NULL) {
        const firc_tun_node_t *row = &x->rows.v[x->row_of[pos]];
        if (strncmp(row->name, name, strlen(name)) == 0) {
            fn(k, row->key);
            return;
        }
    }
    for (size_t r = 0; r < x->rows.n; r++) {
        if (strcmp(x->rows.v[r].name, name) == 0) {
            fn(k, x->rows.v[r].key);
        }
    }
}

static bool sent_key(const sent_t *x, const char *key)
{
    for (size_t p = 0; p < x->n && x->row_of != NULL; p++) {
        if (strcmp(x->rows.v[x->row_of[p]].key, key) == 0) {
            return true;
        }
    }
    return false;
}

static void prune(keys_t *k, const sent_t *x)
{
    for (size_t i = 0; i < k->n;) {
        if (sent_key(x, k->v[i].key)) {
            i++;
        } else {
            key_del_at(k, i);
        }
    }
}

static void track_nodes(firc_tunrun_t *t, const firc_tun_state_t *st, const firc_tev_t *ev)
{
    ssize_t i = find(&t->cur, st->id);
    if (i < 0 || t->ext == NULL) {
        return;
    }
    ext_t *x = &t->ext[i];
    const sent_t *sent = &t->sent[i];
    if (ev == NULL) {
        x->acts.n = 0;
        if (st->status == FIRC_TUN_ST_STARTING || st->status == FIRC_TUN_ST_OFF) {
            x->downs.n = 0;
        }
        return;
    }
    switch (ev->kind) {
    case FIRC_TEV_NODE_DOWN:
        each_key(sent, ev->pos, ev->node, &x->downs, key_add);
        break;
    case FIRC_TEV_NODE_UP:
        each_key(sent, ev->pos, ev->node, &x->downs, key_del);
        break;
    case FIRC_TEV_ACTIVE:
        x->acts.n = 0;
        for (size_t k = 0; k < ev->n_active && k < 8; k++) {
            each_key(sent, ev->active_pos[k], ev->active[k], &x->acts, key_add);
        }
        break;
    case FIRC_TEV_NO_NODE:
        x->acts.n = 0;
        break;
    default:
        break;
    }
}

static int ktcp_dev(const firc_tunnel_t *tun)
{
    uint16_t port = firc_tunnel_tcp_port(tun);
    return port == 0 ? -1 : port - FIRC_TUNNEL_TCP_PORT_BASE;
}

static void publish(const firc_tunrun_t *t)
{
    if (t->has_k && t->k.ports != NULL) {
        t->k.ports(t->ports, t->k.ud);
    }
}

static void set_port(firc_tunrun_t *t, int dev, uint16_t port)
{
    if (t->ports[dev] != port) {
        t->ports[dev] = port;
        publish(t);
    }
}

static int send_cmds(firc_tunrun_t *t, const firc_tunnel_t *tun, firc_tun_cmd_t kind, const firc_ktcp_cmds_t *c)
{
    if (c->n_cmds == 0) {
        return 0;
    }
    firc_err_t err = firc_tunsup_command(t->sup, tun->id, kind, c->text, c->len, c->counts, c->n_cmds);
    if (err != FIRC_OK) {
        firc_log_from(FIRC_LOG_WARN, tun->device, "command not sent: %s", firc_err_str(err));
        return 0;
    }
    return (int)c->n_cmds;
}

static void send_mapall(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, const firc_ktcp_image_t *im)
{
    static const firc_ktcp_image_t none = {0};
    firc_ktcp_cmds_t c = {0};
    if (firc_ktcp_map_cmds(im != NULL ? im : &none, (uint8_t)dev, true, &c) == FIRC_OK) {
        send_cmds(t, tun, FIRC_TUN_CMD_MAP, &c);
    } else {
        firc_log_from(FIRC_LOG_WARN, tun->device, "out of memory, the address map is not sent");
    }
    firc_ktcp_cmds_free(&c);
}

static const firc_ktcp_image_t *image_now(const firc_tunrun_t *t)
{
    return t->has_k && t->k.image != NULL ? t->k.image(t->k.ud) : NULL;
}

static void ready_port(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, uint16_t got)
{
    uint16_t want = firc_tunnel_tcp_port(tun);
    t->drifts[dev] = 0;
    if (want != 0 && got == 0) {
        firc_log_from(FIRC_LOG_WARN, tun->device, "port %u is taken, TCP stays on the TUN", (unsigned)want);
    } else if (want != 0 && got != want) {
        firc_log_from(FIRC_LOG_WARN, tun->device, "tunvless reported port %u, not %u; TCP stays on the TUN",
                      (unsigned)got, (unsigned)want);
    }
    set_port(t, dev, got == want ? want : 0);
    if (t->ports[dev] != 0) {
        send_mapall(t, tun, dev, image_now(t));
    }
}

static void map_drift(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, const firc_tev_t *ev)
{
    if (t->drifts[dev] >= 2) {
        return;
    }
    if (++t->drifts[dev] == 1) {
        send_mapall(t, tun, dev, image_now(t));
        return;
    }
    firc_log_from(FIRC_LOG_WARN, tun->device, "tunvless took %d of %d map lines, its map is no longer resent",
                  ev->count, ev->expect);
}

static void answer_miss(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, const uint8_t fake[4])
{
    uint8_t real[4];
    bool known = t->has_k && t->k.real_of != NULL && t->k.real_of((uint8_t)dev, fake, real, t->k.ud);
    firc_ktcp_cmds_t c = {0};
    if (firc_ktcp_line(&c, fake, known ? real : NULL) == FIRC_OK) {
        send_cmds(t, tun, FIRC_TUN_CMD_MAP, &c);
    }
    firc_ktcp_cmds_free(&c);
}

static void ktcp_event(firc_tunrun_t *t, const firc_tun_state_t *st, const firc_tev_t *ev)
{
    if (ev == NULL) {
        return;
    }
    ssize_t i = find(&t->cur, st->id);
    int dev = i < 0 ? -1 : ktcp_dev(&t->cur.t[i]);
    if (dev < 0 || !firc_tunsup_ready(t->sup, st->id)) {
        return;
    }
    const firc_tunnel_t *tun = &t->cur.t[i];
    switch (ev->kind) {
    case FIRC_TEV_READY:
        if (t->k.ready != NULL) {
            t->k.ready((uint8_t)dev, t->k.ud);
        }
        ready_port(t, tun, dev, ev->tcp_port);
        break;
    case FIRC_TEV_MAP:
        if (ev->drift && t->ports[dev] != 0) {
            map_drift(t, tun, dev, ev);
        }
        break;
    case FIRC_TEV_MISS:
        if (t->ports[dev] != 0) {
            answer_miss(t, tun, dev, ev->fake);
        }
        break;
    case FIRC_TEV_CLOSE:
        firc_log_from(FIRC_LOG_DEBUG, tun->device, "tunvless closed %d connections", ev->count);
        if (t->k.closed != NULL) {
            t->k.closed((uint8_t)dev, t->k.ud);
        }
        break;
    default:
        break;
    }
}

static void watch(firc_tunrun_t *t)
{
    if (t->stopped || t->ext == NULL) {
        return;
    }
    firc_tun_state_t st[FIRC_TUN_MAX];
    size_t n = firc_tunrun_states(t, st, FIRC_TUN_MAX);
    for (size_t i = 0; i < n && i < FIRC_TUN_MAX; i++) {
        firc_tunwatch_see(&t->ext[i].watch, st[i].device, st[i].status, t->now());
    }
}

static void on_watch(firc_loop_t *loop, void *ud)
{
    (void)loop;
    watch(ud);
}

static void on_event(const firc_tun_state_t *st, const firc_tev_t *ev, void *ud)
{
    firc_tunrun_t *t = ud;
    track_nodes(t, st, ev);
    ktcp_event(t, st, ev);
    ssize_t at = find(&t->cur, st->id);
    firc_logrep_t *no_node = at >= 0 && t->ext != NULL ? &t->ext[at].no_node : NULL;
    char line[FIRC_EVENT_TEXT];
    firc_log_level_t level = FIRC_LOG_INFO;
    if (ev != NULL && firc_tun_journal_line(ev, line, sizeof line, &level)) {
        if (ev->kind == FIRC_TEV_NO_NODE && no_node != NULL) {
            firc_logrep_fail(no_node, level, st->device, "%s", line);
        } else {
            firc_log_from(level, st->device, "%s", line);
        }
    }
    if (ev != NULL && ev->kind == FIRC_TEV_ACTIVE && ev->n_active > 0 && no_node != NULL) {
        (void)firc_logrep_ok(no_node, st->device, "nodes");
    }
    watch(t);
    if (ev == NULL || ev->kind != FIRC_TEV_READY) {
        return;
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        if (t->cur.t[i].uplink == FIRC_UPLINK_TUNNEL && strcmp(t->cur.t[i].uplink_ref, st->id) == 0) {
            refresh(t, i);
        }
    }
}

static void forget(firc_tunrun_t *t, const char *id)
{
    char owner[24];
    snprintf(owner, sizeof owner, FIRC_MARK_TUNNEL_OWNER "%s", id);
    firc_rtnl_forget_mark_field(t->r, owner);
}

static void remove_uplink(firc_tunrun_t *t, const char *device, firc_tunnet_uplink_t *u)
{
    firc_err_t err = firc_tunnet_uplink_remove(t->r, u);
    if (err != FIRC_OK) {
        firc_log_from(FIRC_LOG_WARN, device, "uplink not fully removed: %s", firc_err_str(err));
    }
    memset(u, 0, sizeof *u);
}

static ssize_t find_drain(const firc_tunrun_t *t, const char *id)
{
    for (size_t i = 0; i < t->n_drains; i++) {
        if (strcmp(t->drains[i].id, id) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static void drop_drain(firc_tunrun_t *t, size_t i)
{
    memmove(&t->drains[i], &t->drains[i + 1], (t->n_drains - i - 1) * sizeof *t->drains);
    t->n_drains--;
}

static void release(firc_tunrun_t *t, size_t i)
{
    remove_uplink(t, t->drains[i].device, &t->drains[i].u);
    forget(t, t->drains[i].id);
    drop_drain(t, i);
}

static void drain(firc_tunrun_t *t, const firc_tunnel_t *tun, firc_tunnet_uplink_t *u)
{
    if (!firc_tunsup_holds(t->sup, tun->id, u->mark)) {
        remove_uplink(t, tun->device, u);
        forget(t, tun->id);
        return;
    }
    drain_t *grown = realloc(t->drains, (t->n_drains + 1) * sizeof *grown);
    if (grown == NULL) {
        firc_log_from(FIRC_LOG_WARN, tun->device, "out of memory, its uplink rule stays until the next start");
        memset(u, 0, sizeof *u);
        return;
    }
    t->drains = grown;
    drain_t *d = &t->drains[t->n_drains++];
    snprintf(d->id, sizeof d->id, "%s", tun->id);
    snprintf(d->device, sizeof d->device, "%s", tun->device);
    d->u = *u;
    memset(u, 0, sizeof *u);
}

static void on_reap(const char *id, pid_t pid, void *ud)
{
    (void)pid;
    firc_tunrun_t *t = ud;
    ssize_t d = find_drain(t, id);
    if (d >= 0 && !firc_tunsup_holds(t->sup, id, t->drains[d].u.mark)) {
        release(t, (size_t)d);
    }
}

firc_tunrun_t *firc_tunrun_new(firc_loop_t *loop, firc_rtnl_t *r, uint32_t start_table, const char *binary)
{
    firc_tunrun_t *t = calloc(1, sizeof *t);
    if (t == NULL) {
        return NULL;
    }
    t->loop = loop;
    t->r = r;
    t->list_max = TUNVLESS_STDIN_MAX;
    t->start = start_table;
    t->now = mono_ms;
    t->sup = firc_tunsup_new(loop, binary, on_event, t);
    if (t->sup == NULL) {
        free(t);
        return NULL;
    }
    firc_tunsup_set_on_reap(t->sup, on_reap, t);
    if (firc_loop_add_timer(loop, WATCH_MS, WATCH_MS, on_watch, t, &t->watch_timer) != FIRC_OK) {
        t->watch_timer = 0;
        FIRC_WARN("tunnels: a tunnel with no working node will not be reported");
    }
    return t;
}

typedef struct {
    char id[FIRC_MARK_MAX_GROUPS][16];
    size_t n;
} tun_owners_t;

static void collect_tun_owners(void *ud, const firc_rtnl_field_t *v, size_t n)
{
    tun_owners_t *o = ud;
    size_t pl = sizeof(FIRC_MARK_TUNNEL_OWNER) - 1;
    for (size_t i = 0; i < n && o->n < FIRC_MARK_MAX_GROUPS; i++) {
        if (strncmp(v[i].owner, FIRC_MARK_TUNNEL_OWNER, pl) == 0 && strlen(v[i].owner + pl) < sizeof o->id[0]) {
            snprintf(o->id[o->n++], sizeof o->id[0], "%s", v[i].owner + pl);
        }
    }
}

static bool holds_field(const firc_tunrun_t *t, const char *id)
{
    for (size_t i = 0; i < t->cur.n; i++) {
        if (t->up[i].mark != 0 && strcmp(t->cur.t[i].id, id) == 0) {
            return true;
        }
    }
    return find_drain(t, id) >= 0;
}

static void free_unheld_fields(firc_tunrun_t *t)
{
    tun_owners_t *o = calloc(1, sizeof *o);
    if (o == NULL) {
        return;
    }
    firc_rtnl_fields_now(t->r, collect_tun_owners, o);
    for (size_t i = 0; i < o->n; i++) {
        if (!holds_field(t, o->id[i])) {
            forget(t, o->id[i]);
        }
    }
    free(o);
}

static ssize_t find(const firc_tunnels_t *all, const char *id)
{
    for (size_t i = 0; i < all->n; i++) {
        if (strcmp(all->t[i].id, id) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static void keep(firc_tunrun_t *t, const firc_tunnel_t *nt, const firc_tunnels_t *want, firc_tunnet_uplink_t *u)
{
    firc_err_t err = firc_tunnet_uplink_refresh(t->r, nt, want, u);
    if (err != FIRC_OK) {
        firc_log_from(FIRC_LOG_WARN, nt->device, "uplink route not rewritten: %s", firc_err_str(err));
    }
}

static void free_sendable(firc_tun_src_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(v[i].link);
    }
    free(v);
}

static void free_one_sent(sent_t *x)
{
    free_sendable(x->src, x->n);
    free(x->row_of);
    firc_tun_nodes_free(&x->rows);
    memset(x, 0, sizeof *x);
}

static size_t fit_stdin(const firc_tunnel_t *tun, firc_tun_src_t *v, size_t k, firc_tun_nodes_t *nodes,
                        const size_t *row_of, size_t max)
{
    size_t total = 1;
    size_t keep = 0;
    while (keep < k && total + strlen(v[keep].link) + 1 <= max) {
        total += strlen(v[keep].link) + 1;
        keep++;
    }
    if (keep == k) {
        return k;
    }
    for (size_t p = keep; p < k; p++) {
        free(v[p].link);
        v[p].link = NULL;
        snprintf(nodes->v[row_of[p]].skip_reason, sizeof nodes->v[row_of[p]].skip_reason, "%s",
                 "over tunvless's 1 MiB node list");
    }
    firc_log_from(FIRC_LOG_WARN, tun->device, "node list over %zu bytes, %zu nodes kept, %zu left out", max, keep, k - keep);
    return keep;
}

static firc_err_t sendable(const firc_tunnel_t *tun, uint32_t mark, const firc_tun_body_t *bodies, size_t n_bodies,
                           size_t max, sent_t *out)
{
    firc_tun_nodes_t nodes;
    firc_err_t err = firc_tun_nodes_build(tun, mark, bodies, n_bodies, &nodes);
    if (err != FIRC_OK) {
        return err;
    }
    firc_tun_src_t *v = calloc(nodes.n + 1, sizeof *v);
    size_t *row_of = calloc(nodes.n + 1, sizeof *row_of);
    if (v == NULL || row_of == NULL) {
        free(v);
        free(row_of);
        firc_tun_nodes_free(&nodes);
        return FIRC_ERR_NOMEM;
    }
    size_t k = 0;
    for (size_t i = 0; i < nodes.n; i++) {
        if (nodes.v[i].link != NULL) {
            v[k].kind = FIRC_TUN_SRC_LINK;
            v[k].link = nodes.v[i].link;
            nodes.v[i].link = NULL;
            row_of[k] = i;
            k++;
        }
    }
    k = fit_stdin(tun, v, k, &nodes, row_of, max);
    out->src = v;
    out->row_of = row_of;
    out->n = k;
    out->have = true;
    out->rows = nodes;
    return FIRC_OK;
}

static void want_subs(firc_tunrun_t *t)
{
    size_t n = t->cur.n;
    firc_tunnel_t *view = calloc(n + 1, sizeof *view);
    uint32_t *marks = calloc(n + 1, sizeof *marks);
    if (view == NULL || marks == NULL) {
        free(view);
        free(marks);
        FIRC_WARN("tunnels: out of memory, the subscriptions to fetch are not updated");
        return;
    }
    for (size_t i = 0; i < n; i++) {
        view[i] = t->cur.t[i];
        view[i].enable = view[i].enable && t->ok[i];
        marks[i] = t->ok[i] ? t->up[i].mark : 0;
    }
    firc_tunnels_t sel = {.t = view, .n = n};
    firc_tunsubs_want(t->subs, &sel, marks);
    free(view);
    free(marks);
}

static void mark_syn(firc_tunrun_t *t)
{
    for (size_t i = 0; i < t->cur.n; i++) {
        const firc_tunnel_t *tun = &t->cur.t[i];
        firc_tun_status_t cls = !tun->enable ? FIRC_TUN_ST_OFF
                                : !t->ok[i]  ? FIRC_TUN_ST_UPLINK_DOWN
                                : t->waiting[i] ? FIRC_TUN_ST_WAITING
                                                : FIRC_TUN_ST_STARTING;
        if (cls != t->ext[i].syn || t->ext[i].syn_since == 0) {
            t->ext[i].syn = cls;
            t->ext[i].syn_since = mono_ms();
        }
    }
}

static firc_err_t push(firc_tunrun_t *t, bool want)
{
    size_t n = t->cur.n;
    firc_tunnel_t *run = calloc(n + 1, sizeof *run);
    uint32_t *marks = calloc(n + 1, sizeof *marks);
    if (run == NULL || marks == NULL) {
        free(run);
        free(marks);
        return FIRC_ERR_NOMEM;
    }
    if (want && t->subs != NULL) {
        want_subs(t);
    }
    size_t n_bodies = 0;
    const firc_tun_body_t *bodies = firc_tunsubs_bodies(t->subs, &n_bodies);
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (!t->ok[i]) {
            continue;
        }
        const firc_tunnel_t *tun = &t->cur.t[i];
        uint32_t mark = t->up[i].mark;
        sent_t fresh = {0};
        firc_err_t err = sendable(tun, mark, bodies, n_bodies, t->list_max, &fresh);
        if (err != FIRC_OK) {
            firc_log_from(FIRC_LOG_ERROR, tun->device, "node list not built: %s", firc_err_str(err));
        } else {
            free_one_sent(&t->sent[i]);
            t->sent[i] = fresh;
            prune(&t->ext[i].downs, &t->sent[i]);
            prune(&t->ext[i].acts, &t->sent[i]);
        }
        if (tun->enable && t->sent[i].n == 0) {
            if (!t->waiting[i]) {
                firc_log_from(FIRC_LOG_INFO, tun->device, "no nodes to use yet");
                t->waiting[i] = true;
            }
            continue;
        }
        t->waiting[i] = false;
        run[k] = *tun;
        run[k].src = t->sent[i].src;
        run[k].n_src = t->sent[i].n;
        marks[k] = mark;
        k++;
    }
    firc_tunnels_t sel = {.t = run, .n = k};
    firc_err_t rc = firc_tunsup_apply(t->sup, &sel, marks);
    if (rc != FIRC_OK) {
        FIRC_ERROR("tunnels: not every tunnel could be started: %s", firc_err_str(rc));
    }
    free(run);
    free(marks);
    mark_syn(t);
    return rc;
}

static void free_sent(sent_t *v, size_t n)
{
    for (size_t i = 0; v != NULL && i < n; i++) {
        free_one_sent(&v[i]);
    }
    free(v);
}

static void free_ext(ext_t *v, size_t n)
{
    for (size_t i = 0; v != NULL && i < n; i++) {
        free(v[i].downs.v);
        free(v[i].acts.v);
    }
    free(v);
}

static void drop_ports(firc_tunrun_t *t)
{
    bool changed = false;
    for (int dev = 0; dev < FIRC_KTCP_DEVICES; dev++) {
        bool kept = false;
        for (size_t i = 0; i < t->cur.n && t->ports[dev] != 0 && !kept; i++) {
            kept = firc_tunnel_tcp_port(&t->cur.t[i]) == t->ports[dev];
        }
        if (t->ports[dev] != 0 && !kept) {
            t->ports[dev] = 0;
            t->drifts[dev] = 0;
            changed = true;
        }
    }
    if (changed) {
        publish(t);
    }
}

firc_err_t firc_tunrun_apply(firc_tunrun_t *t, firc_tunnels_t *want)
{
    if (t->stopped) {
        return FIRC_ERR_STATE;
    }
    size_t n = want->n;
    firc_tunnet_uplink_t *up = calloc(n + 1, sizeof *up);
    bool *ok = calloc(n + 1, sizeof *ok);
    bool *kept = calloc(t->cur.n + 1, sizeof *kept);
    sent_t *sent = calloc(n + 1, sizeof *sent);
    bool *waiting = calloc(n + 1, sizeof *waiting);
    ext_t *ext = calloc(n + 1, sizeof *ext);
    if (up == NULL || ok == NULL || kept == NULL || sent == NULL || waiting == NULL || ext == NULL) {
        free(up);
        free(ok);
        free(kept);
        free(sent);
        free(waiting);
        free(ext);
        return FIRC_ERR_NOMEM;
    }
    for (size_t i = 0; i < n; i++) {
        const firc_tunnel_t *nt = &want->t[i];
        ssize_t j = find(&t->cur, nt->id);
        bool need = needs_uplink(nt);
        if (j >= 0) {
            kept[j] = true;
            sent[i] = t->sent[j];
            memset(&t->sent[j], 0, sizeof t->sent[j]);
            waiting[i] = t->waiting[j];
            ext[i] = t->ext[j];
            memset(&t->ext[j], 0, sizeof t->ext[j]);
            if (t->up[j].mark != 0) {
                if (need) {
                    up[i] = t->up[j];
                    memset(&t->up[j], 0, sizeof t->up[j]);
                    keep(t, nt, want, &up[i]);
                } else {
                    drain(t, nt, &t->up[j]);
                }
                ok[i] = true;
                continue;
            }
        }
        if (!need) {
            ok[i] = true;
            continue;
        }
        ssize_t d = find_drain(t, nt->id);
        if (d >= 0) {
            up[i] = t->drains[d].u;
            drop_drain(t, (size_t)d);
            keep(t, nt, want, &up[i]);
            ok[i] = true;
            continue;
        }
        firc_err_t err = firc_tunnet_uplink_apply(t->r, t->start, nt, want, &up[i]);
        if (err != FIRC_OK) {
            if (up[i].mark != 0) {
                remove_uplink(t, nt->device, &up[i]);
            }
            memset(&up[i], 0, sizeof up[i]);
            forget(t, nt->id);
            firc_log_from(FIRC_LOG_ERROR, nt->device, "not started, its uplink could not be set up (%s)",
                          firc_err_str(err));
            continue;
        }
        ok[i] = true;
    }
    for (size_t j = 0; j < t->cur.n; j++) {
        if (!kept[j] && t->up[j].mark != 0) {
            drain(t, &t->cur.t[j], &t->up[j]);
        } else if (!kept[j] && find_drain(t, t->cur.t[j].id) < 0) {
            forget(t, t->cur.t[j].id);
        }
    }
    free_sent(t->sent, t->cur.n);
    free_ext(t->ext, t->cur.n);
    firc_tunnels_free(&t->cur);
    free(t->up);
    free(t->ok);
    free(t->waiting);
    t->cur = *want;
    t->up = up;
    t->ok = ok;
    t->sent = sent;
    t->waiting = waiting;
    t->ext = ext;
    want->t = NULL;
    want->n = 0;
    drop_ports(t);
    free_unheld_fields(t);
    firc_err_t rc = push(t, true);
    firc_tunsubs_sweep(t->subs, &t->cur);
    for (size_t i = 0; i < t->cur.n; i++) {
        show_uplink(t, i);
    }
    free(kept);
    return rc;
}

void firc_tunrun_set_subs(firc_tunrun_t *t, firc_tunsubs_t *subs)
{
    t->subs = subs;
}

void firc_tunrun_bodies_changed(void *ud)
{
    firc_tunrun_t *t = ud;
    if (t == NULL || t->stopped) {
        return;
    }
    (void)push(t, false);
}

size_t firc_tunrun_states(const firc_tunrun_t *t, firc_tun_state_t *out, size_t cap)
{
    firc_tun_state_t run[FIRC_TUN_MAX * 2];
    size_t n_run = firc_tunsup_states(t->sup, run, sizeof run / sizeof run[0]);
    if (n_run > sizeof run / sizeof run[0]) {
        n_run = sizeof run / sizeof run[0];
    }
    for (size_t i = 0; i < t->cur.n && i < cap; i++) {
        const firc_tunnel_t *tun = &t->cur.t[i];
        firc_tun_state_t *st = &out[i];
        memset(st, 0, sizeof *st);
        snprintf(st->id, sizeof st->id, "%s", tun->id);
        snprintf(st->device, sizeof st->device, "%s", tun->device);
        st->status = t->ext[i].syn;
        st->since_ms = t->ext[i].syn_since;
        st->uplink_ok = !needs_uplink(tun) || (t->ok[i] && t->up[i].routed);
        int dev = ktcp_dev(tun);
        uint16_t port = dev < 0 || t->ktcp_unusable ? 0 : t->ports[dev];
        st->tcp_port = port;
        if (t->ext[i].syn == FIRC_TUN_ST_UPLINK_DOWN || t->ext[i].syn == FIRC_TUN_ST_WAITING) {
            continue;
        }
        st->status = FIRC_TUN_ST_OFF;
        for (size_t k = 0; k < n_run; k++) {
            if (strcmp(run[k].id, tun->id) == 0) {
                *st = run[k];
                st->tcp_port = port;
                break;
            }
        }
    }
    return t->cur.n;
}

bool firc_tunrun_device_down(const firc_tunrun_t *t, const char *device)
{
    if (device == NULL) {
        return false;
    }
    firc_tun_state_t st[FIRC_TUN_MAX];
    size_t n = firc_tunrun_states(t, st, FIRC_TUN_MAX);
    for (size_t i = 0; i < n && i < FIRC_TUN_MAX; i++) {
        if (strcmp(st[i].device, device) == 0) {
            return st[i].status != FIRC_TUN_ST_UP;
        }
    }
    return false;
}

bool firc_tunrun_device_starting(const firc_tunrun_t *t, const char *device, int64_t *since_ms)
{
    if (device == NULL) {
        return false;
    }
    firc_tun_state_t st[FIRC_TUN_MAX];
    size_t n = firc_tunrun_states(t, st, FIRC_TUN_MAX);
    for (size_t i = 0; i < n && i < FIRC_TUN_MAX; i++) {
        if (strcmp(st[i].device, device) != 0) {
            continue;
        }
        if (st[i].status != FIRC_TUN_ST_STARTING && st[i].status != FIRC_TUN_ST_WAITING) {
            return false;
        }
        *since_ms = st[i].since_ms;
        return true;
    }
    return false;
}

const firc_tunnels_t *firc_tunrun_config(const firc_tunrun_t *t)
{
    return &t->cur;
}

firc_err_t firc_tunrun_restart(firc_tunrun_t *t, const char *id)
{
    if (t->stopped || find(&t->cur, id) < 0) {
        return FIRC_ERR_NOENT;
    }
    firc_err_t err = firc_tunsup_restart(t->sup, id);
    return err == FIRC_ERR_NOENT ? FIRC_ERR_STATE : err;
}

uint64_t firc_tunrun_start_seq(const firc_tunrun_t *t)
{
    return firc_tunsup_start_seq(t->sup);
}

uint64_t firc_tunrun_started(const firc_tunrun_t *t, const char *id)
{
    return firc_tunsup_started(t->sup, id);
}

uint64_t firc_tunrun_updated(const firc_tunrun_t *t, const char *id)
{
    return firc_tunsup_updated(t->sup, id);
}

const firc_tun_nodes_t *firc_tunrun_nodes(const firc_tunrun_t *t, const char *id)
{
    ssize_t i = find(&t->cur, id);
    if (i < 0 || !t->sent[i].have) {
        return NULL;
    }
    return &t->sent[i].rows;
}

bool firc_tunrun_node_down(const firc_tunrun_t *t, const char *id, const char *key, int64_t *since_ms)
{
    ssize_t i = find(&t->cur, id);
    const down_t *d = i < 0 ? NULL : key_find(&t->ext[i].downs, key);
    if (d == NULL) {
        return false;
    }
    *since_ms = d->since;
    return true;
}

bool firc_tunrun_node_active(const firc_tunrun_t *t, const char *id, const char *key)
{
    ssize_t i = find(&t->cur, id);
    return i >= 0 && key_find(&t->ext[i].acts, key) != NULL;
}

bool firc_tunrun_mark_of(const firc_tunrun_t *t, const char *id, uint32_t *mark, bool *held)
{
    *mark = 0;
    *held = false;
    ssize_t i = find(&t->cur, id);
    if (i < 0) {
        return false;
    }
    *mark = t->up[i].mark;
    *held = *mark != 0 && firc_tunsup_holds(t->sup, id, *mark);
    return true;
}

void firc_tunrun_refresh_uplinks(firc_tunrun_t *t, const char *ifname)
{
    if (t == NULL || t->stopped) {
        return;
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        const char *dev = firc_tunnet_uplink_device(&t->cur.t[i], &t->cur);
        if (t->up[i].mark != 0 && dev != NULL && (ifname == NULL || strcmp(dev, ifname) == 0)) {
            refresh(t, i);
        }
    }
}

void firc_tunrun_stop(firc_tunrun_t *t, int grace_ms)
{
    if (t == NULL || t->stopped) {
        return;
    }
    if (t->watch_timer != 0) {
        (void)firc_loop_del_timer(t->loop, t->watch_timer);
        t->watch_timer = 0;
    }
    firc_tunsup_stop(t->sup, grace_ms);
    while (t->n_drains > 0) {
        release(t, t->n_drains - 1);
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        remove_uplink(t, t->cur.t[i].device, &t->up[i]);
    }
    t->stopped = true;
}

void firc_tunrun_free(firc_tunrun_t *t)
{
    if (t == NULL) {
        return;
    }
    firc_tunrun_stop(t, 0);
    firc_tunsup_free(t->sup);
    free_sent(t->sent, t->cur.n);
    free_ext(t->ext, t->cur.n);
    firc_tunnels_free(&t->cur);
    free(t->up);
    free(t->ok);
    free(t->waiting);
    free(t->drains);
    free(t);
}

void firc_tunrun_set_list_max_for_test(firc_tunrun_t *t, size_t bytes)
{
    t->list_max = bytes;
}

void firc_tunrun_set_ktcp(firc_tunrun_t *t, const firc_tunrun_ktcp_t *k)
{
    t->has_k = k != NULL;
    if (k != NULL) {
        t->k = *k;
        publish(t);
    }
}

typedef struct {
    firc_ktcp_cmds_t per[FIRC_KTCP_DEVICES];
    const firc_tunnel_t *to[FIRC_KTCP_DEVICES];
    bool failed[FIRC_KTCP_DEVICES];
} push_t;

static void delta_line(uint8_t dev, const uint8_t fake[4], const uint8_t *real, void *ud)
{
    push_t *p = ud;
    if (dev < FIRC_KTCP_DEVICES && p->to[dev] != NULL && !p->failed[dev] &&
        firc_ktcp_line(&p->per[dev], fake, real) != FIRC_OK) {
        p->failed[dev] = true;
    }
}

static const firc_tunnel_t *live_with_port(const firc_tunrun_t *t, int dev)
{
    for (size_t i = 0; i < t->cur.n && t->ports[dev] != 0; i++) {
        if (ktcp_dev(&t->cur.t[i]) == dev && firc_tunsup_ready(t->sup, t->cur.t[i].id)) {
            return &t->cur.t[i];
        }
    }
    return NULL;
}

void firc_tunrun_map_pushed(firc_tunrun_t *t, const firc_ktcp_image_t *prev, const firc_ktcp_image_t *next)
{
    if (t->stopped) {
        return;
    }
    push_t *p = calloc(1, sizeof *p);
    if (p == NULL) {
        FIRC_WARN("tunnels: out of memory, address map changes not sent");
        return;
    }
    bool any = false;
    for (int dev = 0; dev < FIRC_KTCP_DEVICES; dev++) {
        p->to[dev] = live_with_port(t, dev);
        any = any || p->to[dev] != NULL;
    }
    if (any) {
        firc_ktcp_image_diff(prev, next, delta_line, p);
    }
    for (int dev = 0; dev < FIRC_KTCP_DEVICES; dev++) {
        if (p->failed[dev]) {
            send_mapall(t, p->to[dev], dev, next);
        } else if (p->to[dev] != NULL) {
            send_cmds(t, p->to[dev], FIRC_TUN_CMD_MAP, &p->per[dev]);
        }
        firc_ktcp_cmds_free(&p->per[dev]);
    }
    free(p);
}

void firc_tunrun_set_ktcp_usable(firc_tunrun_t *t, bool usable)
{
    t->ktcp_unusable = !usable;
}

void firc_tunrun_set_tcp_pool(firc_tunrun_t *t, const uint8_t base[4], uint8_t len)
{
    firc_tunsup_set_tcp_pool(t->sup, base, len);
}

int firc_tunrun_close(firc_tunrun_t *t, uint8_t dev, const firc_nf_prefix_t *p, size_t n)
{
    const firc_tunnel_t *tun = t->stopped || dev >= FIRC_KTCP_DEVICES ? NULL : live_with_port(t, dev);
    if (tun == NULL) {
        return 0;
    }
    firc_ktcp_cmds_t c = {0};
    int sent = 0;
    if (firc_ktcp_close_cmd(p, n, &c) == FIRC_OK) {
        sent = send_cmds(t, tun, FIRC_TUN_CMD_CLOSE, &c);
    } else {
        firc_log_from(FIRC_LOG_WARN, tun->device, "out of memory, close not sent");
    }
    firc_ktcp_cmds_free(&c);
    return sent;
}

int firc_tunrun_set_watch_for_test(firc_tunrun_t *t, int64_t (*now_ms)(void), int period_ms)
{
    t->now = now_ms != NULL ? now_ms : mono_ms;
    if (t->watch_timer != 0) {
        (void)firc_loop_del_timer(t->loop, t->watch_timer);
    }
    if (firc_loop_add_timer(t->loop, (uint64_t)period_ms, (uint64_t)period_ms, on_watch, t, &t->watch_timer) != FIRC_OK) {
        t->watch_timer = 0;
    }
    return t->watch_timer;
}

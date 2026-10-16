#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fake_iptables.h"
#include "firc/dnat.h"
#include "firc/fakeip.h"
#include "firc/ipset_to_link.h"
#include "firc/iptables.h"
#include "firc/log.h"
#include "firc/mark.h"
#include "firc/netfilter_cleaner.h"
#include "firc/pool_reject.h"

#define GROUPS 8
#define MAX_PASSES 200

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void say(const char *what, double *v, size_t n) {
    qsort(v, n, sizeof(*v), cmp_d);
    size_t i90 = (n * 9) / 10 < n ? (n * 9) / 10 : n - 1;
    printf("%s p50 %.2f p90 %.2f\n", what, v[n / 2], v[i90]);
}

static firc_ipt_t *engine(firc_ipt_proto_t fam) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(fam);
    return f != NULL ? firc_ipt_new(firc_fake_ipt_as_xt(f), "FIRC_") : NULL;
}

static firc_err_t stage(firc_ipt_t *const ipt[2], const firc_fakeip_t *pool, const firc_fakeip_snapshot_t *snap) {
    firc_err_t err = firc_netfilter_register_base_chains(ipt[0], ipt[1]);
    for (unsigned f = 0; f < 2 && err == FIRC_OK; f++) {
        firc_ip_t base;
        uint8_t len = 0;
        if (firc_fakeip_snapshot_pool_prefix(snap, f, &base, &len)) {
            err = firc_pool_reject_build_rules(ipt[f], "FIRC_", &base, len);
        }
        for (unsigned g = 0; g < GROUPS && err == FIRC_OK; g++) {
            char chain[32], gid[16];
            uint32_t mark = 0;
            snprintf(chain, sizeof(chain), "FIRC_g%u", g);
            snprintf(gid, sizeof(gid), "g%u", g);
            if (!firc_mark_for_field(g + 1u, &mark)) { return FIRC_ERR_INVAL; }
            err = firc_ipset_to_link_build_rules(ipt[f], chain, "nwg1", mark, g + 1u, snap, gid);
        }
        if (err == FIRC_OK) { err = firc_dnat_build_rules(ipt[f], "FIRC_", snap, NULL, NULL); }
    }
    (void)pool;
    return err;
}

static firc_err_t add_name(firc_fakeip_t *pool, size_t i, int64_t now) {
    char qname[64], gid[16];
    snprintf(qname, sizeof(qname), "n%zu.example.", i);
    snprintf(gid, sizeof(gid), "g%zu", i % GROUPS);
    firc_ip_t v4, v6;
    firc_err_t err = firc_fakeip_get(pool, qname, gid, now, &v4, &v6);
    if (err != FIRC_OK) { return err; }
    firc_ip_t real = {.len = 4};
    real.b[0] = 100;
    real.b[1] = (uint8_t)(64u + ((i >> 16) & 0x3fu));
    real.b[2] = (uint8_t)(i >> 8);
    real.b[3] = (uint8_t)i;
    return firc_fakeip_set_real(pool, qname, gid, &real);
}

int main(int argc, char **argv) {
    size_t n = argc > 1 ? strtoul(argv[1], NULL, 10) : 2000;
    size_t passes = argc > 2 ? strtoul(argv[2], NULL, 10) : 20;
    if (n == 0 || n > 60000 || passes == 0 || passes > MAX_PASSES) {
        fprintf(stderr, "usage: passbench N(1-60000) PASSES(1-%d)\n", MAX_PASSES);
        return 2;
    }
    firc_log_set_fd(STDERR_FILENO);
    firc_log_set_level(FIRC_LOG_DEBUG);
    firc_fakeip_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = n + passes + 16;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    firc_ipt_t *ipt[2] = {engine(FIRC_IPT_PROTO_IPV4), engine(FIRC_IPT_PROTO_IPV6)};
    if (firc_fakeip_new(&c, &pool) != FIRC_OK || ipt[0] == NULL || ipt[1] == NULL) { return 3; }
    int64_t now = 1000;
    for (size_t i = 0; i < n; i++) {
        if (add_name(pool, i, now) != FIRC_OK) { return 3; }
    }
    double snap_ms[MAX_PASSES], stage_ms[MAX_PASSES], c4[MAX_PASSES], c6[MAX_PASSES], full4[MAX_PASSES];
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    if (snap == NULL || stage(ipt, pool, snap) != FIRC_OK || firc_ipt_commit(ipt[0]) != FIRC_OK ||
        firc_ipt_commit(ipt[1]) != FIRC_OK) {
        return 4;
    }
    fprintf(stderr, "passbench: warm-up done, %zu names\n", n);
    for (size_t p = 0; p < passes; p++) {
        if (add_name(pool, n + p, now) != FIRC_OK) { return 3; }
        double a = now_ms();
        firc_fakeip_snapshot_free(snap);
        snap = firc_fakeip_snapshot_take(pool);
        double b = now_ms();
        if (snap == NULL || stage(ipt, pool, snap) != FIRC_OK) { return 4; }
        double s = now_ms();
        if (firc_ipt_commit(ipt[0]) != FIRC_OK) { return 5; }
        double w4 = now_ms();
        if (firc_ipt_commit(ipt[1]) != FIRC_OK) { return 5; }
        double w6 = now_ms();
        snap_ms[p] = b - a;
        stage_ms[p] = s - b;
        c4[p] = w4 - s;
        c6[p] = w6 - w4;
    }
    fprintf(stderr, "passbench: full passes\n");
    for (size_t p = 0; p < passes; p++) {
        if (stage(ipt, pool, snap) != FIRC_OK) { return 4; }
        double a = now_ms();
        if (firc_ipt_commit_full(ipt[0]) != FIRC_OK) { return 5; }
        full4[p] = now_ms() - a;
        if (firc_ipt_commit_full(ipt[1]) != FIRC_OK) { return 5; }
    }
    printf("# passbench N=%zu groups=%d passes=%zu (host, fake kernel)\n", n, GROUPS, passes);
    say("snapshot", snap_ms, passes);
    say("stage", stage_ms, passes);
    say("commit4", c4, passes);
    say("commit6", c6, passes);
    say("full4", full4, passes);
    firc_fakeip_snapshot_free(snap);
    firc_ipt_free(ipt[0]);
    firc_ipt_free(ipt[1]);
    firc_fakeip_free(pool);
    return 0;
}

#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>

#include "fake_conntrack.h"
#include "fake_rtnl.h"
#include "fake_iptables.h"
#include "fake_xtables.h"

#include "firc/app.h"
#include "firc/events.h"
#include "firc/fakeip.h"
#include "firc/netfilter_cleaner.h"
#include "firc/pool_reject.h"
#include "firc/port_remap.h"

unsigned __real_if_nametoindex(const char *name);
unsigned __wrap_if_nametoindex(const char *name);
unsigned __wrap_if_nametoindex(const char *name) {
    return __real_if_nametoindex(strncmp(name, "tunvless", 8) == 0 ? "lo" : name);
}

typedef struct {
    firc_config_t cfg;
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
    firc_app_t *app;
    firc_port_remap_t *remap;
} fixture_t;

/* Rules belonging to somebody else, which a rebuild must leave alone. */
static void seed_foreign_rules(firc_fake_ipt_t *f) {
    static const char *fwd[] = {"-i", "eth0", "-j", "ACCEPT"};
    static const char *pre[] = {"-i", "eth0", "-j", "ACCEPT"};
    static const char *post[] = {"-o", "eth0", "-j", "MASQUERADE"};
    static const char *mangle[] = {"-i", "eth0", "-j", "MARK", "--set-xmark", "0x7/0xffffffff"};

    const char *const *rules[1];
    size_t lens[1];

    rules[0] = fwd;
    lens[0] = 4;
    firc_fake_ipt_set_initial_rules(f, "filter", "FORWARD", rules, lens, 1);
    rules[0] = mangle;
    lens[0] = 6;
    firc_fake_ipt_set_initial_rules(f, "mangle", "PREROUTING", rules, lens, 1);
    rules[0] = pre;
    lens[0] = 4;
    firc_fake_ipt_set_initial_rules(f, "nat", "PREROUTING", rules, lens, 1);
    rules[0] = post;
    lens[0] = 4;
    firc_fake_ipt_set_initial_rules(f, "nat", "POSTROUTING", rules, lens, 1);
}

static void fixture_up(fixture_t *fx) {
    memset(fx, 0, sizeof(*fx));
    firc_config_init_defaults(&fx->cfg);

    fx->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fx->fake);
    fx->ipt = firc_ipt_new(firc_fake_ipt_as_xt(fx->fake), "FIRC_");
    firc_netfilter_register_base_chains(fx->ipt, NULL);

    firc_app_deps_t deps = {.cfg = &fx->cfg, .ipt4 = fx->ipt};
    fx->app = firc_app_create(&deps);

    fx->remap = firc_port_remap_new(fx->cfg.app.netfilter.iptables.chain_prefix, 53, 3553, NULL, 0,
                                  fx->ipt, NULL);
    firc_port_remap_enable(fx->remap);
    firc_app_set_port_remap(fx->app, fx->remap);
}

static void fixture_down(fixture_t *fx) {
    firc_port_remap_free(fx->remap);
    firc_app_destroy(fx->app);
    firc_ipt_free(fx->ipt);
    firc_config_clear(&fx->cfg);
}

static void seed_stale_chain(firc_fake_ipt_t *f) {
    static const char *rule[] = {"-j", "MASQUERADE"};
    static const char *jump[] = {"-j", "FIRC_old"};
    const char *const *rules[1] = {rule};
    size_t lens[1] = {2};
    firc_fake_ipt_set_initial_rules(f, "nat", "FIRC_old", rules, lens, 1);

    const char *const *keep[2];
    size_t keep_lens[2];
    static const char *foreign[] = {"-o", "eth0", "-j", "MASQUERADE"};
    keep[0] = foreign;
    keep_lens[0] = 4;
    keep[1] = jump;
    keep_lens[1] = 2;
    firc_fake_ipt_set_initial_rules(f, "nat", "POSTROUTING", keep, keep_lens, 2);
}

static bool chain_has_rule(firc_fake_ipt_t *f, const char *table, const char *chain,
                          const char *const *parts, size_t n_parts) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        if (rules[i]->n_parts != n_parts) { continue; }
        bool same = true;
        for (size_t j = 0; j < n_parts; j++) {
            if (strcmp(rules[i]->parts[j], parts[j]) != 0) {
                same = false;
                break;
            }
        }
        if (same) { return true; }
    }
    return false;
}

static size_t count_rule(firc_fake_ipt_t *f, const char *table, const char *chain,
                        const char *const *parts, size_t n_parts) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0, found = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return 0; }
    for (size_t i = 0; i < n; i++) {
        if (rules[i]->n_parts != n_parts) { continue; }
        bool same = true;
        for (size_t j = 0; j < n_parts; j++) {
            if (strcmp(rules[i]->parts[j], parts[j]) != 0) {
                same = false;
                break;
            }
        }
        if (same) { found++; }
    }
    return found;
}

static const char *const k_remap_jump[] = {"-j", "FIRC_DNSOR"};
static const char *const k_foreign_post[] = {"-o", "eth0", "-j", "MASQUERADE"};

TEST rebuild_does_not_duplicate_jumps(void) {
    fixture_t fx;
    fixture_up(&fx);

    for (int i = 0; i < 4; i++) { ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, NULL)); }

    ASSERT_EQ(1u, count_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2));

    fixture_down(&fx);
    PASS();
}

TEST rebuild_drops_chains_left_by_a_previous_run(void) {
    fixture_t fx;
    fixture_up(&fx);
    seed_stale_chain(fx.fake);
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, NULL));

    ASSERT_FALSE(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));
    static const char *const stale_jump[] = {"-j", "FIRC_old"};
    ASSERT_EQ(0u, count_rule(fx.fake, "nat", "POSTROUTING", stale_jump, 2));
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    fixture_down(&fx);
    PASS();
}

TEST rebuild_keeps_other_writers_rules(void) {
    fixture_t fx;
    fixture_up(&fx);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, NULL));

    ASSERT(chain_has_rule(fx.fake, "nat", "POSTROUTING", k_foreign_post, 4));
    static const char *const foreign_fwd[] = {"-i", "eth0", "-j", "ACCEPT"};
    ASSERT(chain_has_rule(fx.fake, "filter", "FORWARD", foreign_fwd, 4));

    fixture_down(&fx);
    PASS();
}

/* Catches: a pass with a raised cancel token writing, or reporting a failure. */
TEST rebuild_aborts_on_a_raised_cancel(void) {
    fixture_t fx;
    fixture_up(&fx);

    firc_fake_ipt_reset(fx.fake);
    seed_foreign_rules(fx.fake);

    firc_cancel_t *cancel = firc_cancel_new();
    firc_cancel_raise(cancel);

    ASSERT_EQ(FIRC_ERR_CANCELED, firc_app_rebuild_netfilter(fx.app, cancel));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    firc_cancel_clear(cancel);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(fx.app, cancel));
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    firc_cancel_free(cancel);
    fixture_down(&fx);
    PASS();
}

/* Catches: a pass not writing the DNAT chain from its snapshot, or not committing the pool. */
TEST a_pass_writes_the_dnat_chain_and_commits_the_pool(void) {
    firc_fakeip_cfg_t c = {0};
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
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_fake_ipt_t *fake6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt6 = firc_ipt_new(firc_fake_ipt_as_xt(fake6), "FIRC_");
    firc_netfilter_register_base_chains(ipt, ipt6);
    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt, .ipt6 = ipt6, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);

    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, NULL));
    const firc_ip_t real = {{93, 184, 216, 34}, 4};
    const firc_ip_t real6 = {{0x26, 0x06, 0x28, 0, 0x02, 0x20, 0, 1, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46}, 16};
    firc_ip_t both[] = {real, real6};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", "g1", both, 2));
    ASSERT(firc_fakeip_needs_commit(pool, &fake4));
    ASSERT_EQ(FIRC_OK, firc_app_refresh_pool_snapshot(app));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    static const char *want[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination", "93.184.216.34"};
    ASSERT_FALSEm("a mapping of a group the app does not route gets no rule",
                  chain_has_rule(fake, "nat", "FIRC_DNAT", want, 6));
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERTm("entered from PREROUTING, guarded by the pool prefix", chain_has_rule(fake, "nat", "PREROUTING", jump, 4));
    static const char *want6[] = {"-d", "fd37:9a00::1/128", "-j", "DNAT", "--to-destination",
                                  "2606:2800:220:1:248:1893:25c8:1946"};
    ASSERT_FALSEm("nor in the v6 table", chain_has_rule(fake6, "nat", "FIRC_DNAT", want6, 6));
    ASSERT_FALSEm("and the pool was told the pass completed",
                  firc_fakeip_needs_commit(pool, &fake4));

    const firc_ip_t moved = {{93, 184, 216, 35}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", "g1", &moved, 1));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    ASSERTm("a pass over an older snapshot does not commit a newer pair",
            firc_fakeip_needs_commit(pool, &fake4));

    firc_app_destroy(app);
    firc_ipt_free(ipt);
    firc_ipt_free(ipt6);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Builds an app with fake conntrack and a loop, for the window a full pass opens. */
static void up_with_conntrack_and_loop(firc_config_t *cfg, firc_fake_ipt_t **fake, firc_ipt_t **ipt,
                                       firc_fakeip_t **pool, fake_ct_t **kernel, firc_ct_t **ct,
                                       firc_app_t **app, firc_loop_t *loop) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    *pool = NULL;
    if (firc_fakeip_new(&c, pool) != FIRC_OK) { return; }
    firc_config_init_defaults(cfg);
    *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    *ipt = firc_ipt_new(firc_fake_ipt_as_xt(*fake), "FIRC_");
    firc_netfilter_register_base_chains(*ipt, NULL);
    *kernel = fake_ct_start(ct);
    firc_app_deps_t deps = {.cfg = cfg, .ipt4 = *ipt, .pool = *pool, .ct = *ct, .loop = loop};
    *app = firc_app_create(&deps);
}

static void up_with_conntrack(firc_config_t *cfg, firc_fake_ipt_t **fake, firc_ipt_t **ipt,
                              firc_fakeip_t **pool, fake_ct_t **kernel, firc_ct_t **ct,
                              firc_app_t **app) {
    up_with_conntrack_and_loop(cfg, fake, ipt, pool, kernel, ct, app, NULL);
}

static const uint8_t k_issued4[4] = {198, 18, 0, 1};
static const uint8_t k_real4[4] = {93, 184, 216, 34};
static const uint8_t k_issued6[16] = {0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t k_real6[16] = {0x26, 0x06, 0x28, 0, 2, 0x20, 0, 1,
                                    2,    0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46};

static void seed_window_flows(fake_ct_t *k) {
    const uint8_t client[4] = {192, 168, 1, 10};
    const uint8_t client6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    fake_ct_add(k, AF_INET, client, k_issued4, k_issued4, 0);
    fake_ct_add(k, AF_INET, client, k_issued4, k_real4, 0);
    fake_ct_add(k, AF_INET6, client6, k_issued6, k_issued6, 0);
    fake_ct_add(k, AF_INET6, client6, k_issued6, k_real6, 0);
}

/* Catches: flows answered from the pool during a full pass's window left unswept. */
TEST a_full_pass_clears_the_flows_of_the_window_it_opened(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    up_with_conntrack(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    ASSERTm("the unbound v4 flow of the window is dropped", fake_ct_deleted(kernel, k_issued4, 4));
    ASSERTm("and the v6 one, which has a half of the sweep to itself",
            fake_ct_deleted(kernel, k_issued6, 16));
    ASSERT_FALSEm("the bound v4 flow is not: it is routed correctly",
                  fake_ct_deleted(kernel, k_real4, 4));
    ASSERT_FALSEm("nor the bound v6 one", fake_ct_deleted(kernel, k_real6, 16));

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: an incremental pass sweeping live flows. */
TEST an_incremental_pass_opens_no_window_and_clears_nothing(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    up_with_conntrack(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(app, NULL, false));

    ASSERT_EQ_FMTm("the kernel was not asked for a dump at all", (size_t)0,
                   fake_ct_dumps(kernel), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(kernel), "%zu");

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

static void stop_the_loop(firc_loop_t *loop, void *ud) {
    (void)ud;
    firc_loop_stop(loop);
}

/* Catches: a full pass reported through the loop not sweeping. */
TEST the_sweep_also_happens_when_the_pass_is_reported_through_the_loop(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    up_with_conntrack_and_loop(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app, loop);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    ASSERT_FALSEm("nothing has run on the loop yet", fake_ct_deleted(kernel, k_issued4, 4));

    ASSERT_EQ(FIRC_OK, firc_loop_post(loop, stop_the_loop, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));

    ASSERTm("the window's flow went when the report landed",
            fake_ct_deleted(kernel, k_issued4, 4));

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: an incremental pass reported through the loop sweeping. */
TEST an_incremental_pass_reported_through_the_loop_clears_nothing(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    up_with_conntrack_and_loop(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app, loop);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(app, NULL, false));
    ASSERT_EQ(FIRC_OK, firc_loop_post(loop, stop_the_loop, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));

    ASSERT_EQ_FMTm("the kernel was not asked for a dump at all", (size_t)0,
                   fake_ct_dumps(kernel), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(kernel), "%zu");

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    firc_loop_destroy(loop);
    PASS();
}

typedef struct {
    firc_app_t *app;
    fake_ct_t *kernel;
    size_t dumps_before_the_second_report;
} debt_probe_t;

static void incremental_then_full_then_stop(firc_loop_t *loop, void *ud) {
    debt_probe_t *p = ud;
    (void)firc_app_rebuild_netfilter_kind(p->app, NULL, false);
    p->dumps_before_the_second_report = fake_ct_dumps(p->kernel);
    firc_loop_stop(loop);
}

TEST a_sweep_that_could_not_finish_waits_for_the_next_full_pass(void) {
    firc_config_t cfg;
    firc_fake_ipt_t *fake = NULL;
    firc_ipt_t *ipt = NULL;
    firc_fakeip_t *pool = NULL;
    fake_ct_t *kernel = NULL;
    firc_ct_t *ct = NULL;
    firc_app_t *app = NULL;
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    up_with_conntrack_and_loop(&cfg, &fake, &ipt, &pool, &kernel, &ct, &app, loop);
    ASSERT(app != NULL && kernel != NULL);
    seed_window_flows(kernel);

    fake_ct_fail_dump_of(kernel, AF_INET, ENOBUFS);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    debt_probe_t probe = {.app = app, .kernel = kernel, .dumps_before_the_second_report = 0};
    ASSERT_EQ(FIRC_OK, firc_loop_post(loop, incremental_then_full_then_stop, &probe));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    size_t after_incremental = probe.dumps_before_the_second_report;
    ASSERTm("the full pass's sweep did run", after_incremental > 0);

    ASSERT_EQ_FMTm("no sweep rode on the incremental report", after_incremental,
                   fake_ct_dumps(kernel), "%zu");

    firc_app_destroy(app);
    firc_ct_close(ct);
    fake_ct_stop(kernel);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    firc_loop_destroy(loop);
    PASS();
}

static size_t rule_count(firc_fake_ipt_t *f, const char *table, const char *chain) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    return firc_fake_ipt_get_rules(f, table, chain, &rules, &n) ? n : 0;
}

static size_t forward_jumps(firc_fake_ipt_t *f, const char *chain) {
    const char *jump[] = {"-j", chain};
    return count_rule(f, "filter", "FORWARD", jump, 2);
}

static firc_fakeip_t *new_pool(void) {
    firc_fakeip_cfg_t c = {0};
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
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    return firc_fakeip_new(&c, &pool) == FIRC_OK ? pool : NULL;
}

typedef struct {
    firc_config_t cfg;
    firc_fakeip_t *pool;
    firc_fake_ipt_t *fake, *fake6;
    firc_ipt_t *ipt, *ipt6;
    firc_app_t *app;
} pooled_t;

static bool pooled_up(pooled_t *p) {
    memset(p, 0, sizeof(*p));
    p->pool = new_pool();
    if (p->pool == NULL) { return false; }
    firc_config_init_defaults(&p->cfg);
    p->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(p->fake);
    p->ipt = firc_ipt_new(firc_fake_ipt_as_xt(p->fake), "FIRC_");
    p->fake6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    seed_foreign_rules(p->fake6);
    p->ipt6 = firc_ipt_new(firc_fake_ipt_as_xt(p->fake6), "FIRC_");
    firc_app_deps_t deps = {.cfg = &p->cfg, .ipt4 = p->ipt, .ipt6 = p->ipt6, .pool = p->pool};
    p->app = firc_app_create(&deps);
    return p->ipt != NULL && p->ipt6 != NULL && p->app != NULL && firc_app_refresh_pool_snapshot(p->app) == FIRC_OK;
}

static void pooled_down(pooled_t *p) {
    firc_app_destroy(p->app);
    firc_ipt_free(p->ipt);
    firc_ipt_free(p->ipt6);
    firc_fakeip_free(p->pool);
    firc_config_clear(&p->cfg);
}

static size_t writes_of(firc_fake_ipt_t *f, const char *table, size_t from) {
    char *order = firc_fake_xt_write_order(firc_fake_ipt_xt(f));
    size_t n = 0, len = strlen(table);
    for (const char *q = order + from; (q = strstr(q, table)) != NULL; q += len) {
        if ((q == order || q[-1] == '\n') && q[len] == '\n') { n++; }
    }
    free(order);
    return n;
}

static size_t order_len(firc_fake_ipt_t *f) {
    char *order = firc_fake_xt_write_order(firc_fake_ipt_xt(f));
    size_t n = strlen(order);
    free(order);
    return n;
}

/* Catches: a full pass writing a table twice (the stage 1 clean-then-refill window) or leaving one unwritten. */
TEST a_full_pass_is_one_write_per_table(void) {
    pooled_t p;
    ASSERT(pooled_up(&p));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(p.app, NULL, true));
    static const char *stray[] = {"-j", "RETURN"};
    const char *const *rules[1] = {stray};
    size_t lens[1] = {2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(p.fake, "filter", "FIRC_x", rules, lens, 1));
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(p.fake, "mangle", "FIRC_x", rules, lens, 1));
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(p.fake, "nat", "FIRC_x", rules, lens, 1));
    size_t from = order_len(p.fake);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(p.app, NULL, true));
    ASSERT_EQ_FMT((size_t)1, writes_of(p.fake, "filter", from), "%zu");
    ASSERT_EQ_FMT((size_t)1, writes_of(p.fake, "mangle", from), "%zu");
    ASSERT_EQ_FMT((size_t)1, writes_of(p.fake, "nat", from), "%zu");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(p.fake, "mangle", "FIRC_x"));
    pooled_down(&p);
    PASS();
}

/* Catches: a script's rule left above the pool barrier after a full pass (a full pass places our jumps afresh). */
TEST a_full_pass_puts_the_barrier_back_first(void) {
    pooled_t p;
    ASSERT(pooled_up(&p));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(p.app, NULL, true));
    static const char *script[] = {"-i", "br0", "-j", "ACCEPT"};
    static const char *barrier[] = {"-j", "FIRC_POOLREJECT"};
    const char *const *rules[2] = {script, barrier};
    size_t lens[2] = {4, 2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(p.fake, "filter", "FORWARD", rules, lens, 2));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(p.app, NULL, true));
    firc_ipt_rule_t *const *got = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(p.fake, "filter", "FORWARD", &got, &n));
    ASSERT(n >= 2);
    ASSERT_STR_EQ("FIRC_POOLREJECT", got[0]->parts[got[0]->n_parts - 1]);
    pooled_down(&p);
    PASS();
}

/* Catches: the stop leaving a chain of ours behind, or taking the barrier the next start relies on. */
TEST the_stop_keeps_only_the_barrier(void) {
    pooled_t p;
    ASSERT(pooled_up(&p));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(p.app, NULL, true));
    ASSERT(firc_fake_ipt_chain_exists(p.fake, "nat", "FIRC_DNAT"));
    firc_app_destroy(p.app);
    p.app = NULL;
    ASSERT(firc_fake_ipt_chain_exists(p.fake, "filter", "FIRC_POOLREJECT"));
    char *nat = firc_fake_ipt_print(p.fake, "nat"), *mangle = firc_fake_ipt_print(p.fake, "mangle");
    ASSERT(nat != NULL && strstr(nat, "FIRC_") == NULL);
    ASSERT(mangle != NULL && strstr(mangle, "FIRC_") == NULL);
    free(nat);
    free(mangle);
    pooled_down(&p);
    PASS();
}

static bool rule_is(const firc_ipt_rule_t *r, const char *const *want, size_t n) {
    if (r->n_parts != n) { return false; }
    for (size_t i = 0; i < n; i++) {
        if (strcmp(r->parts[i], want[i]) != 0) { return false; }
    }
    return true;
}

static bool rejects_then_fieldless_return_then_unmarked_drop(firc_fake_ipt_t *f) {
    static const char *const ret[] = {"-m", "connmark", "--mark", "0x40000000/0x40ff0000", "-j", "RETURN"};
    static const char *const drop[] = {"-m", "conntrack", "--ctdir", "ORIGINAL", "-m", "connmark", "--mark",
                                       "0x40000000/0x40000000", "-m", "mark", "!", "--mark", "0x40000000/0x40000000",
                                       "-j", "DROP"};
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, "filter", "FIRC_POOLREJECT", &rules, &n) || n != 4) { return false; }
    return strcmp(rules[0]->parts[rules[0]->n_parts - 3], "REJECT") == 0 &&
           strcmp(rules[1]->parts[rules[1]->n_parts - 3], "REJECT") == 0 && rule_is(rules[2], ret, 6) &&
           rule_is(rules[3], drop, 15);
}

/* Catches: the pool reject barrier missing from FORWARD, or behind the firmware's accepts. */
TEST a_pass_puts_the_pool_reject_barrier_first_in_forward(void) {
    pooled_t p;
    ASSERT(pooled_up(&p));
    firc_fake_ipt_t *fake = p.fake, *fake6 = p.fake6;
    firc_app_t *app = p.app;

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));

    firc_ipt_rule_t *const *fwd = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "FORWARD", &fwd, &n));
    ASSERT(n >= 2);
    ASSERT_STR_EQm("entered before anything the firmware accepts", "FIRC_POOLREJECT", fwd[0]->parts[1]);
    ASSERT_EQ_FMTm("one jump, however many passes", (size_t)1, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");
    static const char *foreign_fwd[] = {"-i", "eth0", "-j", "ACCEPT"};
    ASSERT(chain_has_rule(fake, "filter", "FORWARD", foreign_fwd, 4));
    static const char *tcp4[] = {"-d", "198.18.0.0/15", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    static const char *rest4[] = {"-d", "198.18.0.0/15", "-j", "REJECT", "--reject-with", "icmp-host-unreachable"};
    ASSERT(chain_has_rule(fake, "filter", "FIRC_POOLREJECT", tcp4, 8));
    ASSERT(chain_has_rule(fake, "filter", "FIRC_POOLREJECT", rest4, 6));
    ASSERT_EQ_FMT((size_t)4, rule_count(fake, "filter", "FIRC_POOLREJECT"), "%zu");
    ASSERTm("the rejects first, the drop last behind its return", rejects_then_fieldless_return_then_unmarked_drop(fake));
    static const char *tcp6[] = {"-d", "fd37:9a00::/48", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    static const char *rest6[] = {"-d", "fd37:9a00::/48", "-j", "REJECT", "--reject-with", "icmp6-addr-unreachable"};
    ASSERT(chain_has_rule(fake6, "filter", "FIRC_POOLREJECT", tcp6, 8));
    ASSERT(chain_has_rule(fake6, "filter", "FIRC_POOLREJECT", rest6, 6));
    ASSERT_EQ_FMT((size_t)4, rule_count(fake6, "filter", "FIRC_POOLREJECT"), "%zu");
    ASSERTm("in both families", rejects_then_fieldless_return_then_unmarked_drop(fake6));
    ASSERT_EQ_FMT((size_t)1, forward_jumps(fake6, "FIRC_POOLREJECT"), "%zu");

    firc_app_destroy(app);
    p.app = NULL;
    ASSERTm("a clean stop leaves the barrier, like the main-table routes",
            firc_fake_ipt_chain_exists(fake, "filter", "FIRC_POOLREJECT") && forward_jumps(fake, "FIRC_POOLREJECT") == 1);
    pooled_down(&p);
    PASS();
}

/* Catches: the start's clean given the pool writing filter without the barrier. */
TEST the_clean_with_the_pool_keeps_the_barrier(void) {
    firc_fakeip_t *pool = new_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    static const char *tcp[] = {"-d", "198.18.0.0/15", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    const char *const *rules[1] = {tcp};
    size_t lens[1] = {8};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FIRC_POOLREJECT", rules, lens, 1);
    static const char *jump[] = {"-j", "FIRC_POOLREJECT"};
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *fwd[2] = {jump, foreign};
    size_t fwd_lens[2] = {2, 4};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", fwd, fwd_lens, 2);
    seed_stale_chain(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);

    ASSERT_EQ(FIRC_OK, firc_netfilter_clean(ipt, NULL, pool));
    ASSERT_FALSEm("the stale chain went", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    ASSERTm("the barrier stayed", firc_fake_ipt_chain_exists(fake, "filter", "FIRC_POOLREJECT"));
    ASSERT_EQ_FMTm("and its jump", (size_t)1, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a purge leaving the barrier behind. */
TEST the_purge_takes_the_barrier_as_well(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    static const char *tcp[] = {"-d", "198.18.0.0/15", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"};
    const char *const *rules[1] = {tcp};
    size_t lens[1] = {8};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FIRC_POOLREJECT", rules, lens, 1);
    static const char *jump[] = {"-j", "FIRC_POOLREJECT"};
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *fwd[2] = {jump, foreign};
    size_t fwd_lens[2] = {2, 4};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", fwd, fwd_lens, 2);
    seed_stale_chain(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);

    ASSERT_EQ(FIRC_OK, firc_netfilter_clean(ipt, NULL, NULL));
    ASSERT_FALSEm("the stale chain went", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    ASSERT_FALSEm("and so did the barrier", firc_fake_ipt_chain_exists(fake, "filter", "FIRC_POOLREJECT"));
    ASSERT_EQ_FMTm("and its jump", (size_t)0, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");
    ASSERTm("the foreign FORWARD rule stayed", firc_fake_ipt_chain_exists(fake, "filter", "FORWARD"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a stopped daemon leaving its DNAT chain or the jump into it. */
TEST destroying_the_app_takes_the_dnat_chain_back(void) {
    firc_fakeip_cfg_t c = {0};
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
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);
    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(pool, "a.example.com", "g1", 1000, &fake4, NULL));
    const firc_ip_t real = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(pool, "a.example.com", "g1", &real, 1));
    ASSERT_EQ(FIRC_OK, firc_app_refresh_pool_snapshot(app));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(app, NULL));
    static const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_DNAT"));
    ASSERT(chain_has_rule(fake, "nat", "PREROUTING", jump, 4));

    firc_app_destroy(app);
    ASSERT_FALSEm("the chain is gone with the daemon", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_DNAT"));
    ASSERT_FALSEm("and the jump into it", chain_has_rule(fake, "nat", "PREROUTING", jump, 4));
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    ASSERTm("the firmware's rule next to it is untouched", chain_has_rule(fake, "nat", "PREROUTING", foreign, 4));
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: an incremental pass skipping a table that moved since its last write, so what another writer left in it stays. */
TEST an_incremental_pass_sweeps_a_table_moved_since_its_write(void) {
    fixture_t fx;
    fixture_up(&fx);
    seed_stale_chain(fx.fake);
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, false));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_old"));
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));

    fixture_down(&fx);
    PASS();
}

/* Catches: the DNS remap at start finding nat PREROUTING unregistered after the clean and the barrier used it up. */
TEST the_remap_enables_after_the_start_clean_and_the_barrier(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT_EQ(FIRC_OK, firc_netfilter_register_base_chains(ipt, NULL));
    ASSERT_EQ(FIRC_OK, firc_netfilter_clean(ipt, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "FORWARD"));
    firc_ip_t base = {{198, 18}, 4};
    ASSERT_EQ(FIRC_OK, firc_pool_reject_build_rules(ipt, "FIRC_", &base, 15));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    firc_remap_addr_t addr = {AF_INET, {192, 168, 1, 1}, 4};
    firc_port_remap_t *remap = firc_port_remap_new("FIRC_", 53, 3553, &addr, 1, ipt, NULL);
    ASSERT(remap != NULL);
    ASSERT_EQ_FMT(FIRC_OK, firc_port_remap_enable(remap), "%d");
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_DNSOR"));
    ASSERT(chain_has_rule(fake, "nat", "PREROUTING", k_remap_jump, 2));
    firc_port_remap_free(remap);
    firc_ipt_free(ipt);
    PASS();
}

TEST port_remap_uses_the_configured_chain_prefix(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "XX_");
    firc_netfilter_register_base_chains(ipt, NULL);

    firc_port_remap_t *remap = firc_port_remap_new("XX_", 53, 3553, NULL, 0, ipt, NULL);
    ASSERT(remap != NULL);
    ASSERT_EQ(FIRC_OK, firc_port_remap_enable(remap));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "XX_DNSOR"));
    static const char *const jump[] = {"-j", "XX_DNSOR"};
    ASSERT(chain_has_rule(fake, "nat", "PREROUTING", jump, 2));

    ASSERT_EQ(FIRC_OK, firc_port_remap_disable(remap));
    firc_port_remap_free(remap);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: an incremental pass with nothing new reading nat, or a full pass not reading it. */
TEST a_full_pass_reads_every_table_again(void) {
    fixture_t fx;
    fixture_up(&fx);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, true));
    size_t reads = firc_fake_xt_reads(firc_fake_ipt_xt(fx.fake));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, false));
    ASSERT_EQ_FMTm("an incremental pass with nothing new reads nothing", reads,
                   firc_fake_xt_reads(firc_fake_ipt_xt(fx.fake)), "%zu");
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, true));
    ASSERT_GT(firc_fake_xt_reads(firc_fake_ipt_xt(fx.fake)), reads);
    fixture_down(&fx);
    PASS();
}

/* Catches: an incremental pass trusting its last write of a nat the firmware rewrote unheard, or a full pass then writing the jump twice. */
TEST a_pass_after_the_firmware_rewrote_nat_writes_it_back(void) {
    fixture_t fx;
    fixture_up(&fx);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, true));
    ASSERT(chain_has_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2));

    static const char *pre[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *rules[1] = {pre};
    size_t lens[1] = {4};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fx.fake, "nat", "PREROUTING", rules, lens, 1));
    ASSERT_FALSE(chain_has_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, false));
    ASSERT(chain_has_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2));

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(fx.app, NULL, true));
    ASSERT_EQ_FMT((size_t)1, count_rule(fx.fake, "nat", "PREROUTING", k_remap_jump, 2), "%zu");
    ASSERT(firc_fake_ipt_chain_exists(fx.fake, "nat", "FIRC_DNSOR"));
    fixture_down(&fx);
    PASS();
}

/* Catches: a full pass skipping filter as last written although the firmware's rewrite took the barrier's jump away. */
TEST a_full_pass_after_the_firmware_rewrote_filter_puts_the_barrier_back(void) {
    firc_fakeip_cfg_t c = {0};
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
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_app_deps_t deps = {.cfg = &cfg, .ipt4 = ipt, .pool = pool};
    firc_app_t *app = firc_app_create(&deps);

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(app, NULL, true));
    ASSERT_EQ_FMT((size_t)1, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");
    static const char *foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *fwd[1] = {foreign};
    size_t fwd_lens[1] = {4};
    firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", fwd, fwd_lens, 1);
    ASSERT_EQ_FMT((size_t)0, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");

    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(app, NULL, true));
    ASSERT_EQ_FMT((size_t)1, forward_jumps(fake, "FIRC_POOLREJECT"), "%zu");

    firc_app_destroy(app);
    firc_ipt_free(ipt);
    firc_config_clear(&cfg);
    firc_fakeip_free(pool);
    PASS();
}

static void seed_stale_mark(firc_fake_ipt_t *f) {
    static const char *mark[] = {"-d", "198.18.0.0/24", "-j", "MARK", "--set-xmark", "0x10000/0xff0000"};
    const char *const *rules[1] = {mark};
    size_t lens[1] = {6};
    firc_fake_ipt_set_initial_rules(f, "mangle", "FIRC_gone", rules, lens, 1);
    static const char *jump[] = {"-j", "FIRC_gone"};
    static const char *foreign[] = {"-i", "eth0", "-j", "MARK", "--set-xmark", "0x7/0xffffffff"};
    const char *const *pre[2] = {foreign, jump};
    size_t pre_lens[2] = {6, 2};
    firc_fake_ipt_set_initial_rules(f, "mangle", "PREROUTING", pre, pre_lens, 2);
}

static const char *const k_gone_jump[] = {"-j", "FIRC_gone"};

/* Catches: a refused nat sweep after the marks went, so a fake address is rewritten and leaves unmarked. */
TEST a_refused_nat_sweep_leaves_the_marks(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    seed_stale_mark(fake);
    seed_stale_chain(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fake_xt_fail_next_replace(firc_fake_ipt_xt(fake), EINVAL);

    ASSERT(firc_netfilter_clean(ipt, NULL, NULL) != FIRC_OK);
    ASSERTm("the nat chain is still there", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    ASSERTm("so the mark stayed", firc_fake_ipt_chain_exists(fake, "mangle", "FIRC_gone"));
    ASSERTm("and the jump into it", chain_has_rule(fake, "mangle", "PREROUTING", k_gone_jump, 2));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: the start's clean giving up on one lost race, so fircd exits with a killed instance's rules in place. */
TEST the_start_clean_retries_a_lost_race(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    seed_stale_mark(fake);
    seed_stale_chain(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fake_xt_fail_next_replace(firc_fake_ipt_xt(fake), EAGAIN);

    ASSERT_EQ(FIRC_OK, firc_netfilter_clean_retrying(ipt, NULL, NULL));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", "FIRC_gone"));
    ASSERT_FALSE(chain_has_rule(fake, "mangle", "PREROUTING", k_gone_jump, 2));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a refusal retried as if it were a lost race. */
TEST the_start_clean_does_not_retry_a_refusal(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(fake);
    seed_stale_chain(fake);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    firc_netfilter_register_base_chains(ipt, NULL);
    firc_fake_xt_fail_next_replace(firc_fake_ipt_xt(fake), EINVAL);

    ASSERT(firc_netfilter_clean_retrying(ipt, NULL, NULL) != FIRC_OK);
    ASSERTm("one refused write, no second", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    firc_ipt_free(ipt);
    PASS();
}

typedef struct {
    firc_config_t cfg;
    firc_fakeip_t *pool;
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    firc_app_t *app;
    firc_port_remap_t *remap;
    uint16_t ports[FIRC_KTCP_DEVICES];
} tun_rig_t;

static bool tun_rig_up_lacking(tun_rig_t *r, bool target, const char *lack, uint8_t rev) {
    memset(r, 0, sizeof(*r));
    r->pool = new_pool();
    if (r->pool == NULL) { return false; }
    firc_config_init_defaults(&r->cfg);
    r->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    seed_foreign_rules(r->fake);
    if (lack != NULL) { firc_fake_xt_lack(firc_fake_ipt_xt(r->fake), target, lack, rev); }
    firc_xt_t *xt = firc_fake_ipt_as_xt(r->fake);
    (void)firc_xt_probe(xt);
    r->ipt = firc_ipt_new(xt, "FIRC_");
    firc_netfilter_register_base_chains(r->ipt, NULL);
    r->kernel = fake_rtnl_start(&r->rtnl);
    if (r->kernel == NULL) { return false; }
    fake_rtnl_set_link_flags(r->kernel, 0x1 | 0x10);
    firc_app_deps_t deps = {.cfg = &r->cfg, .ipt4 = r->ipt, .rtnl = r->rtnl, .pool = r->pool};
    r->app = firc_app_create(&deps);
    r->remap = firc_port_remap_new(r->cfg.app.netfilter.iptables.chain_prefix, 53, 3553, NULL, 0, r->ipt, NULL);
    if (r->app == NULL || firc_port_remap_enable(r->remap) != FIRC_OK) { return false; }
    firc_app_set_port_remap(r->app, r->remap);
    firc_app_set_running(r->app, true);
    return true;
}

static bool tun_rig_up(tun_rig_t *r) { return tun_rig_up_lacking(r, false, NULL, 0); }

static void tun_rig_down(tun_rig_t *r) {
    firc_app_destroy(r->app);
    firc_port_remap_free(r->remap);
    firc_rtnl_close(r->rtnl);
    fake_rtnl_stop(r->kernel);
    firc_ipt_free(r->ipt);
    firc_fakeip_free(r->pool);
    firc_config_clear(&r->cfg);
}

static firc_id_t tag_id(uint8_t tag) { return (firc_id_t){{tag, tag, tag, tag}}; }

static firc_rule_t *a_rule(const char *type, const char *text) {
    firc_rule_t *rule = firc_rule_new();
    rule->id = (firc_id_t){{0xee, 0, 0, 0}};
    rule->id.b[1] = (uint8_t)strlen(text);
    rule->id.b[2] = (uint8_t)text[0];
    rule->id.b[3] = (uint8_t)type[0];
    rule->type = strdup(type);
    rule->rule = strdup(text);
    rule->enable = true;
    return rule;
}

static bool add_tun_group(tun_rig_t *r, uint8_t tag, const char *iface, const char *name, const char *subnet,
                          firc_ip_t *fake) {
    firc_group_t *g = firc_group_new();
    g->id = tag_id(tag);
    g->name = strdup("g");
    g->iface = strdup(iface);
    g->enable = true;
    firc_group_add_rule(g, a_rule(FIRC_RULE_DOMAIN, name));
    if (subnet != NULL) { firc_group_add_rule(g, a_rule(FIRC_RULE_SUBNET, subnet)); }
    if (firc_app_add_group(r->app, g) != FIRC_OK) { return false; }
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(tag_id(tag), gid);
    const firc_ip_t real = {{93, 184, 216, tag}, 4};
    return firc_fakeip_get(r->pool, name, gid, (int64_t)time(NULL), fake, NULL) == FIRC_OK &&
           firc_fakeip_set_reals(r->pool, name, gid, &real, 1) == FIRC_OK &&
           firc_app_refresh_pool_snapshot(r->app) == FIRC_OK;
}

static void set_port(tun_rig_t *r, int dev, uint16_t port) {
    r->ports[dev] = port;
    firc_app_set_ktcp_ports(r->app, r->ports);
}

static size_t redirects_of(tun_rig_t *r, uint8_t tag, uint16_t port) {
    uint32_t field = firc_ruleset_mark_field(firc_app_find_group_by_id(r->app, tag_id(tag)));
    if (field == 0) { return 0; }
    char mark[32], to[8];
    snprintf(mark, sizeof(mark), "0x%x/0x40ff0000", 0x40000000u | field);
    snprintf(to, sizeof(to), "%u", (unsigned)port);
    const char *want[] = {"-p", "tcp", "-m", "mark", "--mark", mark, "-j", "REDIRECT", "--to-ports", to};
    return count_rule(r->fake, "nat", "FIRC_REDIR", want, 10);
}

static const char *const k_redir_jump[] = {"-p", "tcp", "-m", "mark", "--mark", "0x40000000/0x40000000", "-m",
                                           "addrtype", "!", "--dst-type", "LOCAL", "-j", "FIRC_REDIR"};

static size_t redir_jumps(tun_rig_t *r) { return count_rule(r->fake, "nat", "PREROUTING", k_redir_jump, 13); }

static bool dnat_of(tun_rig_t *r, const firc_ip_t *fake) {
    char want[32];
    snprintf(want, sizeof(want), "-d %u.%u.%u.%u/32", fake->b[0], fake->b[1], fake->b[2], fake->b[3]);
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    bool found = false;
    if (!firc_fake_ipt_get_rules(r->fake, "nat", "FIRC_DNAT", &rules, &n)) { return false; }
    for (size_t i = 0; i < n && !found; i++) {
        char *text = firc_ipt_rule_string(rules[i]);
        found = text != NULL && strstr(text, want) != NULL;
        free(text);
    }
    return found;
}

static size_t said_since(uint64_t since, const char *needle) {
    static firc_event_t ev[256];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(since, ev, sizeof(ev) / sizeof(ev[0]), &next, &dropped), c = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && strstr(ev[i].u.log.text, needle) != NULL) { c++; }
    }
    return c;
}

static uint64_t said_mark(void) {
    static firc_event_t ev[256];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, sizeof(ev) / sizeof(ev[0]), &next, &dropped);
    return n > 0 ? ev[n - 1].seq : 0;
}

static size_t index_of_jump(tun_rig_t *r, const char *target) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(r->fake, "nat", "PREROUTING", &rules, &n)) { return SIZE_MAX; }
    for (size_t i = 0; i < n; i++) {
        if (rules[i]->n_parts >= 2 && strcmp(rules[i]->parts[rules[i]->n_parts - 1], target) == 0) { return i; }
    }
    return SIZE_MAX;
}

/* Catches: a tunnel group with a reported port left without its REDIRECT, or one sent to another port or mark. */
TEST a_tunnel_group_with_a_port_gets_its_redirect(void) {
    tun_rig_t r;
    firc_ip_t f1 = {{0}, 0}, f2 = {{0}, 0}, f3 = {{0}, 0};
    ASSERT(tun_rig_up(&r));
    ASSERT(add_tun_group(&r, 1, "tunvless3", "a.example", NULL, &f1));
    ASSERT(add_tun_group(&r, 2, "tunvless4", "b.example", NULL, &f2));
    ASSERT(add_tun_group(&r, 3, "lo", "c.example", NULL, &f3));
    set_port(&r, 3, 3603);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(r.app, NULL));
    ASSERT_EQ_FMT((size_t)1, rule_count(r.fake, "nat", "FIRC_REDIR"), "%zu");
    ASSERT_EQ_FMT((size_t)1, redirects_of(&r, 1, 3603), "%zu");
    ASSERT_EQ_FMT((size_t)1, redir_jumps(&r), "%zu");
    ASSERT(dnat_of(&r, &f1) && dnat_of(&r, &f2) && dnat_of(&r, &f3));
    tun_rig_down(&r);
    PASS();
}

/* Catches: TCP blackholed while the port is unknown: a REDIRECT staged with no port, or the DNAT dropped. */
TEST no_port_no_redirect_and_dnat_stays(void) {
    tun_rig_t r;
    firc_ip_t f1 = {{0}, 0};
    ASSERT(tun_rig_up(&r));
    ASSERT(add_tun_group(&r, 1, "tunvless3", "a.example", NULL, &f1));
    set_port(&r, 4, 3604);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(r.app, NULL));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));
    ASSERT_EQ_FMT((size_t)0, redir_jumps(&r), "%zu");
    ASSERT(dnat_of(&r, &f1));
    set_port(&r, 3, 3603);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(r.app, NULL, false));
    ASSERT_EQ_FMT((size_t)1, redirects_of(&r, 1, 3603), "%zu");
    set_port(&r, 3, 0);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(r.app, NULL, false));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));
    ASSERT(dnat_of(&r, &f1));
    tun_rig_down(&r);
    PASS();
}

/* Catches: REDIR staged for a group the kernel refused, or the image of a refused try kept. */
TEST a_left_out_group_gets_no_redirect(void) {
    tun_rig_t r;
    firc_ip_t f1 = {{0}, 0}, f2 = {{0}, 0};
    ASSERT(tun_rig_up(&r));
    ASSERT(add_tun_group(&r, 1, "tunvless3", "a.example", NULL, &f1));
    ASSERT(add_tun_group(&r, 2, "tunvless4", "b.example", "10.66.0.0/16", &f2));
    set_port(&r, 3, 3603);
    set_port(&r, 4, 3604);
    firc_fake_ipt_refuse_rules_containing(r.fake, "10.66.0.0/16");
    ASSERT_EQ(FIRC_ERR_IO, firc_app_rebuild_netfilter_kind(r.app, NULL, false));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(r.app, NULL, false));
    ASSERT_EQ_FMT((size_t)1, rule_count(r.fake, "nat", "FIRC_REDIR"), "%zu");
    ASSERT_EQ_FMT((size_t)1, redirects_of(&r, 1, 3603), "%zu");
    const firc_ktcp_image_t *im = firc_app_ktcp_image(r.app);
    ASSERT_EQ_FMT((size_t)1, im->n, "%zu");
    ASSERT_EQ(3, im->v[0].dev);
    ASSERT_MEM_EQ(f1.b, im->v[0].fake, 4);
    tun_rig_down(&r);
    PASS();
}

/* Catches: a kernel refusing the REDIRECT rules failing every pass for every group, or the error said every pass. */
TEST a_refused_redirect_keeps_nat_written(void) {
    firc_event_reset_for_test();
    tun_rig_t r;
    firc_ip_t f1 = {{0}, 0}, f2 = {{0}, 0};
    ASSERT(tun_rig_up(&r));
    ASSERT(add_tun_group(&r, 1, "tunvless3", "a.example", NULL, &f1));
    ASSERT(add_tun_group(&r, 2, "tunvless4", "b.example", NULL, &f2));
    set_port(&r, 3, 3603);
    set_port(&r, 4, 3604);
    firc_fake_ipt_refuse_rules_containing(r.fake, "-j REDIRECT");
    uint64_t mark = said_mark();
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(r.app, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter_kind(r.app, NULL, false));
    ASSERT(dnat_of(&r, &f1) && dnat_of(&r, &f2));
    ASSERT(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_DNSOR"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));
    ASSERT_EQ_FMT((size_t)0, redir_jumps(&r), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_app_ktcp_image(r.app)->n, "%zu");
    ASSERT_EQ_FMT((size_t)1, said_since(mark, "the kernel refused the kernel TCP redirect; TCP stays on the TUN"), "%zu");
    tun_rig_down(&r);
    PASS();
}

static enum greatest_test_res missing_extension_keeps_nat(bool target, const char *name, uint8_t rev) {
    firc_event_reset_for_test();
    tun_rig_t r;
    firc_ip_t f1 = {{0}, 0};
    ASSERT(tun_rig_up_lacking(&r, target, name, rev));
    ASSERT(add_tun_group(&r, 1, "tunvless3", "a.example", NULL, &f1));
    set_port(&r, 3, 3603);
    uint64_t mark = said_mark();
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(r.app, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(r.app, NULL));
    ASSERT(dnat_of(&r, &f1));
    ASSERT(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_DNSOR"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));
    ASSERT_EQ_FMT((size_t)0, redir_jumps(&r), "%zu");
    ASSERT_EQ_FMT((size_t)1,
                  said_since(mark, "kernel TCP needs the REDIRECT target and the addrtype match; TCP stays on the TUN"),
                  "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_app_ktcp_image(r.app)->n, "%zu");
    tun_rig_down(&r);
    PASS();
}

/* Catches: nat failing every pass on a kernel without the REDIRECT target, or the error said every pass. */
TEST a_missing_redirect_target_keeps_nat_written(void) { return missing_extension_keeps_nat(true, "REDIRECT", 0); }

/* Catches: nat failing every pass on a kernel without the addrtype match. */
TEST a_missing_addrtype_match_keeps_nat_written(void) { return missing_extension_keeps_nat(false, "addrtype", 1); }

/* Catches: a rewritten nat left without DNSOR, REDIR or their jumps, a jump put back twice, or REDIR behind DNAT. */
TEST rebuild_restores_the_table_after_a_wipe(void) {
    tun_rig_t r;
    firc_ip_t f1 = {{0}, 0};
    ASSERT(tun_rig_up(&r));
    ASSERT(add_tun_group(&r, 1, "tunvless3", "a.example", NULL, &f1));
    set_port(&r, 3, 3603);
    ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(r.app, NULL));
    ASSERT(chain_has_rule(r.fake, "nat", "PREROUTING", k_remap_jump, 2));
    ASSERT_EQ_FMT((size_t)1, redir_jumps(&r), "%zu");

    firc_fake_ipt_reset(r.fake);
    seed_foreign_rules(r.fake);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_DNSOR"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));

    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(FIRC_OK, firc_app_rebuild_netfilter(r.app, NULL));
        ASSERT(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_DNSOR"));
        ASSERT_EQ_FMT((size_t)1, count_rule(r.fake, "nat", "PREROUTING", k_remap_jump, 2), "%zu");
        ASSERT_EQ_FMT((size_t)1, redirects_of(&r, 1, 3603), "%zu");
        ASSERT_EQ_FMT((size_t)1, redir_jumps(&r), "%zu");
        size_t redir_at = index_of_jump(&r, "FIRC_REDIR"), dnat_at = index_of_jump(&r, "FIRC_DNAT");
        ASSERT(dnat_at != SIZE_MAX);
        ASSERT_LT(redir_at, dnat_at);
    }
    tun_rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(rebuild_restores_the_table_after_a_wipe);
    RUN_TEST(rebuild_does_not_duplicate_jumps);
    RUN_TEST(rebuild_drops_chains_left_by_a_previous_run);
    RUN_TEST(rebuild_keeps_other_writers_rules);
    RUN_TEST(rebuild_aborts_on_a_raised_cancel);
    RUN_TEST(a_pass_writes_the_dnat_chain_and_commits_the_pool);
    RUN_TEST(an_incremental_pass_sweeps_a_table_moved_since_its_write);
    RUN_TEST(port_remap_uses_the_configured_chain_prefix);
    RUN_TEST(the_remap_enables_after_the_start_clean_and_the_barrier);
    RUN_TEST(destroying_the_app_takes_the_dnat_chain_back);
    RUN_TEST(a_pass_puts_the_pool_reject_barrier_first_in_forward);
    RUN_TEST(a_full_pass_is_one_write_per_table);
    RUN_TEST(a_full_pass_puts_the_barrier_back_first);
    RUN_TEST(the_stop_keeps_only_the_barrier);
    RUN_TEST(the_clean_with_the_pool_keeps_the_barrier);
    RUN_TEST(the_purge_takes_the_barrier_as_well);
    RUN_TEST(a_full_pass_clears_the_flows_of_the_window_it_opened);
    RUN_TEST(an_incremental_pass_opens_no_window_and_clears_nothing);
    RUN_TEST(the_sweep_also_happens_when_the_pass_is_reported_through_the_loop);
    RUN_TEST(a_full_pass_reads_every_table_again);
    RUN_TEST(a_pass_after_the_firmware_rewrote_nat_writes_it_back);
    RUN_TEST(a_full_pass_after_the_firmware_rewrote_filter_puts_the_barrier_back);
    RUN_TEST(a_sweep_that_could_not_finish_waits_for_the_next_full_pass);
    RUN_TEST(an_incremental_pass_reported_through_the_loop_clears_nothing);
    RUN_TEST(a_refused_nat_sweep_leaves_the_marks);
    RUN_TEST(the_start_clean_retries_a_lost_race);
    RUN_TEST(the_start_clean_does_not_retry_a_refusal);
    RUN_TEST(a_tunnel_group_with_a_port_gets_its_redirect);
    RUN_TEST(no_port_no_redirect_and_dnat_stays);
    RUN_TEST(a_left_out_group_gets_no_redirect);
    RUN_TEST(a_missing_redirect_target_keeps_nat_written);
    RUN_TEST(a_refused_redirect_keeps_nat_written);
    RUN_TEST(a_missing_addrtype_match_keeps_nat_written);
    GREATEST_MAIN_END();
}

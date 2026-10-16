#include "greatest.h"

#include <string.h>

#include "fake_iptables.h"
#include "firc/netfilter_cleaner.h"
#include "firc/redir.h"

typedef struct {
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
} rig_t;

static const char *const k_foreign[] = {"-i", "eth0", "-j", "ACCEPT"};
static const char *const k_jump[] = {"-p", "tcp", "-m", "mark", "--mark", "0x40000000/0x40000000", "-m", "addrtype",
                                     "!", "--dst-type", "LOCAL", "-j", "FIRC_REDIR"};
static const firc_redir_group_t k_two[] = {{0x40050000u, 3603}, {0x40060000u, 3600}};

static bool rig_up(rig_t *r) {
    r->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *const *rules[1] = {k_foreign};
    size_t lens[1] = {4};
    firc_fake_ipt_set_initial_rules(r->fake, "nat", "PREROUTING", rules, lens, 1);
    r->ipt = firc_ipt_new(firc_fake_ipt_as_xt(r->fake), "FIRC_");
    return r->ipt != NULL;
}

static void rig_down(rig_t *r) {
    firc_ipt_free(r->ipt);
}

static firc_err_t write_groups(rig_t *r, const firc_redir_group_t *g, size_t n) {
    firc_err_t err = firc_netfilter_register_base_chains(r->ipt, NULL);
    if (err == FIRC_OK) { err = firc_redir_build_rules(r->ipt, "FIRC_", g, n); }
    if (err != FIRC_OK) {
        firc_ipt_discard(r->ipt);
        return err;
    }
    return firc_ipt_commit(r->ipt);
}

static bool parts_are(const firc_ipt_rule_t *rule, const char *const *want, size_t n) {
    if (rule->n_parts != n) { return false; }
    for (size_t i = 0; i < n; i++) {
        if (strcmp(rule->parts[i], want[i]) != 0) { return false; }
    }
    return true;
}

static size_t jumps_in(rig_t *r) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0, found = 0;
    if (!firc_fake_ipt_get_rules(r->fake, "nat", "PREROUTING", &rules, &n)) { return 0; }
    for (size_t i = 0; i < n; i++) { found += parts_are(rules[i], k_jump, 13) ? 1u : 0u; }
    return found;
}

/* Catches: a group's REDIRECT lost, merged, sent to another port, or matched on the wrong mark. */
TEST redir_holds_one_redirect_per_group(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT_EQ(FIRC_OK, write_groups(&r, k_two, 2));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(r.fake, "nat", "FIRC_REDIR", &rules, &n));
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    static const char *const first[] = {"-p", "tcp", "-m", "mark", "--mark", "0x40050000/0x40ff0000",
                                        "-j", "REDIRECT", "--to-ports", "3603"};
    static const char *const second[] = {"-p", "tcp", "-m", "mark", "--mark", "0x40060000/0x40ff0000",
                                         "-j", "REDIRECT", "--to-ports", "3600"};
    ASSERT(parts_are(rules[0], first, 10));
    ASSERT(parts_are(rules[1], second, 10));
    rig_down(&r);
    PASS();
}

/* Catches: an empty chain left behind, or a jump into it, when no group has a REDIRECT. */
TEST no_group_stages_no_chain(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT_EQ(FIRC_OK, write_groups(&r, NULL, 0));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));
    ASSERT_EQ(FIRC_OK, write_groups(&r, k_two, 2));
    ASSERT(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));
    ASSERT_EQ(FIRC_OK, write_groups(&r, k_two, 0));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(r.fake, "nat", "FIRC_REDIR"));
    ASSERT_EQ_FMT((size_t)0, jumps_in(&r), "%zu");
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(r.fake, "nat", "PREROUTING", &rules, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    rig_down(&r);
    PASS();
}

/* Catches: the jump appended behind other rules, or taking UDP and other protocols too. */
TEST the_jump_is_inserted_at_1_and_tcp_only(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT_EQ(FIRC_OK, write_groups(&r, k_two, 2));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(r.fake, "nat", "PREROUTING", &rules, &n));
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT(rules[0]->n_parts > 2);
    ASSERT_STR_EQ("-p", rules[0]->parts[0]);
    ASSERT_STR_EQ("tcp", rules[0]->parts[1]);
    ASSERT_STR_EQ("FIRC_REDIR", rules[0]->parts[rules[0]->n_parts - 1]);
    ASSERT(parts_are(rules[1], k_foreign, 4));
    rig_down(&r);
    PASS();
}

/* Catches: the router's own addresses redirected to tunvless, or the invert lost. */
TEST the_jump_excludes_local_destinations(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    ASSERT_EQ(FIRC_OK, write_groups(&r, k_two, 2));
    ASSERT_EQ_FMT((size_t)1, jumps_in(&r), "%zu");
    rig_down(&r);
    PASS();
}

/* Catches: a REDIRECT staged on an IPv6 engine, whose tunnel path cannot dial. */
TEST a_v6_engine_is_refused(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);
    ASSERT_EQ(FIRC_ERR_INVAL, firc_redir_build_rules(ipt, "FIRC_", k_two, 2));
    firc_ipt_free(ipt);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(redir_holds_one_redirect_per_group);
    RUN_TEST(no_group_stages_no_chain);
    RUN_TEST(the_jump_is_inserted_at_1_and_tcp_only);
    RUN_TEST(the_jump_excludes_local_destinations);
    RUN_TEST(a_v6_engine_is_refused);
    GREATEST_MAIN_END();
}

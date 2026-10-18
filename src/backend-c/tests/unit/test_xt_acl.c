#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake_xtables.h"
#include "firc/xtables.h"
#include "xt_golden.h"
#include "../../src/xtables/xt_internal.h"

typedef struct {
    const char *chain;
    const char *const *lines;
    size_t n;
} seed_t;

static firc_fake_xt_t *filter_with(const seed_t *s, size_t n) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV4);
    for (size_t i = 0; i < n; i++) {
        firc_test_stage_t *st = firc_test_stage_new();
        firc_test_stage_override(st, s[i].chain, s[i].lines, s[i].n);
        firc_xt_t *xt = firc_fake_xt_handle(f);
        firc_err_t err = firc_xt_commit(xt, "filter", &st->stage, NULL);
        firc_xt_free(xt);
        firc_test_stage_free(st);
        if (err != FIRC_OK) { abort(); }
    }
    return f;
}

static firc_err_t read_acl(firc_fake_xt_t *f, firc_xt_acl_t *out) {
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_err_t err = firc_xt_acl_denying(xt, "filter", "_NDM_ACL_IN", "_NDM_ACL_OUT", out);
    firc_xt_free(xt);
    return err;
}

static const char *const k_bridge0[] = {"-s 192.168.1.5/32 -j ACCEPT", "-d 192.168.1.0/24 -j ACCEPT", "-j RETURN"};
static const char *const k_pppoe0[] = {"-d 203.0.113.9/32 -j DROP"};
static const char *const k_guest[] = {"-p tcp -j REJECT --reject-with icmp-host-unreachable"};
static const char *const k_marks[] = {"-j MARK --set-xmark 0xfffffffe/0xffffffff"};
static const char *const k_deeper[] = {"-j ACCEPT"};
static const char *const k_onward[] = {"-s 10.0.0.0/8 -j ACCEPT", "-j @Deeper"};

/* Catches: an ACCEPT-only list taken for a deny, so a segment with the usual @Bridge0 shape loses the redirect. */
TEST an_accept_only_list_denies_nothing(void) {
    static const char *const acl[] = {"-i br0 -j @Bridge0", "-i br9 -j ACCEPT", "-i br8 -j RETURN"};
    const seed_t s[] = {{"@Bridge0", k_bridge0, 3}, {"_NDM_ACL_IN", acl, 3}};
    firc_fake_xt_t *f = filter_with(s, 2);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)0, out.n, "%zu");
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a DROP or REJECT in the jumped chain, or a DROP right in _NDM_ACL_IN, not judged a deny. */
TEST drop_and_reject_deny_in_rule_order(void) {
    static const char *const acl[] = {"-i ppp0 -j @PPPoE0", "-i br0 -j @Bridge0", "-i br1 -j @Guest",
                                      "-i nwg3 -j DROP"};
    const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"@Bridge0", k_bridge0, 3}, {"@Guest", k_guest, 1},
                        {"_NDM_ACL_IN", acl, 4}};
    firc_fake_xt_t *f = filter_with(s, 4);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)3, out.n, "%zu");
    ASSERT_STR_EQ("ppp0", out.iface[0]);
    ASSERT_STR_EQ("br1", out.iface[1]);
    ASSERT_STR_EQ("nwg3", out.iface[2]);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a listed name carrying old bytes after its NUL, so two equal readings differ byte for byte. */
TEST a_listed_name_is_zero_after_its_nul(void) {
    static const char *const acl[] = {"-i ppp0 -j DROP", "-i br1 -j DROP"};
    const seed_t s[] = {{"_NDM_ACL_IN", acl, 2}};
    firc_fake_xt_t *f = filter_with(s, 1);
    firc_xt_acl_t out;
    memset(&out, 0xff, sizeof(out));
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)2, out.n, "%zu");
    const char ppp0[16] = "ppp0", br1[16] = "br1";
    ASSERT_MEM_EQ(ppp0, out.iface[0], sizeof(ppp0));
    ASSERT_MEM_EQ(br1, out.iface[1], sizeof(br1));
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a chain with a MARK (its mark read as the ACCEPT verdict), or one jumping onward to an ACCEPT-only chain, followed instead of judged a deny. */
TEST a_chain_with_any_other_target_or_a_jump_denies(void) {
    static const char *const acl[] = {"-i nwg2 -j @Marks", "-i opkgtun0 -j @Onward"};
    const seed_t s[] = {{"@Marks", k_marks, 1}, {"@Deeper", k_deeper, 1}, {"@Onward", k_onward, 2},
                        {"_NDM_ACL_IN", acl, 2}};
    firc_fake_xt_t *f = filter_with(s, 4);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)2, out.n, "%zu");
    ASSERT_STR_EQ("nwg2", out.iface[0]);
    ASSERT_STR_EQ("opkgtun0", out.iface[1]);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a repeated interface listed twice, a 15-byte name cut, or a permitting jump without -i or with ! -i raising all. */
TEST names_listed_once_and_permitting_shapes_leave_all_clear(void) {
    static const char *const acl[] = {"-j @Bridge0", "! -i br3 -j @Bridge0", "-i wireguard123456 -j @PPPoE0",
                                      "-i wireguard123456 -j @Guest"};
    const seed_t s[] = {{"@Bridge0", k_bridge0, 3}, {"@PPPoE0", k_pppoe0, 1}, {"@Guest", k_guest, 1},
                        {"_NDM_ACL_IN", acl, 4}};
    firc_fake_xt_t *f = filter_with(s, 4);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQ("wireguard123456", out.iface[0]);
    ASSERT_FALSE(out.all);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a denying jump without -i, or with ! -i, skipped (fail-open: it covers every segment) instead of raising all. */
TEST no_iface_inverted_or_wildcard_deny_sets_all(void) {
    static const char *const noif[] = {"-j @PPPoE0"};
    static const char *const inv[] = {"! -i br3 -j @PPPoE0"};
    const char *const *cases[] = {noif, inv};
    for (int k = 0; k < 2; k++) {
        const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"_NDM_ACL_IN", cases[k], 1}};
        firc_fake_xt_t *f = filter_with(s, 2);
        firc_xt_acl_t out;
        ASSERT_EQ(FIRC_OK, read_acl(f, &out));
        ASSERT(out.all);
        ASSERT_EQ_FMT((size_t)0, out.n, "%zu");
        firc_fake_xt_free(f);
    }
    PASS();
}

/* Catches: a wildcard -i (mask of strlen bytes, no NUL byte) read as an exact interface, or a denying wildcard not raising all. */
TEST a_wildcard_deny_sets_all(void) {
    static const char *const acl[] = {"-i ppp0 -j @PPPoE0"};
    const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"_NDM_ACL_IN", acl, 1}};
    firc_fake_xt_t *f = filter_with(s, 2);
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_fake_xt_blob(f, "filter", &info, &blob));
    firc_xt_table_t t;
    const char *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why));
    firc_xt_chain_t *c = firc_xt_find_chain(&t, "_NDM_ACL_IN");
    ASSERT(c != NULL && c->n_rules == 1);
    xt_ipt_entry_t *e = (xt_ipt_entry_t *)c->rules[0].bytes;
    e->ip.iniface[3] = '\0';
    e->ip.iniface_mask[3] = 0;
    e->ip.iniface_mask[4] = 0;
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, firc_xt_acl_judge(&t, "_NDM_ACL_IN", "_NDM_ACL_OUT", &out));
    ASSERT_EQ_FMT((size_t)0, out.n, "%zu");
    ASSERT(out.all);
    firc_xt_table_clear(&t);
    free(blob);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a jump to a built-in or a missing chain followed as if it were a user chain of permits. */
TEST a_jump_that_cannot_be_judged_denies(void) {
    static const char *const acl[] = {"-i ppp0 -j @Deeper"};
    const seed_t s[] = {{"@Deeper", k_deeper, 1}, {"_NDM_ACL_IN", acl, 1}};
    firc_fake_xt_t *f = filter_with(s, 2);
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_fake_xt_blob(f, "filter", &info, &blob));
    const char *const targets[] = {"INPUT", "@Gone"};
    for (int k = 0; k < 2; k++) {
        firc_xt_table_t t;
        const char *why = NULL;
        ASSERT_EQ(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why));
        firc_xt_chain_t *c = firc_xt_find_chain(&t, "_NDM_ACL_IN");
        ASSERT(c != NULL && c->n_rules == 1 && firc_xt_find_chain(&t, "INPUT")->n_rules == 0);
        snprintf(c->rules[0].jump, sizeof(c->rules[0].jump), "%s", targets[k]);
        firc_xt_acl_t out;
        ASSERT_EQ(FIRC_OK, firc_xt_acl_judge(&t, "_NDM_ACL_IN", "_NDM_ACL_OUT", &out));
        ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
        ASSERT_STR_EQ("ppp0", out.iface[0]);
        firc_xt_table_clear(&t);
    }
    free(blob);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: no _NDM_ACL_IN (a firmware without lists) read as an error, which would turn kernel TCP off everywhere. */
TEST a_table_without_the_chain_is_an_empty_list(void) {
    static const char *const other[] = {"-i br0 -j DROP"};
    const seed_t s[] = {{"ACME_IN", other, 1}};
    firc_fake_xt_t *f = filter_with(s, 1);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)0, out.n, "%zu");
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a 33rd denying interface dropped silently, which leaves that segment redirected around its list. */
TEST more_than_32_denying_interfaces_is_limit(void) {
    static char names[33][32];
    static const char *acl[33];
    for (int i = 0; i < 33; i++) {
        snprintf(names[i], sizeof(names[i]), "-i nwg%d -j @PPPoE0", i);
        acl[i] = names[i];
    }
    const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"_NDM_ACL_IN", acl, 33}};
    firc_fake_xt_t *f = filter_with(s, 2);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_ERR_LIMIT, read_acl(f, &out));
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: _NDM_ACL_OUT left unread, its rules judged by -i instead of -o (or _NDM_ACL_IN's by -o), a missing _NDM_ACL_IN ending the read, or an ACCEPT-only out list taken for a deny. */
TEST an_out_list_names_its_exact_out_iface(void) {
    static const char *const out_acl[] = {"-o br1 -j @Guest", "-o br2 -j @Bridge0", "-i br7 -o nwg4 -j DROP"};
    const seed_t s[] = {{"@Guest", k_guest, 1}, {"@Bridge0", k_bridge0, 3}, {"_NDM_ACL_OUT", out_acl, 3}};
    firc_fake_xt_t *f = filter_with(s, 3);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)2, out.n, "%zu");
    ASSERT_STR_EQ("br1", out.iface[0]);
    ASSERT_STR_EQ("nwg4", out.iface[1]);
    ASSERT_FALSE(out.all);
    firc_fake_xt_free(f);
    static const char *const in_acl[] = {"-i br3 -o nwg5 -j DROP"};
    const seed_t s2[] = {{"_NDM_ACL_IN", in_acl, 1}};
    f = filter_with(s2, 1);
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)1, out.n, "%zu");
    ASSERT_STR_EQ("br3", out.iface[0]);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: a segment denying in both lists named twice, or the out list's names put before the in list's. */
TEST a_segment_denying_in_both_lists_is_named_once(void) {
    static const char *const in_acl[] = {"-i br1 -j DROP", "-i ppp0 -j @PPPoE0"};
    static const char *const out_acl[] = {"-o nwg9 -j @PPPoE0", "-o br1 -j @Guest"};
    const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"@Guest", k_guest, 1}, {"_NDM_ACL_IN", in_acl, 2},
                        {"_NDM_ACL_OUT", out_acl, 2}};
    firc_fake_xt_t *f = filter_with(s, 4);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_acl(f, &out));
    ASSERT_EQ_FMT((size_t)3, out.n, "%zu");
    ASSERT_STR_EQ("br1", out.iface[0]);
    ASSERT_STR_EQ("ppp0", out.iface[1]);
    ASSERT_STR_EQ("nwg9", out.iface[2]);
    firc_fake_xt_free(f);
    PASS();
}

/* Catches: an out deny without -o, with ! -o, or with a wildcard -o skipped instead of raising all, or a permitting one raising it. */
TEST an_out_deny_without_an_exact_out_iface_sets_all(void) {
    static const char *const noif[] = {"-j @PPPoE0"};
    static const char *const inv[] = {"! -o br3 -j @PPPoE0"};
    static const char *const ok[] = {"-j @Bridge0", "! -o br3 -j ACCEPT"};
    const char *const *cases[] = {noif, inv, ok};
    const size_t lens[] = {1, 1, 2};
    for (int k = 0; k < 3; k++) {
        const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"@Bridge0", k_bridge0, 3}, {"_NDM_ACL_OUT", cases[k], lens[k]}};
        firc_fake_xt_t *f = filter_with(s, 3);
        firc_xt_acl_t out;
        ASSERT_EQ(FIRC_OK, read_acl(f, &out));
        ASSERT_EQ(k < 2, out.all);
        ASSERT_EQ_FMT((size_t)0, out.n, "%zu");
        firc_fake_xt_free(f);
    }
    static const char *const wild[] = {"-o ppp0 -j @PPPoE0"};
    const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"_NDM_ACL_OUT", wild, 1}};
    firc_fake_xt_t *f = filter_with(s, 2);
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_fake_xt_blob(f, "filter", &info, &blob));
    firc_xt_table_t t;
    const char *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_xt_parse(FIRC_IPT_PROTO_IPV4, &info, blob, &t, &why));
    firc_xt_chain_t *c = firc_xt_find_chain(&t, "_NDM_ACL_OUT");
    ASSERT(c != NULL && c->n_rules == 1);
    xt_ipt_entry_t *e = (xt_ipt_entry_t *)c->rules[0].bytes;
    e->ip.outiface[3] = '\0';
    e->ip.outiface_mask[3] = 0;
    e->ip.outiface_mask[4] = 0;
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, firc_xt_acl_judge(&t, "_NDM_ACL_IN", "_NDM_ACL_OUT", &out));
    ASSERT_EQ_FMT((size_t)0, out.n, "%zu");
    ASSERT(out.all);
    firc_xt_table_clear(&t);
    free(blob);
    firc_fake_xt_free(f);
    PASS();
}

static firc_err_t read_split(int n_in, int n_out, firc_xt_acl_t *out) {
    static char names[64][32];
    static const char *in_acl[64], *out_acl[64];
    for (int i = 0; i < n_in; i++) {
        snprintf(names[i], sizeof(names[i]), "-i nwg%d -j @PPPoE0", i);
        in_acl[i] = names[i];
    }
    for (int i = 0; i < n_out; i++) {
        snprintf(names[32 + i], sizeof(names[32 + i]), "-o br%d -j @PPPoE0", i);
        out_acl[i] = names[32 + i];
    }
    const seed_t s[] = {{"@PPPoE0", k_pppoe0, 1}, {"_NDM_ACL_IN", in_acl, (size_t)n_in},
                        {"_NDM_ACL_OUT", out_acl, (size_t)n_out}};
    firc_fake_xt_t *f = filter_with(s, 3);
    firc_err_t err = read_acl(f, out);
    firc_fake_xt_free(f);
    return err;
}

/* Catches: the out list given a cap of its own, so 20 in and 13 out denying segments pass with one left redirected, or 32 together refused. */
TEST in_and_out_count_toward_one_cap(void) {
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_OK, read_split(20, 12, &out));
    ASSERT_EQ_FMT((size_t)32, out.n, "%zu");
    ASSERT_STR_EQ("nwg19", out.iface[19]);
    ASSERT_STR_EQ("br11", out.iface[31]);
    ASSERT_EQ(FIRC_ERR_LIMIT, read_split(20, 13, &out));
    PASS();
}

/* Catches: the read asked of a v6 handle, where the REDIR chain never exists. */
TEST a_v6_handle_is_refused(void) {
    firc_fake_xt_t *f = firc_fake_xt_new(FIRC_IPT_PROTO_IPV6);
    firc_xt_t *xt = firc_fake_xt_handle(f);
    firc_xt_acl_t out;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_xt_acl_denying(xt, "filter", "_NDM_ACL_IN", "_NDM_ACL_OUT", &out));
    firc_xt_free(xt);
    firc_fake_xt_free(f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(an_accept_only_list_denies_nothing);
    RUN_TEST(drop_and_reject_deny_in_rule_order);
    RUN_TEST(a_chain_with_any_other_target_or_a_jump_denies);
    RUN_TEST(names_listed_once_and_permitting_shapes_leave_all_clear);
    RUN_TEST(no_iface_inverted_or_wildcard_deny_sets_all);
    RUN_TEST(a_wildcard_deny_sets_all);
    RUN_TEST(a_jump_that_cannot_be_judged_denies);
    RUN_TEST(a_table_without_the_chain_is_an_empty_list);
    RUN_TEST(more_than_32_denying_interfaces_is_limit);
    RUN_TEST(a_v6_handle_is_refused);
    RUN_TEST(a_listed_name_is_zero_after_its_nul);
    RUN_TEST(an_out_list_names_its_exact_out_iface);
    RUN_TEST(a_segment_denying_in_both_lists_is_named_once);
    RUN_TEST(an_out_deny_without_an_exact_out_iface_sets_all);
    RUN_TEST(in_and_out_count_toward_one_cap);
    GREATEST_MAIN_END();
}

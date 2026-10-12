#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xt_golden.h"
#include "../../src/xtables/xt_internal.h"

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

static uint16_t get16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t get32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static uint32_t error_named_v4(const uint8_t *b, uint32_t size, const char *name) {
    for (uint32_t off = 0; off < size; off += get16(b + off + 90)) {
        const uint8_t *t = b + off + get16(b + off + 88);
        if (strcmp((const char *)t + 2, "ERROR") == 0 && strcmp((const char *)t + 32, name) == 0) { return off; }
    }
    return UINT32_MAX;
}

static firc_err_t run(firc_ipt_proto_t fam, const firc_xt_info_t *info, uint8_t *blob, const firc_xt_stage_t *stage,
                      firc_xt_info_t *ni, uint8_t **nb, int32_t **oi, char *why, size_t why_len) {
    firc_xt_table_t t;
    const char *bad = NULL;
    uint32_t exts = 0;
    firc_err_t err = firc_xt_parse(fam, info, blob, &t, &bad);
    if (err == FIRC_OK) { err = firc_xt_merge(&t, stage, &exts, why, why_len); }
    if (err == FIRC_OK) { err = firc_xt_serialise(&t, nb, ni, oi, why, why_len); }
    firc_xt_table_clear(&t);
    return err;
}

/* Catches: a merge writing a table iptables-restore would not have written from the same transcript. */
TEST each_fixture_merges_as_iptables_restore_did(void) {
    static const struct { const char *base, *stage, *want; } cases[] = {
        {"firmware", "firmware-firc", "firmware-firc"},
        {"firmware-firc", "firmware-firc", "firmware-firc"},
        {"firmware-firc", "full", "firmware-firc"},
        {"firmware-firc", "firmware-firc-remove", "firmware-firc-remove"},
        {"firmware-firc", "sweep", "sweep"},
        {"dedupe-seed", "dedupe", "dedupe"},
        {"kept-seed", "kept", "kept-seed"},
        {"empty", "dnat2000-mark", "dnat2000-mark"},
        {"firmware", "dnat-mark", "dnat-mark"},
    };
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (size_t f = 0; f < 2; f++) {
            firc_xt_info_t bi, wi, ni;
            uint8_t *base = NULL, *want = NULL, *nb = NULL;
            int32_t *oi = NULL;
            char why[256];
            ASSERTm(cases[c].base, firc_test_xt_read(cases[c].base, k_fams[f], &bi, &base));
            ASSERTm(cases[c].want, firc_test_xt_read(cases[c].want, k_fams[f], &wi, &want));
            firc_test_stage_t *s = firc_test_stage_new();
            firc_test_stage_fixture(s, cases[c].stage, k_fams[f]);
            ASSERT_EQ_FMTm(cases[c].stage, FIRC_OK, run(k_fams[f], &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
            ASSERTm(cases[c].stage, firc_test_xt_same(k_fams[f], &wi, want, &ni, nb));
            firc_test_stage_free(s);
            free(base);
            free(want);
            free(nb);
            free(oi);
        }
    }
    PASS();
}

/* Catches: counters of an entry that stayed byte-equal not carried, or a changed rule given the old rule's counters. */
TEST carried_entries_keep_their_old_index(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    firc_ipt_rule_free(s->chains[1].rules[0]);
    s->rules[2] = firc_test_rule("-d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.35");
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT_EQ_FMT(bi.num_entries, ni.num_entries, "%u");
    for (uint32_t k = 0; k < ni.num_entries; k++) {
        ASSERT_EQ_FMT(k == 15 ? -1 : (int32_t)k, oi[k], "%d");
    }
    firc_test_stage_free(s);
    free(base);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a jump into the middle of a firmware chain written to a stale offset after the table moved. */
TEST a_jump_into_the_middle_of_a_chain_is_carried(void) {
    firc_xt_info_t bi, wi, ni;
    uint8_t *base = NULL, *want = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &wi, &want));
    uint32_t head = error_named_v4(base, bi.size, "ACME_PRE");
    uint32_t tail = head + 176 + get16(base + head + 176 + 90);
    put32(base + 152 + 112 + 32, tail);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    uint32_t whead = error_named_v4(want, wi.size, "ACME_PRE");
    uint32_t wtail = whead + 176 + get16(want + whead + 176 + 90);
    ASSERT_EQ_FMT(wtail, get32(nb + 2 * 152 + 112 + 32), "%u");
    firc_test_stage_free(s);
    free(base);
    free(want);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a goto that loses its flag or lands on the chain's old offset after a write. */
TEST a_goto_into_our_chain_follows_it(void) {
    firc_xt_info_t bi, wi, ni;
    uint8_t *base = NULL, *want = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    ASSERT(firc_test_xt_read("firmware-firc-remove", FIRC_IPT_PROTO_IPV4, &wi, &want));
    base[3 * 152 + 82] |= XT_IPT_F_GOTO;
    firc_test_stage_t *s = firc_test_stage_new();
    const char *post[] = {"-j _NDM_MASQ", "-j FIRC_bh"};
    firc_test_stage_override(s, "POSTROUTING", post, 2);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(nb[3 * 152 + 82] & XT_IPT_F_GOTO);
    uint32_t first = error_named_v4(want, wi.size, "FIRC_DNAT") + 176;
    ASSERT_EQ_FMT(first, get32(nb + 3 * 152 + 112 + 32), "%u");
    firc_test_stage_free(s);
    free(base);
    free(want);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a duplicate cut from the end, where iptables -D cuts the first match, or an insert at n+1 refused. */
TEST the_first_of_two_copies_is_cut(void) {
    firc_xt_info_t bi, mi, ni;
    uint8_t *base = NULL, *mb = NULL, *nb = NULL;
    int32_t *om = NULL, *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const char *post[] = {"-j FIRC_bh", "-j _NDM_MASQ", "-j FIRC_bh"};
    firc_test_stage_override(s, "POSTROUTING", post, 3);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &mi, &mb, &om, why, sizeof(why)), "%d");
    firc_test_stage_free(s);
    s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND, FIRC_IPT_OP_INSERT};
    const int nums[] = {0, 3};
    const char *lines[] = {"-j FIRC_bh", "-j FIRC_g1"};
    firc_test_stage_patch(s, "POSTROUTING", 2, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &mi, mb, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    char *got = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &ni, nb);
    ASSERT(strstr(got, "-A POSTROUTING -j _NDM_MASQ\n-A POSTROUTING -j FIRC_bh\n-A POSTROUTING -j FIRC_g1\n-A ACME_PRE") != NULL);
    ASSERT_EQ_FMT(8, oi[7], "%d");
    ASSERT_EQ_FMT(9, oi[8], "%d");
    ASSERT_EQ_FMT(-1, oi[9], "%d");
    free(got);
    firc_test_stage_free(s);
    free(base);
    free(mb);
    free(om);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: a staged jump to a chain the table lacks written with a dangling verdict instead of refused. */
TEST a_jump_to_a_missing_chain_is_refused(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
    const int nums[] = {0};
    const char *lines[] = {"-j FIRC_nowhere"};
    firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_ERR_IO, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "FIRC_nowhere") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a jump to a built-in chain written as a jump to its first rule, which iptables-restore refuses. */
TEST a_jump_to_a_built_in_chain_is_refused(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
    const int nums[] = {0};
    const char *lines[] = {"-j PREROUTING"};
    firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "PREROUTING") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: an insert past the end of a chain written at the end, where iptables-restore refuses it. */
TEST an_insert_past_the_end_is_refused(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_INSERT};
    const int nums[] = {9};
    const char *lines[] = {"-j ACME_PRE"};
    firc_test_stage_patch(s, "POSTROUTING", 1, ops, nums, lines);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a refused rule reported without the words that were refused. */
TEST a_refused_rule_is_quoted(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const char *bad[] = {"-o nwg+ -j MASQUERADE"};
    firc_test_stage_override(s, "FIRC_g1", bad, 1);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(strstr(why, "\"-o nwg+ -j MASQUERADE\"") != NULL);
    firc_test_stage_free(s);
    free(base);
    PASS();
}

/* Catches: a sweep removing a jump the same write staged, or keeping one of ours it did not stage. */
TEST a_sweep_keeps_what_the_same_write_staged(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    const char *dnat[] = {"-d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.34"};
    firc_test_stage_override(s, "FIRC_DNAT", dnat, 1);
    const firc_ipt_option_t ops[] = {FIRC_IPT_OP_APPEND};
    const int nums[] = {0};
    const char *pre[] = {"-d 198.18.0.0/15 -j FIRC_DNAT"};
    firc_test_stage_patch(s, "PREROUTING", 1, ops, nums, pre);
    s->stage.sweep_prefix = "FIRC_";
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    char *got = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &ni, nb);
    ASSERT_STR_EQ("*nat\n"
                  ":PREROUTING ACCEPT [0:0]\n"
                  ":INPUT ACCEPT [0:0]\n"
                  ":OUTPUT ACCEPT [0:0]\n"
                  ":POSTROUTING ACCEPT [0:0]\n"
                  ":ACME_PRE - [0:0]\n"
                  ":FIRC_DNAT - [0:0]\n"
                  ":_NDM_DNAT - [0:0]\n"
                  ":_NDM_MASQ - [0:0]\n"
                  "-A PREROUTING -i eth3 -j _NDM_DNAT\n"
                  "-A PREROUTING -j ACME_PRE\n"
                  "-A PREROUTING -d 198.18.0.0/15 -j FIRC_DNAT\n"
                  "-A POSTROUTING -j _NDM_MASQ\n"
                  "-A ACME_PRE -s 192.168.1.0/24 -p udp -m udp --dport 5353 -j RETURN\n"
                  "-A FIRC_DNAT -d 198.18.0.1/32 -j DNAT --to-destination 93.184.216.34\n"
                  "-A _NDM_DNAT -d 203.0.113.5/32 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 192.168.1.10:443\n"
                  "-A _NDM_MASQ -o eth3 -j SNAT --to-source 203.0.113.5\n"
                  "-A _NDM_MASQ -o ppp0 -j MASQUERADE\n"
                  "COMMIT\n",
                  got);
    free(got);
    firc_test_stage_free(s);
    free(base);
    free(nb);
    free(oi);
    PASS();
}

/* Catches: the unchanged check missing a changed mark, or seeing a change in an identical table. */
TEST blob_equal_sees_a_changed_mark_only(void) {
    firc_xt_info_t bi, ni, mi;
    uint8_t *base = NULL, *nb = NULL, *mb = NULL;
    int32_t *oi = NULL, *om = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &base));
    uint8_t *copy = malloc(bi.size);
    memcpy(copy, base, bi.size);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "firmware-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, copy, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    ASSERT(firc_xt_blob_equal(&ni, nb, &bi, copy));
    firc_ipt_rule_free(s->rules[3]);
    s->rules[3] = firc_test_rule("-o nwg1 -m mark --mark 0x20000/0xff0000 -j MASQUERADE");
    memcpy(copy, base, bi.size);
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, copy, &s->stage, &mi, &mb, &om, why, sizeof(why)), "%d");
    ASSERT_FALSE(firc_xt_blob_equal(&mi, mb, &bi, copy));
    firc_test_stage_free(s);
    free(copy);
    free(base);
    free(nb);
    free(mb);
    free(oi);
    free(om);
    PASS();
}

/* Catches: counters handed to a new entry, or an old entry's counters dropped, when carried over. */
TEST counters_follow_old_index(void) {
    const int32_t old_index[] = {2, -1, 0};
    const firc_xt_counter_t old[] = {{10, 100}, {20, 200}, {30, 300}};
    firc_xt_counter_t *out = NULL;
    ASSERT_EQ_FMT(FIRC_OK, firc_xt_carry_counters(old_index, 3, old, 3, &out), "%d");
    ASSERT_EQ(30u, (unsigned)out[0].pcnt);
    ASSERT_EQ(300u, (unsigned)out[0].bcnt);
    ASSERT_EQ(0u, (unsigned)out[1].pcnt);
    ASSERT_EQ(0u, (unsigned)out[1].bcnt);
    ASSERT_EQ(10u, (unsigned)out[2].pcnt);
    free(out);
    PASS();
}

/* Catches: a filter or mangle rule firc writes encoded unlike iptables-restore 1.4.21 wrote it. */
TEST filter_and_mangle_fixtures_merge_as_iptables_restore_did(void) {
    static const struct { const char *base, *name; } cases[] = {
        {"f-firmware", "f-firc"}, {"f-firmware", "f-egress"}, {"m-firmware", "m-firc"}, {"m-firmware", "m-firc2"}};
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (size_t f = 0; f < 2; f++) {
            firc_xt_info_t bi, wi, ni;
            uint8_t *base = NULL, *want = NULL, *nb = NULL;
            int32_t *oi = NULL;
            char why[256];
            ASSERTm(cases[c].base, firc_test_xt_read(cases[c].base, k_fams[f], &bi, &base));
            ASSERTm(cases[c].name, firc_test_xt_read(cases[c].name, k_fams[f], &wi, &want));
            firc_test_stage_t *s = firc_test_stage_new();
            firc_test_stage_rules_file(s, cases[c].name, k_fams[f]);
            ASSERT_EQ_FMTm(why, FIRC_OK, run(k_fams[f], &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
            ASSERTm(cases[c].name, firc_test_xt_same(k_fams[f], &wi, want, &ni, nb));
            firc_test_stage_free(s);
            free(base);
            free(want);
            free(nb);
            free(oi);
        }
    }
    PASS();
}

/* Catches: a capture rule encoded unlike iptables-restore 1.4.21 wrote it (on a 32-bit build, against the router's capture). */
TEST the_capture_fixture_merges_as_iptables_restore_did(void) {
    for (size_t f = 0; f < 2; f++) {
        firc_xt_info_t bi, wi, ni;
        uint8_t *base = NULL, *want = NULL, *nb = NULL;
        int32_t *oi = NULL;
        char why[256];
        ASSERT(firc_test_xt_read("m-firmware", k_fams[f], &bi, &base));
        ASSERT(firc_test_xt_read("m-tap", k_fams[f], &wi, &want));
        firc_test_stage_t *s = firc_test_stage_new();
        firc_test_stage_rules_file(s, "m-tap", k_fams[f]);
        ASSERT_EQ_FMTm(why, FIRC_OK, run(k_fams[f], &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
        ASSERT(firc_test_xt_same(k_fams[f], &wi, want, &ni, nb));
        firc_test_stage_free(s);
        free(base);
        free(want);
        free(nb);
        free(oi);
    }
    PASS();
}

static void fill_private(firc_ipt_proto_t fam, uint8_t *blob, uint32_t size) {
    uint32_t eh = firc_xt_ehdr(fam), at_t = firc_xt_at_toff(fam);
    for (uint32_t off = 0; off < size; off += firc_xt_rd16(blob + off + at_t + 2)) {
        uint8_t *e = blob + off;
        uint32_t toff = firc_xt_rd16(e + at_t);
        for (uint32_t m = eh; m < toff; m += firc_xt_rd16(e + m)) {
            uint32_t ms = firc_xt_rd16(e + m);
            if (strcmp((const char *)e + m + 2, "limit") == 0) {
                memset(e + m + XT_MATCH_HDR_LEN + XT_LIMIT_USERSPACE, 0x5a, ms - XT_MATCH_HDR_LEN - XT_LIMIT_USERSPACE);
            } else if (strcmp((const char *)e + m + 2, "string") == 0) {
                memset(e + m + XT_MATCH_HDR_LEN + XT_STRING_USERSPACE, 0x5a, ms - XT_MATCH_HDR_LEN - XT_STRING_USERSPACE);
            }
        }
    }
}

/* Catches: kernel-filled bytes of limit/string making a capture chain nothing changed in look changed, so every pass writes the table. */
TEST an_unchanged_capture_chain_with_kernel_bytes_is_not_written(void) {
    for (size_t f = 0; f < 2; f++) {
        firc_xt_info_t ri, ni;
        uint8_t *read = NULL, *nb = NULL;
        int32_t *oi = NULL;
        char why[256];
        ASSERT(firc_test_xt_read("m-tap", k_fams[f], &ri, &read));
        fill_private(k_fams[f], read, ri.size);
        firc_test_stage_t *s = firc_test_stage_new();
        firc_test_stage_rules_file(s, "m-tap", k_fams[f]);
        ASSERT_EQ_FMTm(why, FIRC_OK, run(k_fams[f], &ri, read, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
        ASSERT(firc_xt_blob_equal(&ni, nb, &ri, read));
        firc_test_stage_free(s);
        free(read);
        free(nb);
        free(oi);
    }
    PASS();
}

static bool flip_in_match(firc_ipt_proto_t fam, uint8_t *blob, uint32_t size, const char *name, uint32_t at) {
    uint32_t eh = firc_xt_ehdr(fam), at_t = firc_xt_at_toff(fam);
    for (uint32_t off = 0; off < size; off += firc_xt_rd16(blob + off + at_t + 2)) {
        uint8_t *e = blob + off;
        uint32_t toff = firc_xt_rd16(e + at_t);
        for (uint32_t m = eh; m < toff; m += firc_xt_rd16(e + m)) {
            if (strcmp((const char *)e + m + 2, name) == 0) {
                e[m + XT_MATCH_HDR_LEN + at] ^= 0x01;
                return true;
            }
        }
    }
    return false;
}

/* Catches: the compare skipping a user-set byte of limit or string (the burst, the last pattern byte), so a changed capture rule is never written. */
TEST a_changed_user_byte_of_limit_or_string_is_written(void) {
    static const struct { const char *name; uint32_t at; } cases[] = {
        {"limit", XT_LIMIT_USERSPACE - 1u}, {"string", XT_STRING_USERSPACE - 1u}, {"string", 149u}, {"connbytes", 23u}};
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (size_t f = 0; f < 2; f++) {
            firc_xt_info_t ri, ni;
            uint8_t *read = NULL, *nb = NULL;
            int32_t *oi = NULL;
            char why[256];
            ASSERT(firc_test_xt_read("m-tap", k_fams[f], &ri, &read));
            ASSERTm(cases[c].name, flip_in_match(k_fams[f], read, ri.size, cases[c].name, cases[c].at));
            firc_test_stage_t *s = firc_test_stage_new();
            firc_test_stage_rules_file(s, "m-tap", k_fams[f]);
            ASSERT_EQ_FMTm(why, FIRC_OK, run(k_fams[f], &ri, read, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
            ASSERTm(cases[c].name, !firc_xt_blob_equal(&ni, nb, &ri, read));
            firc_test_stage_free(s);
            free(read);
            free(nb);
            free(oi);
        }
    }
    PASS();
}

/* Catches: a merge that decodes or re-encodes a firmware rule it does not know instead of carrying its bytes. */
TEST an_unknown_extension_in_a_firmware_rule_is_carried_byte_for_byte(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("m-firmware", FIRC_IPT_PROTO_IPV4, &bi, &base));
    uint8_t *hit = NULL;
    for (uint32_t i = 2; i + 4 < bi.size && hit == NULL; i++) {
        if (memcmp(base + i, "mark\0", 5) == 0 && base[i - 2 + 31] == 1) { hit = base + i; }
    }
    ASSERT(hit != NULL);
    memcpy(hit, "zzzz", 4);
    uint32_t off = 0, len = 0;
    for (uint32_t o = 0; o < bi.size; o += firc_xt_rd16(base + o + 90)) {
        if (base + o < hit && hit < base + o + firc_xt_rd16(base + o + 90)) {
            off = o;
            len = firc_xt_rd16(base + o + 90);
        }
    }
    ASSERT(len > 112);
    uint8_t *orig = malloc(len);
    ASSERT(orig != NULL);
    memcpy(orig, base + off, len);
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_rules_file(s, "m-firc", FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ_FMTm(why, FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    bool found = false;
    for (uint32_t o = 0; o < ni.size && !found; o += firc_xt_rd16(nb + o + 90)) {
        found = firc_xt_rd16(nb + o + 90) == len && memcmp(nb + o, orig, 92) == 0 &&
                memcmp(nb + o + 112, orig + 112, len - 112) == 0;
    }
    ASSERT(found);
    free(orig);
    firc_test_stage_free(s);
    free(base);
    free(nb);
    free(oi);
    PASS();
}

static char *lines_of(const char *text, const char *chain) {
    char head[48];
    int hl = snprintf(head, sizeof(head), "-A %s ", chain);
    size_t cap = strlen(text) + 1, n = 0;
    char *out = calloc(cap, 1);
    if (out == NULL) { abort(); }
    for (const char *l = text; *l != '\0';) {
        const char *end = strchr(l, '\n');
        size_t len = end != NULL ? (size_t)(end - l) + 1 : strlen(l);
        if (strncmp(l, head, (size_t)hl) == 0) {
            memcpy(out + n, l, len);
            n += len;
        }
        l += len;
    }
    return out;
}

static firc_err_t moved_down(const char *fixture, firc_ipt_proto_t fam, const char *table, const char *chain,
                             const char *jump, firc_xt_info_t *ni, uint8_t **nb) {
    firc_xt_info_t bi;
    uint8_t *base = NULL;
    int32_t *oi = NULL;
    char why[256];
    if (!firc_test_xt_read(fixture, fam, &bi, &base)) { return FIRC_ERR_IO; }
    char *text = firc_test_xt_print(fam, table, &bi, base);
    char *mine = text != NULL ? lines_of(text, chain) : NULL;
    if (mine == NULL) { abort(); }
    const char *rules[32];
    size_t n = 0, hl = strlen(chain) + 4;
    for (char *save = NULL, *l = strtok_r(mine, "\n", &save); l != NULL && n < 31; l = strtok_r(NULL, "\n", &save)) {
        if (strcmp(l + hl, jump) != 0) { rules[n++] = l + hl; }
    }
    rules[n++] = jump;
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_override(s, chain, rules, n);
    firc_err_t err = run(fam, &bi, base, &s->stage, ni, nb, &oi, why, sizeof(why));
    firc_test_stage_free(s);
    free(mine);
    free(text);
    free(base);
    free(oi);
    return err;
}

/* Catches: a full pass leaving our jump below a rule someone put above it (the position an incremental pass keeps). */
TEST a_relocating_merge_puts_our_jumps_back_in_place(void) {
    for (size_t f = 0; f < 2; f++) {
        for (int relocate = 0; relocate < 2; relocate++) {
            firc_xt_info_t bi, ni;
            uint8_t *base = NULL, *nb = NULL;
            int32_t *oi = NULL;
            char why[256];
            ASSERT(firc_test_xt_read("kept-seed", k_fams[f], &bi, &base));
            firc_test_stage_t *s = firc_test_stage_new();
            firc_test_stage_fixture(s, "kept", k_fams[f]);
            s->stage.sweep_prefix = "FIRC_";
            s->stage.relocate_jumps = relocate != 0;
            ASSERT_EQ_FMT(FIRC_OK, run(k_fams[f], &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
            char *text = firc_test_xt_print(k_fams[f], "nat", &ni, nb);
            ASSERT(text != NULL);
            char *pre = lines_of(text, "PREROUTING");
            ASSERT_STR_EQm(relocate ? "a full pass puts it first" : "an incremental pass keeps it",
                           relocate ? "-A PREROUTING -j FIRC_DNSOR\n-A PREROUTING -i eth3 -j _NDM_DNAT\n-A PREROUTING -j ACME_PRE\n"
                                    : "-A PREROUTING -i eth3 -j _NDM_DNAT\n-A PREROUTING -j ACME_PRE\n-A PREROUTING -j FIRC_DNSOR\n",
                           pre);
            free(pre);
            free(text);
            firc_test_stage_free(s);
            free(base);
            free(nb);
            free(oi);
        }
    }
    PASS();
}

/* Catches: a full pass leaving the pool barrier or the capture's jump below firmware rules, or reordering the jumps it staged. */
TEST a_full_pass_puts_the_barrier_and_the_capture_first(void) {
    static const struct { const char *name, *table, *chain, *jump, *kept; } cases[] = {
        {"f-firc", "filter", "FORWARD", "-j FIRC_POOLREJECT",
         "-A FORWARD -j ACME_FWD\n-A FORWARD -j _NDM_FORWARD\n-A FORWARD -j FIRC_g1\n-A FORWARD -j FIRC_bh\n"
         "-A FORWARD -j FIRC_POOLREJECT\n"},
        {"m-tap", "mangle", "FORWARD", "-j FIRC_TAP", "-A FORWARD -j _NDM_QOS\n-A FORWARD -j FIRC_TAP\n"},
    };
    for (size_t c = 0; c < 2; c++) {
        for (size_t f = 0; f < 2; f++) {
            for (int relocate = 0; relocate < 2; relocate++) {
                firc_xt_info_t si, wi, ni;
                uint8_t *seed = NULL, *want = NULL, *nb = NULL;
                int32_t *oi = NULL;
                char why[256];
                ASSERT_EQ_FMTm(cases[c].name, FIRC_OK, moved_down(cases[c].name, k_fams[f], cases[c].table, cases[c].chain, cases[c].jump, &si, &seed), "%d");
                char *seen = firc_test_xt_print(k_fams[f], cases[c].table, &si, seed);
                char *fwd = lines_of(seen, cases[c].chain);
                ASSERT_STR_EQm("the seed has our jump last", cases[c].kept, fwd);
                free(fwd);
                free(seen);
                firc_test_stage_t *s = firc_test_stage_new();
                firc_test_stage_rules_file(s, cases[c].name, k_fams[f]);
                s->stage.sweep_prefix = "FIRC_";
                s->stage.relocate_jumps = relocate != 0;
                ASSERT_EQ_FMTm(why, FIRC_OK, run(k_fams[f], &si, seed, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
                if (relocate) {
                    ASSERTm(cases[c].name, firc_test_xt_read(cases[c].name, k_fams[f], &wi, &want));
                    ASSERTm(cases[c].name, firc_test_xt_same(k_fams[f], &wi, want, &ni, nb));
                } else {
                    char *text = firc_test_xt_print(k_fams[f], cases[c].table, &ni, nb);
                    char *got = lines_of(text, cases[c].chain);
                    ASSERT_STR_EQm("an incremental pass keeps it", cases[c].kept, got);
                    free(got);
                    free(text);
                }
                firc_test_stage_free(s);
                free(seed);
                free(want);
                free(nb);
                free(oi);
            }
        }
    }
    PASS();
}

/* Catches: a full pass rewriting a table whose jumps already stand where they are staged (every full pass then writes), one that was empty of ours, or one cutting jumps inside chains (their counters lost). */
TEST a_relocating_merge_of_a_table_in_place_changes_nothing(void) {
    static const struct { const char *base, *want; bool fixture; size_t moved; } cases[] = {
        {"firmware-firc", "firmware-firc", true, 4},
        {"firmware", "firmware-firc", true, 0},
        {"f-firc", "f-firc", false, 3},
        {"m-tap", "m-tap", false, 1},
        {"m-firc", "m-firc", false, 2},
        {"m-firmware", "m-firc", false, 0},
    };
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        for (size_t f = 0; f < 2; f++) {
            firc_xt_info_t bi, wi, ni;
            uint8_t *base = NULL, *want = NULL, *nb = NULL;
            int32_t *oi = NULL;
            char why[256];
            ASSERTm(cases[c].base, firc_test_xt_read(cases[c].base, k_fams[f], &bi, &base));
            ASSERTm(cases[c].want, firc_test_xt_read(cases[c].want, k_fams[f], &wi, &want));
            firc_test_stage_t *s = firc_test_stage_new();
            if (cases[c].fixture) {
                firc_test_stage_fixture(s, "full", k_fams[f]);
            } else {
                firc_test_stage_rules_file(s, cases[c].want, k_fams[f]);
                s->stage.sweep_prefix = "FIRC_";
            }
            s->stage.relocate_jumps = true;
            ASSERT_EQ_FMTm(why, FIRC_OK, run(k_fams[f], &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
            ASSERTm(cases[c].base, firc_test_xt_same(k_fams[f], &wi, want, &ni, nb));
            if (strcmp(cases[c].base, cases[c].want) == 0) {
                ASSERTm(cases[c].base, firc_xt_blob_equal(&ni, nb, &bi, base));
                size_t fresh = 0;
                for (uint32_t k = 0; k < ni.num_entries; k++) { fresh += oi[k] < 0 ? 1u : 0u; }
                ASSERT_EQ_FMTm("only the relocated jumps lose their counters", cases[c].moved, fresh, "%zu");
            }
            firc_test_stage_free(s);
            free(base);
            free(want);
            free(nb);
            free(oi);
        }
    }
    PASS();
}

/* Catches: jumps cut for relocation when no sweep prefix names ours (a firmware jump taken for ours, or a NULL prefix read). */
TEST relocation_needs_a_sweep_prefix(void) {
    firc_xt_info_t bi, ni;
    uint8_t *base = NULL, *nb = NULL;
    int32_t *oi = NULL;
    char why[256];
    ASSERT(firc_test_xt_read("kept-seed", FIRC_IPT_PROTO_IPV4, &bi, &base));
    firc_test_stage_t *s = firc_test_stage_new();
    firc_test_stage_fixture(s, "kept", FIRC_IPT_PROTO_IPV4);
    s->stage.relocate_jumps = true;
    ASSERT_EQ_FMT(FIRC_OK, run(FIRC_IPT_PROTO_IPV4, &bi, base, &s->stage, &ni, &nb, &oi, why, sizeof(why)), "%d");
    char *text = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &ni, nb);
    char *pre = lines_of(text, "PREROUTING");
    ASSERT_STR_EQ("-A PREROUTING -i eth3 -j _NDM_DNAT\n-A PREROUTING -j ACME_PRE\n-A PREROUTING -j FIRC_DNSOR\n", pre);
    free(pre);
    free(text);
    firc_test_stage_free(s);
    free(base);
    free(nb);
    free(oi);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(each_fixture_merges_as_iptables_restore_did);
    RUN_TEST(filter_and_mangle_fixtures_merge_as_iptables_restore_did);
    RUN_TEST(the_capture_fixture_merges_as_iptables_restore_did);
    RUN_TEST(an_unchanged_capture_chain_with_kernel_bytes_is_not_written);
    RUN_TEST(a_changed_user_byte_of_limit_or_string_is_written);
    RUN_TEST(an_unknown_extension_in_a_firmware_rule_is_carried_byte_for_byte);
    RUN_TEST(carried_entries_keep_their_old_index);
    RUN_TEST(a_jump_into_the_middle_of_a_chain_is_carried);
    RUN_TEST(a_goto_into_our_chain_follows_it);
    RUN_TEST(the_first_of_two_copies_is_cut);
    RUN_TEST(a_jump_to_a_missing_chain_is_refused);
    RUN_TEST(a_jump_to_a_built_in_chain_is_refused);
    RUN_TEST(an_insert_past_the_end_is_refused);
    RUN_TEST(a_refused_rule_is_quoted);
    RUN_TEST(a_sweep_keeps_what_the_same_write_staged);
    RUN_TEST(blob_equal_sees_a_changed_mark_only);
    RUN_TEST(counters_follow_old_index);
    RUN_TEST(a_relocating_merge_puts_our_jumps_back_in_place);
    RUN_TEST(a_full_pass_puts_the_barrier_and_the_capture_first);
    RUN_TEST(a_relocating_merge_of_a_table_in_place_changes_nothing);
    RUN_TEST(relocation_needs_a_sweep_prefix);
    GREATEST_MAIN_END();
}

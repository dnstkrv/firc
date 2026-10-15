#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "xt_golden.h"
#include "../../src/xtables/abi.h"

enum { K_TARGET_OFFSET = 88, K_NEXT_OFFSET = 90, K_FLAGS = 82, K_COMEFROM = 92, K_COUNTERS = 96, K_SRC = 0, K_DST = 4, K_SMSK = 8, K_DMSK = 12, K_V4_HEADER = 112 };

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

/* Catches: the test printer (fake reads, routecheck) printing a filter or mangle rule unlike iptables-save 1.4.21. */
TEST every_table_prints_as_iptables_save_did(void) {
    for (size_t i = 0; i < firc_test_xt_n_all; i++) {
        for (size_t f = 0; f < 2; f++) {
            const firc_test_xt_fixture_t *fx = &firc_test_xt_all[i];
            if (!firc_test_xt_in_family(fx->name, k_fams[f])) { continue; }
            firc_xt_info_t info;
            uint8_t *blob = NULL;
            ASSERTm(fx->name, firc_test_xt_read(fx->name, k_fams[f], &info, &blob));
            char *want = firc_test_xt_read_text(fx->name, k_fams[f]);
            char *got = firc_test_xt_print(k_fams[f], fx->table, &info, blob);
            ASSERTm(fx->name, want != NULL && got != NULL);
            ASSERT_STR_EQm(fx->name, want, got);
            free(want);
            free(got);
            free(blob);
        }
    }
    PASS();
}

/* Catches: the loader passing an extension it cannot convert, so a big-endian run compares unconverted bytes. */
TEST an_unknown_extension_is_not_converted(void) {
    size_t len = 0;
    uint8_t *raw = firc_test_xt_raw("firmware", FIRC_IPT_PROTO_IPV4, &len);
    ASSERT(raw != NULL && len > XT_REPLACE_HDR_LEN);
    uint8_t *snat = NULL;
    for (size_t i = XT_REPLACE_HDR_LEN; i + 4 <= len && snat == NULL; i++) {
        if (memcmp(raw + i, "SNAT", 4) == 0) { snat = raw + i; }
    }
    ASSERT(snat != NULL);
    snat[0] = 'X';
    ASSERT_FALSE(firc_test_xt_to_host(FIRC_IPT_PROTO_IPV4, raw + XT_REPLACE_HDR_LEN, (uint32_t)(len - XT_REPLACE_HDR_LEN)));
    free(raw);
    PASS();
}

/* Catches: the comparison seeing counters a kernel write never compares, or missing a changed address. */
TEST same_ignores_counters_and_comefrom_only(void) {
    firc_xt_info_t ai, bi;
    uint8_t *a = NULL, *b = NULL;
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &ai, &a));
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &b));
    uint32_t last = 0;
    for (uint32_t off = 0; off < bi.size;) {
        last = off;
        uint16_t next;
        memcpy(&next, b + off + K_NEXT_OFFSET, 2);
        off += next;
    }
    ASSERT(last > 0);
    uint32_t at[2] = {0, last};
    for (int k = 0; k < 2; k++) {
        memset(b + at[k] + K_COUNTERS, 0x11, 16);
        b[at[k] + K_COMEFROM] = 0x01;
    }
    ASSERT(firc_test_xt_same(FIRC_IPT_PROTO_IPV4, &ai, a, &bi, b));
    b[last + K_SRC] ^= 0x01;
    ASSERT_FALSE(firc_test_xt_same(FIRC_IPT_PROTO_IPV4, &ai, a, &bi, b));
    b[last + K_SRC] ^= 0x01;
    b[0 + K_SRC] ^= 0x01;
    ASSERT_FALSE(firc_test_xt_same(FIRC_IPT_PROTO_IPV4, &ai, a, &bi, b));
    free(a);
    free(b);
    PASS();
}

/* Catches: the printer losing the order of -s and -d or the goto form, which no captured fixture exercises. */
TEST source_destination_and_goto_print_in_iptables_order(void) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("tiny", FIRC_IPT_PROTO_IPV4, &info, &blob));
    uint32_t hit = UINT32_MAX;
    for (uint32_t off = 0; off < info.size;) {
        uint16_t toff, next;
        memcpy(&toff, blob + off + K_TARGET_OFFSET, 2);
        memcpy(&next, blob + off + K_NEXT_OFFSET, 2);
        if (blob[off + toff + 2] == '\0' && toff == K_V4_HEADER && next == K_V4_HEADER + XT_STANDARD_TARGET_LEN) {
            int32_t verdict;
            memcpy(&verdict, blob + off + toff + 32, 4);
            if (verdict > 0) { hit = off; }
        }
        off += next;
    }
    ASSERT(hit != UINT32_MAX);
    static const uint8_t src[4] = {10, 0, 0, 0}, smsk[4] = {255, 0, 0, 0};
    static const uint8_t dst[4] = {192, 168, 1, 1}, dmsk[4] = {255, 255, 255, 255};
    memcpy(blob + hit + K_SRC, src, 4);
    memcpy(blob + hit + K_DST, dst, 4);
    memcpy(blob + hit + K_SMSK, smsk, 4);
    memcpy(blob + hit + K_DMSK, dmsk, 4);
    blob[hit + K_FLAGS] = 0x02;
    char *got = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &info, blob);
    ASSERT(got != NULL);
    ASSERT(strstr(got, "-A POSTROUTING -s 10.0.0.0/8 -d 192.168.1.1/32 -g FIRC_g1\n") != NULL);
    free(got);
    free(blob);
    PASS();
}

/* Catches: a corrupt next_offset or target size sending the loader or printer past the blob or into a loop. */
TEST corrupt_blobs_are_refused_not_followed(void) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("tiny", FIRC_IPT_PROTO_IPV4, &info, &blob));
    uint16_t zero = 0, huge = 0xfff0, small = 40;
    memcpy(blob + K_NEXT_OFFSET, &zero, 2);
    ASSERT(firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &info, blob) == NULL);
    memcpy(blob + K_NEXT_OFFSET, &huge, 2);
    ASSERT(firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &info, blob) == NULL);
    memcpy(blob + K_NEXT_OFFSET, &small, 2);
    ASSERT(firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "nat", &info, blob) == NULL);
    free(blob);
    size_t len = 0;
    uint8_t *raw = firc_test_xt_raw("tiny", FIRC_IPT_PROTO_IPV4, &len);
    ASSERT(raw != NULL);
    uint8_t *e = raw + XT_REPLACE_HDR_LEN;
    uint16_t toff = (uint16_t)(e[K_TARGET_OFFSET] | (e[K_TARGET_OFFSET + 1] << 8));
    ASSERT(toff >= K_V4_HEADER && toff + 2u <= len - XT_REPLACE_HDR_LEN);
    e[toff] = 0;
    e[toff + 1] = 0;
    ASSERT_FALSE(firc_test_xt_to_host(FIRC_IPT_PROTO_IPV4, e, (uint32_t)(len - XT_REPLACE_HDR_LEN)));
    free(raw);
    PASS();
}

/* Catches: the printer or loader refusing what the routers' iptables wrote: 32-bit limit, Keenetic mac revision 1. */
TEST router_goldens_print_as_iptables_save_did(void) {
    static const struct { const char *name, *variant; } k_router[] = {{"m-tap", "ilp32"}, {"m-firc", "kn"}};
    for (size_t i = 0; i < sizeof(k_router) / sizeof(k_router[0]); i++) {
        for (size_t f = 0; f < 2; f++) {
            firc_xt_info_t info;
            uint8_t *blob = NULL;
            ASSERTm(k_router[i].name, firc_test_xt_read_as(k_router[i].name, k_fams[f], k_router[i].variant, &info, &blob));
            firc_xt_info_t host_info;
            uint8_t *host = NULL;
            ASSERTm(k_router[i].name, firc_test_xt_read(k_router[i].name, k_fams[f], &host_info, &host));
            bool own_abi = sizeof(long) == 4 && strcmp(k_router[i].variant, "ilp32") == 0;
            ASSERTm(k_router[i].name, own_abi || !firc_test_xt_same(k_fams[f], &info, blob, &host_info, host));
            free(host);
            char *want = firc_test_xt_read_text_as(k_router[i].name, k_fams[f], k_router[i].variant);
            char *got = firc_test_xt_print(k_fams[f], "mangle", &info, blob);
            ASSERTm(k_router[i].name, want != NULL && got != NULL);
            ASSERT_STR_EQm(k_router[i].name, want, got);
            free(want);
            free(got);
            free(blob);
        }
    }
    PASS();
}

static uint32_t find_match(const uint8_t *e, uint32_t toff, const char *name, bool host) {
    for (uint32_t m = K_V4_HEADER; m < toff;) {
        if (strcmp((const char *)e + m + 2, name) == 0) { return m; }
        uint16_t ms = (uint16_t)(e[m] | (e[m + 1] << 8));
        if (host) { memcpy(&ms, e + m, 2); }
        if (ms == 0) { return 0; }
        m += ms;
    }
    return 0;
}

static bool shrink_payload(const char *name, uint32_t by) {
    size_t len = 0;
    uint8_t *raw = firc_test_xt_raw("m-tap", FIRC_IPT_PROTO_IPV4, &len);
    if (raw == NULL) { return false; }
    uint8_t *blob = raw + XT_REPLACE_HDR_LEN;
    uint32_t size = (uint32_t)(len - XT_REPLACE_HDR_LEN);
    bool ok = false;
    for (uint32_t off = 0; off < size;) {
        uint8_t *e = blob + off;
        uint16_t toff = (uint16_t)(e[K_TARGET_OFFSET] | (e[K_TARGET_OFFSET + 1] << 8));
        uint16_t next = (uint16_t)(e[K_NEXT_OFFSET] | (e[K_NEXT_OFFSET + 1] << 8));
        uint32_t m = strcmp((const char *)e + toff + 2, name) == 0 ? toff : find_match(e, toff, name, false);
        if (m != 0) {
            uint16_t ms = (uint16_t)(e[m] | (e[m + 1] << 8));
            memmove(e + m + ms - by, e + m + ms, size - (off + m + ms));
            ms = (uint16_t)(ms - by);
            if (m != toff) { toff = (uint16_t)(toff - by); }
            next = (uint16_t)(next - by);
            e[m] = (uint8_t)ms;
            e[m + 1] = (uint8_t)(ms >> 8);
            e[K_TARGET_OFFSET] = (uint8_t)toff;
            e[K_TARGET_OFFSET + 1] = (uint8_t)(toff >> 8);
            e[K_NEXT_OFFSET] = (uint8_t)next;
            e[K_NEXT_OFFSET + 1] = (uint8_t)(next >> 8);
            ok = firc_test_xt_to_host(FIRC_IPT_PROTO_IPV4, blob, size - by);
            break;
        }
        off += next;
    }
    free(raw);
    return ok;
}

/* Catches: the loader passing a payload one byte shorter than the struct the printer copies out of it. */
TEST a_truncated_payload_is_refused(void) {
    static const struct { const char *name; uint32_t room, need; } k_short[] = {
        {"string", 160, 160}, {"conntrack", 168, 164}, {"connbytes", 24, 24}, {"length", 8, 6},
        {"mark", 16, 12}, {"tcp", 16, 12}, {"NFLOG", 80, 76}, {"limit", sizeof(long) == 4 ? 32 : 40, 8},
    };
    for (size_t i = 0; i < sizeof(k_short) / sizeof(k_short[0]); i++) {
        uint32_t room = k_short[i].room, need = k_short[i].need;
        ASSERTm(k_short[i].name, shrink_payload(k_short[i].name, room - need));
        ASSERT_FALSEm(k_short[i].name, shrink_payload(k_short[i].name, room - need + 1));
    }
    PASS();
}

/* Catches: the printer rounding a limit rate firc never emits into one it does. */
TEST a_limit_rate_off_the_second_is_refused(void) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("m-tap", FIRC_IPT_PROTO_IPV4, &info, &blob));
    uint32_t hits = 0;
    for (uint32_t off = 0; off < info.size;) {
        uint16_t toff, next;
        memcpy(&toff, blob + off + K_TARGET_OFFSET, 2);
        memcpy(&next, blob + off + K_NEXT_OFFSET, 2);
        uint32_t m = find_match(blob + off, toff, "limit", true);
        if (m != 0) {
            uint32_t avg = 30;
            memcpy(blob + off + m + 32, &avg, 4);
            hits++;
        }
        off += next;
    }
    ASSERT_EQ(2u, hits);
    char *got = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, "mangle", &info, blob);
    ASSERT(got == NULL);
    free(blob);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(every_table_prints_as_iptables_save_did);
    RUN_TEST(router_goldens_print_as_iptables_save_did);
    RUN_TEST(a_truncated_payload_is_refused);
    RUN_TEST(a_limit_rate_off_the_second_is_refused);
    RUN_TEST(an_unknown_extension_is_not_converted);
    RUN_TEST(source_destination_and_goto_print_in_iptables_order);
    RUN_TEST(corrupt_blobs_are_refused_not_followed);
    RUN_TEST(same_ignores_counters_and_comefrom_only);
    GREATEST_MAIN_END();
}

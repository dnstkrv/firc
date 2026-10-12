#include "greatest.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "firc/match.h"
#include "firc/subparse.h"

#define FX "tests/unit/fixtures/srs/"

typedef struct got {
    firc_sub_rules_t rs;
    firc_sub_parse_stats_t st;
    firc_err_t err;
} got_t;

typedef struct bytes {
    uint8_t *p;
    size_t n, cap;
} bytes_t;

static void put(bytes_t *b, const void *src, size_t n) {
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->p = realloc(b->p, b->cap);
    }
    memcpy(b->p + b->n, src, n);
    b->n += n;
    b->p[b->n] = 0;
}

static void put8(bytes_t *b, unsigned v) {
    uint8_t c = (uint8_t)v;
    put(b, &c, 1);
}

static void put_uvarint(bytes_t *b, uint64_t v) {
    while (v >= 0x80) {
        put8(b, (unsigned)(v & 0x7f) | 0x80);
        v >>= 7;
    }
    put8(b, (unsigned)v);
}

static void put_be64(bytes_t *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) { put8(b, (unsigned)(v >> (i * 8)) & 0xff); }
}

static bytes_t srs_of(const bytes_t *raw, unsigned version) {
    bytes_t out = {0};
    put(&out, "SRS", 3);
    put8(&out, version);
    uLongf zn = compressBound((uLong)raw->n);
    uint8_t *z = malloc(zn);
    compress2(z, &zn, raw->p, (uLong)raw->n, 9);
    put(&out, z, zn);
    free(z);
    return out;
}

static bytes_t read_fixture(const char *name) {
    bytes_t b = {0};
    char path[256];
    snprintf(path, sizeof(path), FX "%s", name);
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return b; }
    char chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) { put(&b, chunk, n); }
    fclose(f);
    return b;
}

static got_t parse_n(const void *body, size_t len) {
    got_t g;
    memset(&g, 0, sizeof(g));
    firc_sub_rules_init(&g.rs);
    g.err = firc_sub_parse_rules_stats(body, len, &g.rs, &g.st, NULL, NULL);
    return g;
}

static got_t parse_fixture(const char *name) {
    bytes_t b = read_fixture(name);
    got_t g = parse_n(b.p != NULL ? (const char *)b.p : "", b.n);
    free(b.p);
    return g;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static char *sorted_rows(const got_t *g) {
    char **rows = calloc(g->rs.n + 1, sizeof(char *));
    size_t total = 1;
    for (size_t i = 0; i < g->rs.n; i++) {
        const char *p = firc_sub_rules_proto(&g->rs, i), *q = firc_sub_rules_ports(&g->rs, i);
        char buf[512];
        snprintf(buf, sizeof(buf), "%s %s %s %s", firc_sub_rules_type(&g->rs, i), firc_sub_rules_text(&g->rs, i),
                 p ? p : "-", q ? q : "-");
        rows[i] = strdup(buf);
        total += strlen(buf) + 1;
    }
    qsort(rows, g->rs.n, sizeof(char *), cmp_str);
    char *out = malloc(total);
    out[0] = '\0';
    for (size_t i = 0; i < g->rs.n; i++) {
        strcat(out, rows[i]);
        strcat(out, "\n");
        free(rows[i]);
    }
    free(rows);
    return out;
}

static void free_got(got_t *g) { firc_sub_rules_free(&g->rs); }

TEST a_compiled_rule_set_reads_as_sing_box_decompiles_it(void) {
    static const char *const names[] = {"mixed", "legacy", "names", "skip"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        static char srs[64], dec[64];
        snprintf(srs, sizeof(srs), "%s.srs", names[i]);
        snprintf(dec, sizeof(dec), "%s.dec.json", names[i]);
        got_t a = parse_fixture(srs), b = parse_fixture(dec);
        ASSERT_EQ_FMTm(srs, FIRC_OK, a.err, "%d");
        ASSERT_EQ_FMTm(dec, FIRC_OK, b.err, "%d");
        char *ra = sorted_rows(&a), *rb = sorted_rows(&b);
        ASSERT_STR_EQm(srs, rb, ra);
        ASSERT_EQ_FMTm(srs, b.st.dropped, a.st.dropped, "%zu");
        ASSERT_EQ_FMTm(srs, b.st.unconstrained, a.st.unconstrained, "%zu");
        free(ra);
        free(rb);
        free_got(&a);
        free_got(&b);
    }
    PASS();
}

TEST every_mapped_item_of_a_compiled_rule_set_lands_as_its_firc_rule(void) {
    got_t g = parse_fixture("mixed.srs");
    ASSERT_EQ(FIRC_OK, g.err);
    char *rows = sorted_rows(&g);
    ASSERT_STR_EQ("domain a.example - -\n"
                  "domain constrained.example - -\n"
                  "domain exact.test - -\n"
                  "domain mixed.case.org - -\n"
                  "namespace example.com - -\n"
                  "namespace sub.example.org - -\n"
                  "regex ^ads[0-9]+\\.example\\.net$ - -\n"
                  "subnet 10.0.0.0/8 - -\n"
                  "subnet 172.16.0.0/12 - -\n"
                  "subnet 192.168.1.1/32 - -\n"
                  "subnet 198.51.100.7/32 tcp 53,853\n"
                  "subnet 198.51.100.7/32 udp 53,853\n"
                  "subnet 203.0.113.0/24 udp 50000-50099,19200-19400\n"
                  "subnet6 2001:db8::/32 - -\n"
                  "subnet6 ::ffff:1.2.3.4/128 - -\n"
                  "wildcard *tracker* - -\n",
                  rows);
    ASSERT_EQ_FMT((size_t)9, g.st.dropped, "%zu");
    ASSERT_EQ_FMT((size_t)1, g.st.unconstrained, "%zu");
    free(rows);
    free_got(&g);
    PASS();
}

TEST a_legacy_suffix_pair_is_one_namespace(void) {
    got_t g = parse_fixture("legacy.srs");
    ASSERT_EQ(FIRC_OK, g.err);
    char *rows = sorted_rows(&g);
    ASSERT_STR_EQ("domain plain.org - -\n"
                  "namespace both.net - -\n"
                  "namespace example.com - -\n"
                  "namespace only-sub.net - -\n",
                  rows);
    ASSERT_EQ_FMT((size_t)0, g.st.dropped, "%zu");
    free(rows);
    free_got(&g);
    PASS();
}

static bool firc_routes(const got_t *g, const char *name) {
    bool hit = false;
    for (size_t i = 0; i < g->rs.n && !hit; i++) {
        firc_rule_matcher_t *m = firc_rule_matcher_new(firc_sub_rules_type(&g->rs, i), firc_sub_rules_text(&g->rs, i));
        if (m == NULL) { continue; }
        hit = firc_rule_matcher_match(m, name);
        firc_rule_matcher_free(m);
    }
    return hit;
}

static char *disagreements(const char *srs, const char *oracle) {
    got_t g = parse_fixture(srs);
    bytes_t o = read_fixture(oracle);
    char *out = calloc(1, o.n + 1);
    if (g.err != FIRC_OK || o.p == NULL) {
        strcpy(out, "unreadable");
    } else {
        char *save = NULL;
        for (char *line = strtok_r((char *)o.p, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
            if (line[0] == '#') { continue; }
            char *sp = strrchr(line, ' ');
            *sp = '\0';
            bool want = sp[1] == '1';
            if (firc_routes(&g, line) != want) {
                strcat(out, line);
                strcat(out, " ");
            }
        }
    }
    free(o.p);
    free_got(&g);
    return out;
}

TEST adguard_rules_route_exactly_what_sing_box_matches(void) {
    char *d = disagreements("adguard.srs", "adguard.oracle");
    ASSERT_STR_EQ("", d);
    free(d);
    PASS();
}

TEST legacy_names_route_what_sing_box_matches_but_the_apex_of_a_dot_suffix(void) {
    char *d = disagreements("legacy.srs", "legacy.oracle");
    ASSERT_STR_EQ("only-sub.net ", d);
    free(d);
    PASS();
}

TEST names_route_what_sing_box_matches_but_the_apex_of_a_dot_suffix(void) {
    char *d = disagreements("names.srs", "names.oracle");
    ASSERT_STR_EQ("sub.example.org ", d);
    free(d);
    PASS();
}

TEST adguard_rules_take_the_narrowest_type_that_says_the_same(void) {
    got_t g = parse_fixture("adguard.srs");
    ASSERT_EQ(FIRC_OK, g.err);
    char *rows = sorted_rows(&g);
    ASSERT_STR_EQ("domain exact.example.org - -\n"
                  "domain host.example - -\n"
                  "namespace ads.example.com - -\n"
                  "regex (?:^|\\.)nocaret\\.example - -\n"
                  "regex (?:^|\\.)wild.*card\\.com$ - -\n"
                  "regex ^prefix-only - -\n"
                  "regex ^regex[0-9]+\\.example$ - -\n"
                  "regex example\\.info - -\n"
                  "regex tracker\\.net$ - -\n",
                  rows);
    ASSERT_EQ_FMT((size_t)0, g.st.dropped, "%zu");
    free(rows);
    free_got(&g);
    PASS();
}

TEST an_adguard_list_with_exceptions_is_dropped_whole(void) {
    got_t g = parse_fixture("adguard_exclude.srs");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    ASSERT_EQ_FMT((size_t)1, g.st.dropped, "%zu");
    free_got(&g);
    PASS();
}

TEST a_condition_firc_cannot_honour_is_skipped_to_the_next_rule(void) {
    got_t g = parse_fixture("skip.srs");
    ASSERT_EQ(FIRC_OK, g.err);
    char *rows = sorted_rows(&g);
    ASSERT_STR_EQ("namespace kept.example - -\n"
                  "subnet6 2001:db8:1::/48 - -\n",
                  rows);
    ASSERT_EQ_FMT((size_t)5, g.st.dropped, "%zu");
    free(rows);
    free_got(&g);
    PASS();
}

static bytes_t ab_rule(uint64_t bitmap, uint64_t leaves, const char *labels) {
    bytes_t raw = {0};
    put_uvarint(&raw, 1);
    put8(&raw, 0);
    put8(&raw, 2);
    put8(&raw, 0);
    put_uvarint(&raw, 1);
    put_be64(&raw, leaves);
    put_uvarint(&raw, 1);
    put_be64(&raw, bitmap);
    put_uvarint(&raw, strlen(labels));
    put(&raw, labels, strlen(labels));
    put8(&raw, 0xff);
    put8(&raw, 0);
    return raw;
}

TEST a_hand_built_trie_reads_and_a_broken_one_is_refused(void) {
    bytes_t raw = ab_rule(0x1A, 0x4, "ba");
    bytes_t body = srs_of(&raw, 2);
    got_t g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_OK, g.err);
    char *rows = sorted_rows(&g);
    ASSERT_STR_EQ("domain ab - -\n", rows);
    free(rows);
    free_got(&g);
    free(raw.p);
    free(body.p);

    raw = ab_rule(0x1B, 0x4, "ba");
    body = srs_of(&raw, 2);
    g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    free_got(&g);
    free(raw.p);
    free(body.p);

    raw = ab_rule(0x1A, 0x5, "ba");
    body = srs_of(&raw, 2);
    g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_EQ_FMT((size_t)1, g.st.dropped, "%zu");
    free_got(&g);
    free(raw.p);
    free(body.p);

    raw = ab_rule(0x1A, 0x4, "b");
    body = srs_of(&raw, 2);
    g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    free_got(&g);
    free(raw.p);
    free(body.p);
    PASS();
}

TEST a_key_deeper_than_any_name_is_one_drop(void) {
    enum { DEPTH = 400 };
    bytes_t raw = {0};
    put_uvarint(&raw, 1);
    put8(&raw, 0);
    put8(&raw, 2);
    put8(&raw, 0);
    size_t bits = 2 * DEPTH + 1, words = (bits + 63) / 64;
    uint64_t *bm = calloc(words, sizeof(uint64_t)), *lv = calloc(words, sizeof(uint64_t));
    for (size_t i = 0; i < DEPTH; i++) { bm[(2 * i + 1) / 64] |= 1ULL << ((2 * i + 1) % 64); }
    bm[(2 * DEPTH) / 64] |= 1ULL << ((2 * DEPTH) % 64);
    lv[DEPTH / 64] |= 1ULL << (DEPTH % 64);
    put_uvarint(&raw, words);
    for (size_t i = 0; i < words; i++) { put_be64(&raw, lv[i]); }
    put_uvarint(&raw, words);
    for (size_t i = 0; i < words; i++) { put_be64(&raw, bm[i]); }
    put_uvarint(&raw, DEPTH);
    for (size_t i = 0; i < DEPTH; i++) { put8(&raw, 'a'); }
    put8(&raw, 0xff);
    put8(&raw, 0);
    bytes_t body = srs_of(&raw, 2);
    got_t g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    ASSERT_EQ_FMT((size_t)1, g.st.dropped, "%zu");
    free_got(&g);
    free(bm);
    free(lv);
    free(raw.p);
    free(body.p);
    PASS();
}

TEST a_newer_version_is_refused_by_name(void) {
    bytes_t b = read_fixture("names.srs");
    ASSERT(b.n > 4);
    b.p[3] = 6;
    got_t g = parse_n(b.p, b.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(strstr(g.st.why, "version") != NULL);
    free_got(&g);
    free(b.p);
    PASS();
}

TEST a_cut_corrupt_or_padded_body_is_refused(void) {
    bytes_t b = read_fixture("mixed.srs");
    ASSERT(b.n > 16);
    got_t g = parse_n(b.p, b.n / 2);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    free_got(&g);

    g = parse_n(b.p, b.n - 4);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    free_got(&g);

    b.p[b.n - 1] ^= 0xff;
    g = parse_n(b.p, b.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    free_got(&g);
    b.p[b.n - 1] ^= 0xff;

    put8(&b, '\n');
    g = parse_n(b.p, b.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    free_got(&g);
    free(b.p);

    bytes_t raw = ab_rule(0x1A, 0x4, "ba");
    put8(&raw, 0);
    bytes_t body = srs_of(&raw, 2);
    g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    free_got(&g);
    free(raw.p);
    free(body.p);
    PASS();
}

TEST a_body_that_inflates_past_sixteen_mib_is_refused_unread(void) {
    bytes_t raw = {0};
    raw.cap = (16u << 20) + 2;
    raw.p = calloc(1, raw.cap);
    raw.n = (16u << 20) + 1;
    bytes_t body = srs_of(&raw, 2);
    got_t g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(strstr(g.st.why, "16 MiB") != NULL);
    free_got(&g);
    free(body.p);

    raw.n = 16u << 20;
    body = srs_of(&raw, 2);
    g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(strstr(g.st.why, "16 MiB") == NULL);
    free_got(&g);
    free(body.p);
    free(raw.p);
    PASS();
}

static bytes_t wide_ranges(size_t n, size_t regex_len) {
    bytes_t raw = {0};
    put_uvarint(&raw, 1);
    put8(&raw, 0);
    if (regex_len > 0) {
        put8(&raw, 4);
        put_uvarint(&raw, 1);
        put_uvarint(&raw, regex_len);
        for (size_t i = 0; i < regex_len; i++) { put8(&raw, 'a'); }
    }
    put8(&raw, 6);
    put8(&raw, 1);
    put_be64(&raw, n);
    static const uint8_t lo[4] = {0, 0, 0, 1}, hi[4] = {255, 255, 255, 254};
    for (size_t i = 0; i < n; i++) {
        put_uvarint(&raw, 4);
        put(&raw, lo, 4);
        put_uvarint(&raw, 4);
        put(&raw, hi, 4);
    }
    put8(&raw, 0xff);
    put8(&raw, 0);
    bytes_t body = srs_of(&raw, 2);
    free(raw.p);
    return body;
}

TEST a_list_holds_at_most_eight_mib_of_rule_text(void) {
    bytes_t body = wide_ranges(10034, 183);
    got_t g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)63, g.rs.n, "%zu");
    free_got(&g);
    free(body.p);

    body = wide_ranges(10034, 184);
    g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    free_got(&g);
    free(body.p);

    body = wide_ranges(10035, 0);
    g = parse_n(body.p, body.n);
    ASSERT_EQ(FIRC_ERR_INVAL, g.err);
    ASSERT(strstr(g.st.why, "too large") != NULL);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    free_got(&g);
    free(body.p);
    PASS();
}

static bool stop_at_first(void *ud, size_t n) {
    (void)n;
    ++*(int *)ud;
    return false;
}

TEST a_compiled_parse_reports_progress_and_can_be_stopped(void) {
    bytes_t body = wide_ranges(400, 0);
    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    firc_sub_parse_stats_t st;
    int calls = 0;
    ASSERT_EQ(FIRC_ERR_CANCELED, firc_sub_parse_rules_stats((const char *)body.p, body.n, &rs, &st, stop_at_first,
                                                            &calls));
    ASSERT_EQ(1, calls);
    ASSERT_EQ_FMT((size_t)0, rs.n, "%zu");
    free(body.p);
    PASS();
}

TEST text_that_starts_with_srs_is_still_a_line_list(void) {
    static const char body[] = "SRS.example.com\nsrs2.example.com\n";
    got_t g = parse_n(body, sizeof(body) - 1);
    ASSERT_EQ(FIRC_OK, g.err);
    char *rows = sorted_rows(&g);
    ASSERT_STR_EQ("namespace srs.example.com - -\n"
                  "namespace srs2.example.com - -\n",
                  rows);
    free(rows);
    free_got(&g);
    PASS();
}

enum { WRAP_DEFAULT, WRAP_DROPPED, WRAP_LOGICAL };

static void put_trie(bytes_t *raw, uint64_t bitmap) {
    put8(raw, 2);
    put8(raw, 0);
    put_uvarint(raw, 1);
    put_be64(raw, 0x4);
    put_uvarint(raw, 1);
    put_be64(raw, bitmap);
    put_uvarint(raw, 2);
    put(raw, "ba", 2);
}

static void put_range(bytes_t *raw, const uint8_t *from, size_t fl, const uint8_t *to, size_t tl) {
    put8(raw, 6);
    put8(raw, 1);
    put_be64(raw, 1);
    put_uvarint(raw, fl);
    put(raw, from, fl);
    put_uvarint(raw, tl);
    put(raw, to, tl);
}

static got_t parse_item(int wrap, void (*item)(bytes_t *, const void *), const void *arg) {
    bytes_t raw = {0};
    put_uvarint(&raw, 2);
    if (wrap == WRAP_LOGICAL) {
        put8(&raw, 1);
        put8(&raw, 1);
        put_uvarint(&raw, 1);
    }
    put8(&raw, 0);
    if (wrap == WRAP_DROPPED) {
        put8(&raw, 11);
        put_uvarint(&raw, 1);
        put_uvarint(&raw, 4);
        put(&raw, "curl", 4);
    }
    item(&raw, arg);
    put8(&raw, 0xff);
    put8(&raw, 0);
    if (wrap == WRAP_LOGICAL) { put8(&raw, 0); }
    put8(&raw, 0);
    put_trie(&raw, 0x1A);
    put8(&raw, 0xff);
    put8(&raw, 0);
    bytes_t body = srs_of(&raw, 2);
    got_t g = parse_n(body.p, body.n);
    free(raw.p);
    free(body.p);
    return g;
}

static void item_trie(bytes_t *raw, const void *arg) { put_trie(raw, *(const uint64_t *)arg); }

typedef struct range_arg {
    const uint8_t *from;
    size_t fl;
    const uint8_t *to;
    size_t tl;
} range_arg_t;

static void item_range(bytes_t *raw, const void *arg) {
    const range_arg_t *r = arg;
    put_range(raw, r->from, r->fl, r->to, r->tl);
}

TEST a_broken_trie_anywhere_refuses_the_body(void) {
    static const uint64_t good = 0x1A, bad = 0x1B;
    for (int wrap = WRAP_DEFAULT; wrap <= WRAP_LOGICAL; wrap++) {
        got_t g = parse_item(wrap, item_trie, &good);
        ASSERT_EQ_FMT((int)FIRC_OK, (int)g.err, "%d");
        ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
        free_got(&g);
        g = parse_item(wrap, item_trie, &bad);
        ASSERT_EQ_FMT((int)FIRC_ERR_INVAL, (int)g.err, "%d");
        ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
        free_got(&g);
    }
    PASS();
}

TEST a_reversed_or_mixed_range_anywhere_refuses_the_body(void) {
    static const uint8_t lo[4] = {10, 0, 0, 1}, hi[4] = {10, 0, 0, 2};
    static const uint8_t lo6[16] = {0x20, 0x01, 0x0d, 0xb8};
    const range_arg_t ok = {lo, 4, hi, 4}, reversed = {hi, 4, lo, 4}, mixed = {lo, 4, lo6, 16};
    for (int wrap = WRAP_DEFAULT; wrap <= WRAP_LOGICAL; wrap++) {
        got_t g = parse_item(wrap, item_range, &ok);
        ASSERT_EQ_FMT((int)FIRC_OK, (int)g.err, "%d");
        ASSERT_EQ_FMT(wrap == WRAP_DEFAULT ? (size_t)3 : (size_t)1, g.rs.n, "%zu");
        free_got(&g);
        g = parse_item(wrap, item_range, &reversed);
        ASSERT_EQ_FMT((int)FIRC_ERR_INVAL, (int)g.err, "%d");
        free_got(&g);
        g = parse_item(wrap, item_range, &mixed);
        ASSERT_EQ_FMT((int)FIRC_ERR_INVAL, (int)g.err, "%d");
        free_got(&g);
    }
    PASS();
}

TEST a_refresh_reads_a_compiled_body_as_the_parse_does(void) {
    bytes_t b = read_fixture("names.srs");
    got_t parsed = parse_n(b.p, b.n);
    ASSERT_EQ(FIRC_OK, parsed.err);
    got_t refreshed;
    memset(&refreshed, 0, sizeof(refreshed));
    firc_sub_rules_init(&refreshed.rs);
    firc_sub_rules_t none;
    firc_sub_rules_init(&none);
    ASSERT_EQ(FIRC_OK, firc_sub_refresh_rules((const char *)b.p, b.n, &none, &refreshed.rs));
    char *want = sorted_rows(&parsed), *have = sorted_rows(&refreshed);
    ASSERT(parsed.rs.n > 0);
    ASSERT_STR_EQ(want, have);
    free(want);
    free(have);
    free_got(&parsed);
    free_got(&refreshed);
    free(b.p);
    PASS();
}

TEST only_the_magic_and_a_version_byte_make_a_body_binary(void) {
    ASSERT(firc_sub_body_is_srs("SRS\x01", 4));
    ASSERT(firc_sub_body_is_srs("SRS\x05" "x", 5));
    ASSERT(!firc_sub_body_is_srs("SRS", 3));
    ASSERT(!firc_sub_body_is_srs("SRS.", 4));
    ASSERT(!firc_sub_body_is_srs("SRS\n", 4));
    ASSERT(!firc_sub_body_is_srs("srs\x01", 4));
    ASSERT(!firc_sub_body_is_srs("XSRS\x01", 5));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_compiled_rule_set_reads_as_sing_box_decompiles_it);
    RUN_TEST(every_mapped_item_of_a_compiled_rule_set_lands_as_its_firc_rule);
    RUN_TEST(a_legacy_suffix_pair_is_one_namespace);
    RUN_TEST(adguard_rules_route_exactly_what_sing_box_matches);
    RUN_TEST(legacy_names_route_what_sing_box_matches_but_the_apex_of_a_dot_suffix);
    RUN_TEST(names_route_what_sing_box_matches_but_the_apex_of_a_dot_suffix);
    RUN_TEST(adguard_rules_take_the_narrowest_type_that_says_the_same);
    RUN_TEST(an_adguard_list_with_exceptions_is_dropped_whole);
    RUN_TEST(a_condition_firc_cannot_honour_is_skipped_to_the_next_rule);
    RUN_TEST(a_hand_built_trie_reads_and_a_broken_one_is_refused);
    RUN_TEST(a_key_deeper_than_any_name_is_one_drop);
    RUN_TEST(a_newer_version_is_refused_by_name);
    RUN_TEST(a_cut_corrupt_or_padded_body_is_refused);
    RUN_TEST(a_body_that_inflates_past_sixteen_mib_is_refused_unread);
    RUN_TEST(a_list_holds_at_most_eight_mib_of_rule_text);
    RUN_TEST(a_compiled_parse_reports_progress_and_can_be_stopped);
    RUN_TEST(text_that_starts_with_srs_is_still_a_line_list);
    RUN_TEST(only_the_magic_and_a_version_byte_make_a_body_binary);
    RUN_TEST(a_broken_trie_anywhere_refuses_the_body);
    RUN_TEST(a_reversed_or_mixed_range_anywhere_refuses_the_body);
    RUN_TEST(a_refresh_reads_a_compiled_body_as_the_parse_does);
    GREATEST_MAIN_END();
}

/* Byte-for-byte stability of the ClientHello: a guard for changes to reality.c.
 *
 * The Chrome fingerprint is what lets a Reality server tell us from a stranger, and a deliberate
 * change to it is checked by a capture next to a real browser. A capture needs a network, a
 * server and eyes; this test needs only a compiler. It does not replace the capture: it catches
 * an UNINTENDED change, an edit "nearby" that leaked into the built Hello unnoticed.
 *
 * The Hello is a function of randomness, time and the cipher order. Randomness comes from a
 * deterministic generator (os_getrandom is redefined by a macro BEFORE the source is included, so
 * the key pair, the extension shuffle and all the noise are covered), time is fixed, and the
 * cipher order, which depends on the CPU, is pinned with STEER_CIPHER.
 *
 * The Hello is really built (X25519 and the authenticator's AES-GCM go through src/lib/scrypto.h),
 * so the test needs the crypto library and runs in `make crypto-test`:
 *
 *     make crypto-test                   # builds it and compares with tests/chello-frozen.h
 *     ./out/tests/hellofreeze --emit > tests/chello-frozen.h   # refreeze
 *
 * Refreeze ONLY together with a capture next to a browser: a freeze records whatever is there and
 * would silently legitimize a broken fingerprint. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
/* The declaration first: the macro below would otherwise rewrite it too. */
#include "osrand.h"

/* Deterministic getrandom. Changing the generator changes the reference, i.e. needs a refreeze. */
static uint64_t prng = 0x123456789ABCDEFull;
static unsigned g_calls;
static void prng_step(void) { prng = prng * 6364136223846793005ull + 1442695040888963407ull; }

/* Why the generator skips 128 bytes.
 *
 * The frozen Hello was made with mbedtls, which blinded each X25519 multiplication (randomized
 * projective coordinates) with bytes from the same source as the rest of the Hello: 64 per
 * multiplication, and building a Hello takes two (the public key, and the secret with the
 * server's pbk). wolfCrypt behind scrypto blinds (where it does: portable C,
 * WOLFSSL_CURVE25519_BLINDING) from ITS OWN generator, so none of that reaches this stream. In
 * real use this changes nothing, but the test's deterministic stream would be 128 bytes off, and
 * every Hello byte after the key (random, GREASE, ECH padding, extension shuffle) would differ
 * though the builder had not changed.
 *
 * So the generator skips those 128 bytes where they were drawn: right after the first call (the
 * 32-byte private key, x25519_keypair), before the second. With the skip the current code gives
 * the frozen Hello byte for byte. If the calls in reality.c move, the test turns red, and it
 * should: such a change needs the same analysis. */
#define MBEDTLS_BLINDING_BYTES 128
static ssize_t det_getrandom(void *buf, size_t n, unsigned int flags) {
    (void)flags;
    if (++g_calls == 2)
        for (int i = 0; i < MBEDTLS_BLINDING_BYTES; i++) prng_step();
    unsigned char *p = buf;
    for (size_t i = 0; i < n; i++) {
        prng_step();
        p[i] = (unsigned char)(prng >> 33);
    }
    return (ssize_t)n;
}
static time_t det_time(time_t *p) { (void)p; return (time_t)1700000000; }

#include "scrypto.h"
static int g_poison_left;
static unsigned char g_p256_drawn[32];
static int det_p256_pub(const unsigned char seed[32], unsigned char pub[65]) {
    if (g_poison_left > 0) {
        unsigned char above_n[32];
        memset(above_n, 0xff, sizeof above_n);
        g_poison_left--;
        return sc_p256_pub(above_n, pub);
    }
    memcpy(g_p256_drawn, seed, 32);
    return sc_p256_pub(seed, pub);
}

static const unsigned char *g_seed_at;
static int g_seed_wiped;
static int det_keygen(unsigned char *ek, unsigned char *dk, const unsigned char *seed) {
    g_seed_at = seed;
    g_seed_wiped = 0;
    return sc_mlkem768_keygen(ek, dk, seed);
}
static void det_wipe(void *p, size_t n) {
    sc_wipe(p, n);
    if (p != g_seed_at || n != SC_MLKEM768_SEED) return;
    size_t left = 0;
    for (size_t i = 0; i < n; i++) left += ((const unsigned char *)p)[i] != 0;
    g_seed_wiped = left == 0;
}

#define os_getrandom(b, n, f) det_getrandom((b), (n), (f))
#define time(p) det_time(p)
#define sc_p256_pub(s, p) det_p256_pub((s), (p))
#define sc_mlkem768_keygen(e, d, s) det_keygen((e), (d), (s))
#define sc_wipe(p, n) det_wipe((p), (n))
#include "../src/proto/tls/reality.c"
#undef os_getrandom
#undef time
#undef sc_p256_pub
#undef sc_mlkem768_keygen
#undef sc_wipe

#include "chello-frozen.h"
#include "chello-frozen-pq.h"
#include "chello-frozen-firefox.h"

static const struct reality_cfg CFG = {
    .sni = "www.example.com",
    .pbk = "xNlHRs0RY8mJhMhOVWRxg8ykpZmqHrjKQqm3-1lQF3E",
    .sid = "0123456789abcdef",
    .fp  = "chrome",
    .alpn = "h2",
};

/* The same with the real X25519MLKEM768 hybrid (reality_cfg.pq), as Chrome 131+ sends it. The
 * ML-KEM key is made from a seed drawn from the same deterministic source, so the bytes are
 * reproducible. */
static const struct reality_cfg CFG_PQ = {
    .sni = "www.example.com",
    .pbk = "xNlHRs0RY8mJhMhOVWRxg8ykpZmqHrjKQqm3-1lQF3E",
    .sid = "0123456789abcdef",
    .fp  = "chrome",
    .alpn = "h2",
    .pq = 1,
};

static const struct reality_cfg CFG_FF = {
    .sni = "www.example.com",
    .pbk = "xNlHRs0RY8mJhMhOVWRxg8ykpZmqHrjKQqm3-1lQF3E",
    .sid = "0123456789abcdef",
    .fp  = "firefox",
    .alpn = "h2",
    .pq = 1,
};

static size_t build_seeded(const struct reality_cfg *cfg, const char *cipher, uint64_t seed,
                           unsigned char *out, size_t cap) {
    setenv("STEER_CIPHER", cipher, 1);
    prng = seed;
    g_calls = 0;
    struct reality_state st;
    size_t n = 0;
    if (reality_build_hello(cfg, &st, out, cap, &n) != 0) return 0;
    return n;
}
static size_t build_cfg(const struct reality_cfg *cfg, const char *cipher,
                        unsigned char *out, size_t cap) {
    return build_seeded(cfg, cipher, 0x123456789ABCDEFull, out, cap);
}
static size_t build(const char *cipher, unsigned char *out, size_t cap) {
    return build_cfg(&CFG, cipher, out, cap);
}

/* The extension types of a built Hello (a whole record), in order; returns their number. */
static size_t ext_types(const unsigned char *h, size_t n, unsigned *t, size_t cap) {
    size_t p = 5 + 4 + 2 + 32, k = 0;
    p += 1 + h[p];                                          /* session_id */
    p += 2 + ((size_t)h[p] << 8 | h[p + 1]);                /* cipher suites */
    p += 1 + h[p];                                          /* compression */
    size_t end = p + 2 + ((size_t)h[p] << 8 | h[p + 1]);
    for (p += 2; p + 4 <= end && end <= n && k < cap; p += 4 + ((size_t)h[p + 2] << 8 | h[p + 3]))
        t[k++] = (unsigned)h[p] << 8 | h[p + 1];
    return k;
}
struct extv { const unsigned char *p; size_t n; int count; };
static struct extv find_ext(const unsigned char *h, size_t n, unsigned type) {
    struct extv e = { NULL, 0, 0 };
    size_t p = 5 + 4 + 2 + 32;
    p += 1 + h[p];
    p += 2 + ((size_t)h[p] << 8 | h[p + 1]);
    p += 1 + h[p];
    size_t end = p + 2 + ((size_t)h[p] << 8 | h[p + 1]);
    for (p += 2; p + 4 <= end && end <= n; p += 4 + ((size_t)h[p + 2] << 8 | h[p + 3])) {
        if (((unsigned)h[p] << 8 | h[p + 1]) != type) continue;
        if (!e.count++) { e.p = h + p + 4; e.n = (size_t)h[p + 2] << 8 | h[p + 3]; }
    }
    return e;
}
static size_t suites_of(const unsigned char *h, unsigned *s, size_t cap) {
    size_t p = 5 + 4 + 2 + 32;
    p += 1 + h[p];
    size_t n = ((size_t)h[p] << 8 | h[p + 1]) / 2, k = 0;
    for (p += 2; k < n && k < cap; k++, p += 2) s[k] = (unsigned)h[p] << 8 | h[p + 1];
    return k;
}
static int body_is(struct extv e, const char *hex) {
    size_t n = strlen(hex) / 2;
    if (e.count != 1 || e.n != n) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || e.p[i] != v) return 0;
    }
    return 1;
}
static int plain_chrome_offers_brotli(void) {
    struct reality_cfg cfg = CFG;
    cfg.plain = 1;
    cfg.pbk = cfg.sid = NULL;
    unsigned char h[4096];
    size_t n = build_cfg(&cfg, "aes", h, sizeof(h));
    return n && body_is(find_ext(h, n, 0x001B), "020002");
}
static int is_grease(unsigned v) { return (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF); }

static int verdict(int good, const char *what) {
    printf("%-62s %s\n", what, good ? "ok" : "FAIL");
    return !good;
}

static const unsigned FF_ORDER[] = {
    0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0010, 0x0005, 0x0022,
    0x0012, 0x0033, 0x002B, 0x000D, 0x001C, 0x001B, 0xFE0D,
};
static const unsigned FF_SUITES[] = {
    0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030,
    0xC00A, 0xC009, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
};
#define FF_NEXT (sizeof(FF_ORDER) / sizeof(FF_ORDER[0]))
#define FF_NSUITES (sizeof(FF_SUITES) / sizeof(FF_SUITES[0]))

static size_t build_ff_state(const struct reality_cfg *cfg, const struct reality_carrier *car,
                             uint64_t seed, struct reality_state *st, unsigned char *out, size_t cap) {
    setenv("STEER_CIPHER", "aes", 1);
    prng = seed;
    g_calls = 0;
    size_t n = 0;
    if (reality_build_hello_carry(cfg, st, car, out, cap, &n) != 0) return 0;
    return n;
}

/* Catches a Firefox Hello that moved by a bit, one whose suites follow the CPU, or a shape picked by an exact "firefox" match. */
static int ff_hello_matches_the_frozen_bytes(void) {
    unsigned char a[4096], c[4096], m[4096];
    struct reality_cfg mixed = CFG_FF;
    mixed.fp = "FireFox";
    size_t an = build_cfg(&CFG_FF, "aes", a, sizeof a);
    size_t cn = build_cfg(&CFG_FF, "chacha", c, sizeof c);
    size_t mn = build_cfg(&mixed, "aes", m, sizeof m);
    int bad = 0;
    bad += verdict(an == FROZEN_FF_N && !memcmp(a, FROZEN_FF, an), "Firefox Hello: byte for byte as frozen");
    bad += verdict(cn == FROZEN_FF_N && !memcmp(c, FROZEN_FF, cn), "Firefox Hello: the same without AES hardware");
    bad += verdict(mn == FROZEN_FF_N && !memcmp(m, FROZEN_FF, mn), "Firefox Hello: fp=FireFox gives it too");
    return bad;
}

/* Catches GREASE or a shuffle in the Firefox Hello, or suites and extensions apart from the uTLS capture. */
static int ff_hello_has_no_grease_and_a_fixed_order(void) {
    int bad = 0;
    for (uint64_t seed = 1; seed <= 256; seed++) {
        unsigned char h[4096];
        unsigned t[32], su[32];
        size_t n = build_seeded(&CFG_FF, "aes", seed, h, sizeof h);
        if (!n) { bad++; continue; }
        size_t k = ext_types(h, n, t, 32), ns = suites_of(h, su, 32);
        bad += k != FF_NEXT || ns != FF_NSUITES;
        for (size_t i = 0; i < k && i < FF_NEXT; i++) bad += t[i] != FF_ORDER[i] || is_grease(t[i]);
        for (size_t i = 0; i < ns && i < FF_NSUITES; i++) bad += su[i] != FF_SUITES[i] || is_grease(su[i]);
        struct extv g = find_ext(h, n, 0x000A), v = find_ext(h, n, 0x002B);
        for (size_t i = 2; g.p && i + 1 < g.n; i += 2) bad += is_grease((unsigned)g.p[i] << 8 | g.p[i + 1]);
        for (size_t i = 1; v.p && i + 1 < v.n; i += 2) bad += is_grease((unsigned)v.p[i] << 8 | v.p[i + 1]);
        bad += !g.p || !v.p;
    }
    return verdict(!bad, "256 Firefox Hellos: no GREASE, the capture's order");
}

/* Catches a key_share apart from Firefox's: order, sizes, a separate X25519 key, or a compressed P-256 point. */
static int ff_key_share_is_hybrid_x25519_p256(void) {
    unsigned char h[4096];
    size_t n = build_cfg(&CFG_FF, "aes", h, sizeof h);
    struct extv e = n ? find_ext(h, n, 0x0033) : (struct extv){ NULL, 0, 0 };
    static const unsigned want_g[] = { 0x11EC, 0x001D, 0x0017 };
    static const size_t want_l[] = { 1216, 32, 65 };
    const unsigned char *share[3] = { NULL, NULL, NULL };
    int good = e.count == 1 && e.n >= 2 && ((size_t)e.p[0] << 8 | e.p[1]) == e.n - 2;
    size_t q = 2, k = 0;
    while (good && q + 4 <= e.n && k < 3) {
        unsigned g = (unsigned)e.p[q] << 8 | e.p[q + 1];
        size_t l = (size_t)e.p[q + 2] << 8 | e.p[q + 3];
        good = g == want_g[k] && l == want_l[k] && q + 4 + l <= e.n;
        share[k++] = e.p + q + 4;
        q += 4 + l;
    }
    good = good && k == 3 && q == e.n;
    int bad = verdict(good, "Firefox key_share: hybrid 1216, X25519 32, P-256 65");
    bad += verdict(good && !memcmp(share[1], share[0] + 1184, 32), "Firefox key_share: X25519 is the hybrid's own half");
    bad += verdict(good && share[2][0] == 0x04, "Firefox key_share: P-256 point uncompressed");
    return bad;
}

/* Catches a P-256 share that is not a point on the curve, in the frozen Hello or a fresh one. */
static int ff_p256_share_is_on_the_curve(void) {
    const size_t at = 2 + 4 + 1216 + 4 + 32 + 4;
    struct extv f = find_ext((const unsigned char *)FROZEN_FF, FROZEN_FF_N, 0x0033);
    int bad = verdict(f.count == 1 && f.n == at + 65 && sc_p256_on_curve(f.p + at) == 0,
                      "frozen Firefox Hello: P-256 share on the curve");
    int fresh = 1;
    for (uint64_t seed = 1; seed <= 64; seed++) {
        unsigned char h[4096];
        size_t n = build_seeded(&CFG_FF, "aes", seed, h, sizeof h);
        struct extv e = n ? find_ext(h, n, 0x0033) : (struct extv){ NULL, 0, 0 };
        fresh = fresh && e.count == 1 && e.n == at + 65 && sc_p256_on_curve(e.p + at) == 0;
    }
    bad += verdict(fresh, "64 Firefox Hellos: P-256 share on the curve");
    return bad;
}

/* Catches the ML-KEM seed, the decapsulation key's d and z, left on the stack after the Hello is built. */
static int mlkem_seed_is_wiped(void) {
    unsigned char h[4096];
    g_seed_at = NULL;
    size_t cn = build_cfg(&CFG_PQ, "aes", h, sizeof h);
    int chrome = cn && g_seed_at && g_seed_wiped;
    g_seed_at = NULL;
    size_t fn = build_cfg(&CFG_FF, "aes", h, sizeof h);
    int firefox = fn && g_seed_at && g_seed_wiped;
    int bad = verdict(chrome, "Chrome hybrid Hello: ML-KEM seed zeroed after keygen");
    bad += verdict(firefox, "Firefox Hello: ML-KEM seed zeroed after keygen");
    return bad;
}

/* Catches an extension body of the Firefox Hello that differs from the uTLS capture. */
static int ff_small_extensions_match_the_capture(void) {
    unsigned char h[4096];
    size_t n = build_cfg(&CFG_FF, "aes", h, sizeof h);
    static const struct { unsigned type; const char *hex; } want[] = {
        { 0x0000, "001200000f7777772e6578616d706c652e636f6d" },
        { 0x0017, "" },
        { 0xFF01, "00" },
        { 0x000A, "000e11ec001d00170018001901000101" },
        { 0x000B, "0100" },
        { 0x0010, "000c02683208687474702f312e31" },
        { 0x0005, "0100000000" },
        { 0x0022, "00080403050306030203" },
        { 0x0012, "" },
        { 0x002B, "0403040303" },
        { 0x000D, "001604030503060308040805080604010501060102030201" },
        { 0x001C, "4001" },
    };
    int bad = 0;
    for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) bad += !n || !body_is(find_ext(h, n, want[i].type), want[i].hex);
    return verdict(!bad, "Firefox extension bodies as in the uTLS capture");
}

/* Catches Firefox offering Chrome's brotli alone, on Reality or on plain TLS. */
static int ff_offers_three_certificate_compressions(void) {
    struct reality_cfg plain = CFG_FF;
    plain.plain = 1;
    plain.pbk = plain.sid = NULL;
    unsigned char r[4096], p[4096];
    size_t rn = build_cfg(&CFG_FF, "aes", r, sizeof r), pn = build_cfg(&plain, "aes", p, sizeof p);
    int bad = verdict(rn && body_is(find_ext(r, rn, 0x001B), "06000100020003"), "Firefox Reality Hello offers zlib, brotli, zstd");
    bad += verdict(pn && body_is(find_ext(p, pn, 0x001B), "06000100020003"), "Firefox plain-TLS Hello offers zlib, brotli, zstd");
    return bad;
}

/* Catches a Hello whose compress_certificate list is written apart from reality_cert_algs, so the check of what was offered drifts from the offer. */
static int every_shape_offers_reality_cert_algs(void) {
    struct reality_cfg plain = CFG, ffplain = CFG_FF;
    plain.plain = ffplain.plain = 1;
    plain.pbk = plain.sid = ffplain.pbk = ffplain.sid = NULL;
    const struct { const struct reality_cfg *cfg; const char *name; } shapes[] = {
        { &CFG, "Chrome Reality" }, { &CFG_PQ, "Chrome Reality, hybrid" }, { &plain, "Chrome plain TLS" },
        { &CFG_FF, "Firefox Reality" }, { &ffplain, "Firefox plain TLS" },
    };
    int bad = 0;
    for (size_t i = 0; i < sizeof shapes / sizeof shapes[0]; i++) {
        unsigned char h[4096];
        size_t n = build_cfg(shapes[i].cfg, "aes", h, sizeof h);
        struct extv e = n ? find_ext(h, n, 0x001B) : (struct extv){ NULL, 0, 0 };
        unsigned mask = 0, count = 0, want = reality_cert_algs(reality_fp_of(shapes[i].cfg->fp));
        int good = e.count == 1 && e.n >= 3 && e.p[0] == e.n - 1 && !(e.p[0] & 1);
        for (size_t q = 1; good && q + 1 < e.n; q += 2, count++) {
            unsigned alg = (unsigned)e.p[q] << 8 | e.p[q + 1];
            good = alg < 32 && !(mask & 1u << alg);
            mask |= alg < 32 ? 1u << alg : 0;
        }
        char what[96];
        snprintf(what, sizeof what, "%s: compress_certificate is reality_cert_algs", shapes[i].name);
        bad += verdict(good && want && mask == want && count == (unsigned)__builtin_popcount(want), what);
    }
    return bad;
}

/* Catches a Firefox Hello cut short by pq = 0, or one that offers the hybrid without its ML-KEM key. */
static int ff_ignores_pq_off(void) {
    struct reality_cfg off = CFG_FF;
    off.pq = 0;
    unsigned char a[4096], b[4096];
    struct reality_state sa, sb;
    size_t an = build_ff_state(&CFG_FF, NULL, 0x123456789ABCDEFull, &sa, a, sizeof a);
    size_t bn = build_ff_state(&off, NULL, 0x123456789ABCDEFull, &sb, b, sizeof b);
    int bad = verdict(an && an == bn && !memcmp(a, b, an), "Firefox Hello: pq = 0 gives the same bytes");
    bad += verdict(sa.pq == 1 && sb.pq == 1, "Firefox Hello: the ML-KEM key is kept either way");
    return bad;
}

/* Catches Firefox's ECH GREASE with Chrome's payload, a fixed AEAD, or an AEAD outside its two. */
static int ff_ech_grease_picks_either_aead(void) {
    int bad = 0, seen1 = 0, seen3 = 0;
    for (uint64_t seed = 1; seed <= 256; seed++) {
        unsigned char h[4096];
        size_t n = build_seeded(&CFG_FF, "aes", seed, h, sizeof h);
        struct extv e = n ? find_ext(h, n, 0xFE0D) : (struct extv){ NULL, 0, 0 };
        if (e.count != 1 || e.n != 281) { bad++; continue; }
        unsigned aead = (unsigned)e.p[3] << 8 | e.p[4];
        seen1 += aead == 0x0001;
        seen3 += aead == 0x0003;
        bad += e.p[0] != 0 || e.p[1] != 0 || e.p[2] != 1 || (aead != 1 && aead != 3);
        bad += e.p[6] != 0 || e.p[7] != 32 || e.p[40] != 0 || e.p[41] != 239;
    }
    return verdict(!bad && seen1 && seen3, "256 Firefox Hellos: ECH 239 B, AES-128-GCM or ChaCha20");
}

/* Catches a fingerprint read other than "firefox" in any case, or a Chrome Hello lost to a stray fp. */
static int fp_of_reads_firefox_in_any_case(void) {
    int bad = 0;
    bad += reality_fp_of("firefox") != REALITY_FP_FIREFOX;
    bad += reality_fp_of("FIREFOX") != REALITY_FP_FIREFOX;
    bad += reality_fp_of("Firefox") != REALITY_FP_FIREFOX;
    bad += reality_fp_of("chrome") != REALITY_FP_CHROME;
    bad += reality_fp_of("edge") != REALITY_FP_CHROME;
    bad += reality_fp_of("") != REALITY_FP_CHROME;
    bad += reality_fp_of(NULL) != REALITY_FP_CHROME;
    bad += reality_fp_of("firefox1") != REALITY_FP_CHROME;
    bad += reality_fp_of("firefo") != REALITY_FP_CHROME;
    bad += reality_fp_of("safari") != REALITY_FP_CHROME;
    int fails = verdict(!bad, "fp: firefox in any case, anything else Chrome");
    const char *others[] = { NULL, "", "safari", "random" };
    int chrome = 1;
    for (size_t i = 0; i < sizeof others / sizeof others[0]; i++) {
        struct reality_cfg cfg = CFG;
        cfg.fp = others[i];
        unsigned char h[4096];
        size_t n = build_cfg(&cfg, "aes", h, sizeof h);
        chrome = chrome && n == FROZEN_N && !memcmp(h, FROZEN_AES, n);
    }
    fails += verdict(chrome, "fp NULL, empty, safari, random: the Chrome Hello as frozen");
    return fails;
}

/* Catches the ws/httpupgrade carrier lost on Firefox, or one that changes its extension order. */
static int ff_carrier_offers_http11_alone(void) {
    struct reality_carrier car = { .alpn_http11 = 1 };
    struct reality_state st;
    unsigned char h[4096];
    unsigned t[32];
    size_t n = build_ff_state(&CFG_FF, &car, 0x123456789ABCDEFull, &st, h, sizeof h);
    size_t k = n ? ext_types(h, n, t, 32) : 0;
    int order = k == FF_NEXT;
    for (size_t i = 0; order && i < k; i++) order = t[i] == FF_ORDER[i];
    return verdict(n && order && body_is(find_ext(h, n, 0x0010), "000908687474702f312e31"),
                   "Firefox Hello for ws: http/1.1 alone, the same order");
}

/* Catches a P-256 scalar refused once ending the Firefox Hello, or a redraw bound other than four. */
static int ff_p256_redraws_a_refused_scalar(void) {
    unsigned char h[4096], pub[65];
    g_poison_left = 3;
    size_t n = build_cfg(&CFG_FF, "aes", h, sizeof h);
    int used = g_poison_left == 0;
    struct extv e = n ? find_ext(h, n, 0x0033) : (struct extv){ NULL, 0, 0 };
    const size_t at = 2 + 4 + 1216 + 4 + 32 + 4;
    int good = n == FROZEN_FF_N && used && e.count == 1 && e.n == at + 65 &&
               sc_p256_pub(g_p256_drawn, pub) == 0 && !memcmp(e.p + at, pub, 65);
    int bad = verdict(good, "Firefox Hello: three refused P-256 scalars redrawn");
    g_poison_left = 4;
    size_t m = build_cfg(&CFG_FF, "aes", h, sizeof h);
    bad += verdict(m == 0 && g_poison_left == 0, "Firefox Hello: a fourth refused scalar ends it");
    g_poison_left = 0;
    return bad;
}

static void emit(const char *name, const unsigned char *b, size_t n) {
    printf("static const char %s[] =\n    \"", name);
    for (size_t i = 0; i < n; i++) {
        printf("\\x%02x", b[i]);
        if ((i + 1) % 16 == 0 && i + 1 < n) printf("\"\n    \"");
    }
    printf("\";\n\n");
}

int main(int argc, char **argv) {
    unsigned char a[4096], c[4096];
    if (argc > 2 && !strcmp(argv[1], "--raw-ff")) {
        size_t n = build_cfg(&CFG_FF, "aes", a, sizeof(a));
        FILE *f = fopen(argv[2], "wb");
        if (!n || !f) return 2;
        fwrite(a, 1, n, f);
        fclose(f);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--emit-ff")) {
        size_t fa = build_cfg(&CFG_FF, "aes", a, sizeof(a));
        if (!fa) { puts("building the Firefox Hello failed"); return 2; }
        puts("/* Generated by tests/hellofreeze.c --emit-ff: the Firefox 148 Hello. */");
        puts("#ifndef STEER_CHELLO_FROZEN_FIREFOX_H\n#define STEER_CHELLO_FROZEN_FIREFOX_H\n");
        emit("FROZEN_FF", a, fa);
        printf("#define FROZEN_FF_N %zu\n\n#endif\n", fa);
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "--raw-pq")) {           /* for tests/hello-diff.py (uTLS) */
        size_t n = build_cfg(&CFG_PQ, "aes", a, sizeof(a));
        FILE *f = fopen(argv[2], "wb");
        if (!n || !f) return 2;
        fwrite(a, 1, n, f);
        fclose(f);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--emit-pq")) {
        size_t pa = build_cfg(&CFG_PQ, "aes", a, sizeof(a)), pc = build_cfg(&CFG_PQ, "chacha", c, sizeof(c));
        if (!pa || !pc) { puts("building the hybrid Hello failed"); return 2; }
        puts("/* Generated by tests/hellofreeze.c --emit-pq: the Hello with X25519MLKEM768. */");
        puts("#ifndef STEER_CHELLO_FROZEN_PQ_H\n#define STEER_CHELLO_FROZEN_PQ_H\n");
        emit("FROZEN_PQ_AES", a, pa);
        emit("FROZEN_PQ_CHACHA", c, pc);
        printf("#define FROZEN_PQ_N %zu\n\n#endif\n", pa);
        return 0;
    }
    size_t an = build("aes", a, sizeof(a));
    size_t cn = build("chacha", c, sizeof(c));
    if (!an || !cn) { puts("building the Hello failed"); return 2; }

    if (argc > 1 && !strcmp(argv[1], "--emit")) {
        puts("/* Generated by tests/hellofreeze.c --emit; see that file's header. */");
        puts("#ifndef STEER_CHELLO_FROZEN_H\n#define STEER_CHELLO_FROZEN_H\n");
        emit("FROZEN_AES", a, an);
        emit("FROZEN_CHACHA", c, cn);
        printf("#define FROZEN_N %zu\n\n#endif\n", an);
        return 0;
    }

    int fails = 0;
    if (an != FROZEN_N || memcmp(a, FROZEN_AES, an) != 0) {
        printf("FAIL: Hello (aes) differs from the frozen copy (%zu vs %d bytes)\n",
               an, FROZEN_N);
        for (size_t i = 0; i < an && i < FROZEN_N; i++)
            if (a[i] != (unsigned char)FROZEN_AES[i]) {
                printf("  first difference at byte %zu: %02x vs %02x\n",
                       i, a[i], (unsigned char)FROZEN_AES[i]);
                break;
            }
        fails++;
    } else {
        printf("%-62s ok\n", "Hello (aes): byte for byte as frozen");
    }
    if (cn != FROZEN_N || memcmp(c, FROZEN_CHACHA, cn) != 0) {
        printf("FAIL: Hello (chacha) differs from the frozen copy\n");
        fails++;
    } else {
        printf("%-62s ok\n", "Hello (chacha): byte for byte as frozen");
    }
    {
        unsigned char pa[4096], pc[4096];
        size_t pan = build_cfg(&CFG_PQ, "aes", pa, sizeof(pa)), pcn = build_cfg(&CFG_PQ, "chacha", pc, sizeof(pc));
        if (pan != FROZEN_PQ_N || memcmp(pa, FROZEN_PQ_AES, pan) != 0) {
            printf("FAIL: hybrid Hello (aes) differs from the frozen copy (%zu vs %d bytes)\n", pan, FROZEN_PQ_N);
            fails++;
        } else printf("%-62s ok\n", "hybrid Hello (aes): byte for byte as frozen");
        if (pcn != FROZEN_PQ_N || memcmp(pc, FROZEN_PQ_CHACHA, pcn) != 0) {
            printf("FAIL: hybrid Hello (chacha) differs from the frozen copy\n");
            fails++;
        } else printf("%-62s ok\n", "hybrid Hello (chacha): byte for byte as frozen");
        /* The hybrid adds exactly 4 (group header in key_share) + 1216 (its key share) + 2
         * (supported_groups). */
        if (pan != an + 4 + 1216 + 2) {
            printf("FAIL: hybrid Hello is %zu bytes, expected %zu\n", pan, an + 4 + 1216 + 2);
            fails++;
        } else printf("%-62s ok\n", "hybrid adds exactly its key share (1216) and its group");
    }
    /* The suite orders MUST differ: if they match, cpu_has_aes no longer affects the Hello, and
     * a MIPS router would get a cipher six times slower. */
    if (memcmp(a, c, an) == 0) {
        printf("FAIL: aes and chacha gave the same Hello: the cipher order has no effect\n");
        fails++;
    } else {
        printf("%-62s ok\n", "cipher suite order follows the CPU (aes and chacha differ)");
    }
    /* GREASE is drawn per connection, and the frozen Hello holds one draw: a rule that matters in
     * one draw of sixteen (the two GREASE extensions must not share a type) needs many. Over 256
     * draws: GREASE comes first and last, and no extension type repeats (a server refuses a Hello
     * with a repeated extension). */
    {
        int bad = 0;
        for (uint64_t s = 1; s <= 256; s++) {
            unsigned char h[4096];
            unsigned t[32];
            size_t n = build_seeded(&CFG, "aes", s, h, sizeof(h));
            size_t k = n ? ext_types(h, n, t, 32) : 0;
            if (k < 3 || !is_grease(t[0]) || !is_grease(t[k - 1])) bad++;
            for (size_t i = 0; i < k; i++)
                for (size_t j = i + 1; j < k; j++) bad += t[i] == t[j];
        }
        if (bad) {
            printf("FAIL: %d faults in the extension types of 256 random Hellos\n", bad);
            fails++;
        } else {
            printf("%-62s ok\n", "256 random Hellos: GREASE first and last, no type repeats");
        }
    }
    /* Catches plain TLS sent without compress_certificate, or with another set than Chrome's brotli alone. */
    if (!plain_chrome_offers_brotli()) {
        printf("FAIL: the plain-TLS Chrome Hello does not offer brotli alone in compress_certificate\n");
        fails++;
    } else {
        printf("%-62s ok\n", "plain-TLS Chrome Hello offers brotli alone");
    }
    fails += ff_hello_matches_the_frozen_bytes();
    fails += ff_hello_has_no_grease_and_a_fixed_order();
    fails += ff_key_share_is_hybrid_x25519_p256();
    fails += ff_p256_share_is_on_the_curve();
    fails += mlkem_seed_is_wiped();
    fails += ff_small_extensions_match_the_capture();
    fails += ff_offers_three_certificate_compressions();
    fails += every_shape_offers_reality_cert_algs();
    fails += ff_ignores_pq_off();
    fails += ff_ech_grease_picks_either_aead();
    fails += fp_of_reads_firefox_in_any_case();
    fails += ff_carrier_offers_http11_alone();
    fails += ff_p256_redraws_a_refused_scalar();
    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");
    return fails ? 1 : 0;
}

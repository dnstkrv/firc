#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unit.h"
#include "certzip.h"
#include "certzip-samples.h"

struct sample {
    const char *name;
    int alg;
    const unsigned char *chain, *zero40960, *zero40961;
    size_t chain_n, zero40960_n, zero40961_n;
};

#define SAMPLE(nm, a, s) { nm, a, CHAIN_##s, ZERO40960_##s, ZERO40961_##s, \
                           sizeof CHAIN_##s, sizeof ZERO40960_##s, sizeof ZERO40961_##s }

static const struct sample S[] = {
    SAMPLE("zlib", CERTZIP_ZLIB, ZLIB),
    SAMPLE("brotli", CERTZIP_BROTLI, BROTLI),
    SAMPLE("zstd", CERTZIP_ZSTD, ZSTD),
};

static unsigned char out[65536];

static size_t g_max_alloc;
void *__real_malloc(size_t n);
void *__wrap_malloc(size_t n);
void *__wrap_malloc(size_t n) {
    if (n > g_max_alloc) g_max_alloc = n;
    return __real_malloc(n);
}

static int inflate_to(const struct sample *s, const unsigned char *in, size_t in_n, size_t declared,
                      size_t cap) {
    memset(out, 0xEE, sizeof out);
    return certzip_inflate(s->alg, in, in_n, declared, out, cap);
}

static size_t count_not(const unsigned char *b, size_t n, unsigned char v) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++) k += b[i] != v;
    return k;
}

int main(void) {
    char what[128];
    for (size_t i = 0; i < sizeof S / sizeof *S; i++) {
        const struct sample *s = &S[i];

        /* Catches a decoder that is not wired in, or one that returns other bytes than the reference tool packed. */
        snprintf(what, sizeof what, "%s: real chain round trip, return code", s->name);
        check(what, 0, inflate_to(s, s->chain, s->chain_n, sizeof CHAIN, sizeof out));
        snprintf(what, sizeof what, "%s: real chain round trip, bytes", s->name);
        check_mem(what, CHAIN, out, sizeof CHAIN);

        /* Catches a write past the declared length into the rest of the caller's buffer. */
        snprintf(what, sizeof what, "%s: nothing written after the declared length", s->name);
        check(what, 0, (long)count_not(out + sizeof CHAIN, sizeof out - sizeof CHAIN, 0xEE));

        /* Catches a stream longer than declared taken as the first declared bytes. */
        snprintf(what, sizeof what, "%s: declared one byte short is refused", s->name);
        check(what, -1, inflate_to(s, s->chain, s->chain_n, sizeof CHAIN - 1, sizeof out));

        /* Catches a stream shorter than declared accepted with stale bytes at its end. */
        snprintf(what, sizeof what, "%s: declared one byte long is refused", s->name);
        check(what, -1, inflate_to(s, s->chain, s->chain_n, sizeof CHAIN + 1, sizeof out));

        /* Catches a decoder told the declared length as room when the caller has less. */
        unsigned char *small = malloc(sizeof CHAIN - 1);
        snprintf(what, sizeof what, "%s: room one byte short of declared is refused", s->name);
        check(what, -1, small ? certzip_inflate(s->alg, s->chain, s->chain_n, sizeof CHAIN, small,
                                                sizeof CHAIN - 1) : 0);
        free(small);

        /* Catches an unfinished stream accepted because the declared bytes already came out. */
        snprintf(what, sizeof what, "%s: stream cut by one byte is refused", s->name);
        check(what, -1, inflate_to(s, s->chain, s->chain_n - 1, sizeof CHAIN, sizeof out));

        unsigned char *buf = malloc(s->chain_n + 1);
        if (!buf) return 1;
        memcpy(buf, s->chain, s->chain_n);
        buf[s->chain_n] = 0x00;
        /* Catches bytes after the end of the stream ignored. */
        snprintf(what, sizeof what, "%s: a byte after the stream is refused", s->name);
        check(what, -1, inflate_to(s, buf, s->chain_n + 1, sizeof CHAIN, sizeof out));

        memcpy(buf, s->chain, s->chain_n);
        if (s->alg == CERTZIP_BROTLI) buf[0] = 0x11;
        else buf[s->chain_n / 2] ^= 0xFF;
        /* Catches a decoder error taken for success. */
        snprintf(what, sizeof what, "%s: corrupt stream is refused", s->name);
        check(what, -1, inflate_to(s, buf, s->chain_n, sizeof CHAIN, sizeof out));
        free(buf);

        /* Catches the cap set below 40960, refusing a chain the handshake buffer holds. */
        snprintf(what, sizeof what, "%s: 40960 bytes accepted", s->name);
        check(what, 0, inflate_to(s, s->zero40960, s->zero40960_n, 40960, sizeof out));
        snprintf(what, sizeof what, "%s: 40960 bytes are the zeros packed", s->name);
        check(what, 0, (long)count_not(out, 40960, 0x00));

        /* Catches a missing or off-by-one cap: 40961 declared and really produced, with room for it. */
        snprintf(what, sizeof what, "%s: 40961 bytes refused", s->name);
        check(what, -1, inflate_to(s, s->zero40961, s->zero40961_n, 40961, sizeof out));
    }

    const struct sample *z = &S[0];
    struct sample bad = *z;
    /* Catches an algorithm code outside RFC 8879's three taken as one of them. */
    bad.alg = 4;
    check("algorithm 4 is refused", -1, inflate_to(&bad, z->chain, z->chain_n, sizeof CHAIN, sizeof out));
    bad.alg = 0;
    check("algorithm 0 is refused", -1, inflate_to(&bad, z->chain, z->chain_n, sizeof CHAIN, sizeof out));

    /* Catches the algorithm code ignored and the stream decoded by its look. */
    bad.alg = CERTZIP_ZSTD;
    check("a zlib stream named zstd is refused", -1,
          inflate_to(&bad, z->chain, z->chain_n, sizeof CHAIN, sizeof out));

    unsigned char huge[4 + 64] = { 0xCF, 0xFF, 0xFF, 0xFF };
    memset(huge + 4, 'A', 64);
    struct sample br = S[1];
    g_max_alloc = 0;
    /* Catches the brotli allocator cap removed: a 16 MB meta-block header makes the decoder allocate a 16 MB ring buffer. */
    check("brotli: 16 MB meta-block header is refused", -1, inflate_to(&br, huge, sizeof huge, 40960, 40960));
    check("brotli: no allocation of 512 KB or more for it", 1, g_max_alloc < (512u << 10));

    unsigned char mega[4 + 64] = { 0xAF, 0xFF, 0xFF, 0x0F };
    memset(mega + 4, 'A', 64);
    g_max_alloc = 0;
    /* Catches the brotli cap above 512 KB: a 1 MB meta-block header makes the decoder allocate a 1 MB ring buffer. */
    check("brotli: 1 MB meta-block header is refused", -1, inflate_to(&br, mega, sizeof mega, 40960, 40960));
    check("brotli: no allocation of 512 KB or more for the 1 MB header", 1, g_max_alloc < (512u << 10));

    return unit_done("certzipmatch");
}

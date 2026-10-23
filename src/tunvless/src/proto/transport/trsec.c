/* Link security: security=none, tls and reality — the handshake over the socket to the node (the
 * middle layer in transport.h). Every link, the main one and xhttp's second one, uses this one
 * handshake; the only difference is the alpn the transport passes in.
 *
 * Reality has no negative answer. A server that does not recognise the client does not refuse:
 * it proxies the connection to the real site it hides behind. The handshake can complete and
 * still lead to someone else's site. Only the protocol above the transport can tell (vless_probe
 * in proto/vless/client.c), so here "the handshake passed" means exactly that and no more.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>

#include "transport.h"
#include "reality.h"
#include "roots.h"
#include "certverify.h"
#include "ech.h"
#include "certzip.h"

/* security=none — a bare stream, no TLS at all (for a trusted network). Without TLS there is no
 * ALPN negotiation, so an HTTP/2 transport starts HTTP/2 at once: the server either accepts bare
 * h2 over TCP (h2c) or answers with garbage, and the probe sees it. */
static int sec_none(struct tr_link *l, const struct tr_node *n, const char *alpn) {
    (void)n; (void)alpn;
    l->plain = 1;
    return 0;
}

/* security=tls (plain TLS) and security=reality.
 *
 * They differ in exactly three things, all required. Plain TLS sends a ClientHello without the
 * Reality authenticator (a TLS server would only see meaningless bytes in session_id). It needs a
 * NAME: Reality allows an empty SNI (the server expects a Hello without the extension), but plain
 * TLS without a name has nothing to send and nothing to check the certificate against. And it
 * verifies the certificate, the only proof of the server's identity here.
 *
 * The name is sni, with host only as a fallback: sni is what the server is asked for, so the
 * certificate is checked against it. With an IP address and no sni the check would be against the
 * address, as in Xray; certificates are almost never issued to an IP, so the subscription parser
 * (sublink.c) skips such a node before it gets here.
 *
 * The Reality state (our ephemeral key and the authenticator key) lives on this function's stack,
 * not in the connection: nothing needs it after the handshake. */
static int sec_tls_like(struct tr_link *l, const struct tr_node *n, const char *alpn,
                        int is_tls) {
    const char *verify_host = n->sni[0] ? n->sni : n->host;
    struct reality_cfg cfg = {
        .sni = is_tls ? verify_host : n->sni,
        .pbk = n->pbk, .sid = n->sid, .fp = n->fp,
        /* ALPN only when the transport needs it. tcp has none, and its Hello stays the one
         * verified against live nodes. */
        .alpn = alpn,
        .plain = is_tls,
        /* The X25519MLKEM768 hybrid in the ClientHello, as in Chrome 131+, uTLS
         * HelloChrome_Auto and Go 1.24+, so in any Xray client with fp=chrome or no fp. Without
         * it the Hello looks like an old Chrome, both by size (about 540 bytes instead of about
         * 1760) and by supported_groups. Setting STEER_NOPQ (to any value) turns it off, for
         * debugging a middlebox that drops a Hello longer than one segment. */
        .pq = !getenv("STEER_NOPQ") && !l->nopq,
    };
    /* pqv: an ML-DSA-65 key, base64url. Decoded BEFORE the Hello is sent: a broken key fails the
     * node rather than letting the handshake go on without checking the signature. The
     * subscription parser (sublink.c) already rejects such keys; this is the second line. */
    unsigned char pqv[SC_MLDSA65_PK];
    const int have_pqv = !is_tls && n->pqv && n->pqv[0];
    if (have_pqv && xc_b64url_decode(n->pqv, pqv, sizeof pqv) != SC_MLDSA65_PK) return REALITY_EBADKEY;
    struct reality_state rst;
    unsigned char hello[2560];
    size_t hello_n = 0;
    /* ws and httpupgrade offer ONLY http/1.1 in ALPN, as Xray does (uTLS
     * WebsocketHandshakeContext rewrites the fingerprint's ALPN to http/1.1 alone) and as Chrome
     * does on a WebSocket connection. With the usual "h2, http/1.1" the server behind TLS may pick
     * h2, and the HTTP/1.1 Upgrade request becomes garbage on an HTTP/2 connection. For the other
     * transports the Hello does not change by a bit (tests/hellofreeze.c): the carrier is used
     * only for these two. */
    struct reality_carrier car = { .alpn_http11 = 1 };
    const int h11 = alpn && !strcmp(alpn, "http/1.1");
    int rc = h11 ? reality_build_hello_carry(&cfg, &rst, &car, hello, sizeof(hello), &hello_n)
                 : reality_build_hello(&cfg, &rst, hello, sizeof(hello), &hello_n);
    if (rc) return rc;

    /* ECH (security=tls, the node's `ech=`): the Hello built above, with the real SNI, becomes the
     * inner one; the outer one with public_name from the ECHConfig goes on the wire (ech.h). The
     * buffers are on the heap: the outer Hello holds an encrypted copy of the inner one, twice the
     * usual size, and the threads that run handshakes have small stacks (connectors: 128 KB). */
    struct ech_heap {
        struct ech_cfg cfg;
        struct ech_state st;
        unsigned char list[1100];
        unsigned char outer[6144];
        size_t outer_n;
    } *eh = NULL;
    struct tls13_ech te = { 0 };
    const unsigned char *send_hello = hello;
    size_t send_n = hello_n;
    if (is_tls && n->ech && n->ech[0]) {
        eh = calloc(1, sizeof *eh);
        if (!eh) return TR_EIO;
        int ln = ech_b64_decode(n->ech, eh->list, sizeof eh->list);
        int er = ln <= 0 ? ECH_EPARSE : ech_pick(eh->list, (size_t)ln, &eh->cfg);
        if (er == 0) er = ech_wrap(&eh->cfg, hello, hello_n, eh->outer, sizeof eh->outer, &eh->outer_n, &eh->st);
        if (er != 0) {
            free(eh);
            return er;                              /* an ECH_E* code (transport.c, tr_strerror) */
        }
        send_hello = eh->outer;
        send_n = eh->outer_n;
        te.inner = eh->st.inner;
        te.inner_n = eh->st.inner_n;
        te.random = eh->st.random;
    }

    size_t sent = 0;
    while (sent < send_n) {
        /* MSG_NOSIGNAL: a node that closes before the ClientHello is a write error, not a
         * signal. */
        ssize_t w = send(l->fd, send_hello + sent, send_n - sent, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            free(eh);
            return TR_EIO;
        }
        sent += (size_t)w;
    }

    /* Our PRIVATE key is passed, not a ready secret: the TLS key schedule needs the server's
     * ephemeral key, which only arrives in the ServerHello. */
    /* The node kind decides how the server proves itself, always exactly one way: plain TLS by
     * the chain and the name, Reality by an HMAC in the signature field of a temporary
     * certificate, keyed with what only the owner of the long-term key pair has. */
    struct tls13_auth auth = { 0 };
    /* Pins, verify names and an explicit opt-out of verification come from the node
     * (certverify.h). Without them the pointer stays NULL and verification is the default:
     * the chain up to the roots, and SNI. */
    struct cert_policy pol = { .pcs = n->pcs, .pks = n->pks, .vcn = n->vcn, .insecure = n->insecure };
    if (is_tls) {
        auth.host = verify_host;
        auth.roots = tls_cert_roots();
        auth.cert_algs = reality_fp_of(cfg.fp) == REALITY_FP_FIREFOX
                             ? 1u << CERTZIP_ZLIB | 1u << CERTZIP_BROTLI | 1u << CERTZIP_ZSTD
                             : 1u << CERTZIP_BROTLI;
        if (pol.pcs || pol.pks || pol.vcn || pol.insecure) auth.policy = &pol;
    } else auth.reality_key = rst.authkey;
    if (rst.pq) auth.mlkem_dk = rst.mlkem_dk;
    auth.mldsa_pk = have_pqv ? pqv : NULL;

    if (eh) auth.ech = &te;
    int hrc = tls13_handshake_auth(&l->tls, l->fd, send_hello, send_n, rst.priv, &auth);
    free(eh);
    return hrc;
}

static int sec_tls(struct tr_link *l, const struct tr_node *n, const char *alpn) {
    return sec_tls_like(l, n, alpn, 1);
}

static int sec_reality(struct tr_link *l, const struct tr_node *n, const char *alpn) {
    return sec_tls_like(l, n, alpn, 0);
}

const struct security_ops tr_sec_none    = { .name = "none",    .handshake = sec_none };
const struct security_ops tr_sec_tls     = { .name = "tls",     .handshake = sec_tls };
const struct security_ops tr_sec_reality = { .name = "reality", .handshake = sec_reality };

/* Anything that is not none or tls is reality: the subscription parser (sublink.c) rejects an
 * unsupported value before the node gets here. */
const struct security_ops *tr_security(const char *name) {
    if (!strcmp(name, "none")) return &tr_sec_none;
    if (!strcmp(name, "tls")) return &tr_sec_tls;
    return &tr_sec_reality;
}

long tr_nopq_ttl_s = 3600;
long tr_nopq_skip_s = 300;

struct nopq_ent {
    uint64_t host;
    uint16_t port;
    uint8_t used, logged;
    long until, skip_until;
    uint64_t seq;
};
static struct nopq_ent g_nopq[TR_NOPQ_MAX];
static uint64_t g_nopq_seq;
static pthread_mutex_t g_nopq_mu = PTHREAD_MUTEX_INITIALIZER;

static long nopq_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec;
}

static uint64_t nopq_hash(const char *s) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 0x100000001b3ull;
    return h;
}

static struct nopq_ent *nopq_find(uint64_t h, uint16_t port) {
    for (size_t i = 0; i < TR_NOPQ_MAX; i++)
        if (g_nopq[i].used && g_nopq[i].host == h && g_nopq[i].port == port) return &g_nopq[i];
    return NULL;
}

static struct nopq_ent *nopq_slot(const struct tr_node *n, long now) {
    uint64_t h = nopq_hash(n->host);
    struct nopq_ent *e = nopq_find(h, n->port);
    if (!e) {
        e = &g_nopq[0];
        for (size_t i = 0; i < TR_NOPQ_MAX; i++) {
            struct nopq_ent *c = &g_nopq[i];
            if (!c->used || (c->until <= now && c->skip_until <= now)) { e = c; break; }
            if (c->seq < e->seq) e = c;
        }
        memset(e, 0, sizeof *e);
        e->used = 1;
        e->host = h;
        e->port = n->port;
    }
    e->seq = ++g_nopq_seq;
    return e;
}

enum { NOPQ_NONE, NOPQ_SHORT, NOPQ_USELESS };

static int nopq_state(const struct tr_node *n) {
    long now = nopq_now();
    pthread_mutex_lock(&g_nopq_mu);
    struct nopq_ent *e = nopq_find(nopq_hash(n->host), n->port);
    int r = !e ? NOPQ_NONE : e->until > now ? NOPQ_SHORT : e->skip_until > now ? NOPQ_USELESS : NOPQ_NONE;
    pthread_mutex_unlock(&g_nopq_mu);
    return r;
}

static void nopq_useless(const struct tr_node *n) {
    long now = nopq_now();
    pthread_mutex_lock(&g_nopq_mu);
    nopq_slot(n, now)->skip_until = now + tr_nopq_skip_s;
    pthread_mutex_unlock(&g_nopq_mu);
}

static void nopq_remember(const struct tr_node *n) {
    long now = nopq_now();
    pthread_mutex_lock(&g_nopq_mu);
    struct nopq_ent *e = nopq_slot(n, now);
    e->until = now + tr_nopq_ttl_s;
    int say = !e->logged;
    e->logged = 1;
    pthread_mutex_unlock(&g_nopq_mu);
    if (say)
        fprintf(stderr, "tunvless[warn]: node %s:%u does not answer a long ClientHello, using a short one "
                        "without the post-quantum key share (the long one is tried again in %ld min)\n",
                n->host, (unsigned)n->port, tr_nopq_ttl_s / 60);
}

static int link_try(struct tr_link *l, const struct tr_node *n, const char *alpn, int timeout_s, int nopq) {
    l->fd = -1;
    l->nopq = nopq;
    int fd = tr_dial(n->host, n->port, timeout_s);
    if (fd < 0) return fd;
    l->fd = fd;
    /* On a failed handshake only close(), not tr_link_close: tls13_handshake_auth frees its own
     * heap state on failure, and tests/vlessmatch.c checks that under AddressSanitizer for every
     * failure branch. */
    int rc = tr_security(n->security)->handshake(l, n, alpn);
    if (rc) { close(fd); l->fd = -1; return rc; }
    return 0;
}

int tr_link_open(struct tr_link *l, const struct tr_node *n, const char *alpn, int timeout_s) {
    if (reality_fp_of(n->fp) == REALITY_FP_FIREFOX) return link_try(l, n, alpn, timeout_s, 0);
    const int pq_able = !getenv("STEER_NOPQ");
    const int st = pq_able ? nopq_state(n) : NOPQ_NONE;
    int rc = link_try(l, n, alpn, timeout_s, st == NOPQ_SHORT || !pq_able);
    if (rc != TLS13_ETIMEOUT || !pq_able || st != NOPQ_NONE) return rc;
    int rc2 = link_try(l, n, alpn, timeout_s, 1);
    if (rc2 == 0) {
        nopq_remember(n);
        return 0;
    }
    if (rc2 == TLS13_ETIMEOUT) nopq_useless(n);
    return rc;
}

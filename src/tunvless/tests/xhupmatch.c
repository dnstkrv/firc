/* A server's answer to an xhttp upload (stream-up and packet-up): a refusal must reach the sender.
 *
 * In stream-up and packet-up the upload goes over its own link, and its answers are read only by
 * up_drain, which runs as part of a write. The xhttp server answers 400 to a chunk with bad
 * padding; if up_drain drops that answer, the write reports success, and the node looks alive
 * while no data flows. packet-up is harder: the answer to a chunk arrives when the next chunk is
 * already open, so h2.c must not throw it away as a frame of another stream. The
 * tests/run-tunnel*.sh stands do not reach this: their fake server speaks bare TCP, not xhttp.
 *
 * The file includes the xhttp transport whole (src/proto/transport/trxhttp.c: up_drain and
 * up_request are static) and links the real h2.c and the other transport layers as separate
 * objects. The upload link is plain (as with security=none) on a socket pair: what the client
 * writes, the test reads (and looks for the request paths in), and the "server" writes HTTP/2
 * frames to the other end by hand. TLS and Reality are not needed and are stubbed out. No
 * header stubs are needed: tls13.h includes only src/lib/scrypto.h, which has no crypto library
 * types. No network and no privileges, so the test runs in `make test`. */
#include "../src/proto/transport/trxhttp.c"

#include <stdlib.h>
#include <sys/socket.h>
#include "reality.h"
#include "hpackread.h"

/* ---- TLS and Reality stubs: the test link is plain, they are never reached --------- */

void sc_wipe(void *p, size_t n) { memset(p, 0, n); }
int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
/* trsec.c also calls the carrier variant (ALPN http/1.1 for ws and httpupgrade); not reached
 * here either. */
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)car; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
unsigned tls13_server_group(void) { return 0; }
/* trsec.c parses the pqv key with it (reality.c); not reached here. */
int xc_b64url_decode(const char *in, unsigned char *out, size_t out_n) {
    static const char al[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint32_t acc = 0;
    int bits = 0;
    size_t k = 0;
    for (const char *p = in; *p && *p != '='; p++) {
        const char *c = strchr(al, *p);
        if (!c) return -1;
        acc = acc << 6 | (uint32_t)(c - al);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (k >= out_n) return -1;
            out[k++] = (unsigned char)(acc >> bits);
        }
    }
    return (int)k;
}
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_buffered(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap)
    { (void)t; (void)out; (void)cap; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n)
    { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t cap, size_t *got)
    { (void)t; (void)o; (void)cap; *got = 0; return -1; }
int tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *bn)
    { (void)t; *b = NULL; *bn = 0; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }

/* ---- test -------------------------------------------------------------------------- */

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-74s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) g_fail = 1;
}

static int g_srv = -1;                /* the "server" end of the socket pair */

/* What the client has written since the pair was made: preface, HEADERS, DATA. Kept to look for
 * the request paths: HPACK sends them as plain literals (put_headers in h2.c). */
static unsigned char g_seen[1 << 20];
static size_t g_seen_n;

static void srv_drain(void) {
    ssize_t r;
    while ((r = recv(g_srv, g_seen + g_seen_n, sizeof(g_seen) - g_seen_n, MSG_DONTWAIT)) > 0)
        g_seen_n += (size_t)r;
}

static int seen(const char *s) {
    return memmem(g_seen, g_seen_n, s, strlen(s)) != NULL;
}

/* Whether the client left unread bytes on its end: an answer up_drain never took. */
static int unread(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    return poll(&p, 1, 0) > 0;
}

/* HEADERS from the server on stream sid with one HPACK byte, a static index of :status:
 * 0x88 is 200, 0x8C is 400 (RFC 7541, Appendix A). */
static void srv_headers(uint32_t sid, unsigned char hpack, int end_stream) {
    unsigned char f[10] = { 0, 0, 1, 0x01, (unsigned char)(0x04 | (end_stream ? 0x01 : 0)),
                            (unsigned char)(sid >> 24), (unsigned char)(sid >> 16),
                            (unsigned char)(sid >> 8), (unsigned char)sid, hpack };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

/* RST_STREAM(NO_ERROR) from the server on stream sid. */
static void srv_rst(uint32_t sid) {
    unsigned char f[13] = { 0, 0, 4, 0x03, 0, (unsigned char)(sid >> 24),
                            (unsigned char)(sid >> 16), (unsigned char)(sid >> 8),
                            (unsigned char)sid, 0, 0, 0, 0 };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

static void conn_init(struct transport *c, enum xhttp_mode xh, int fd) {
    memset(c, 0, sizeof(*c));
    c->link.fd = -1;
    c->fr = &tr_xhttp;
    c->xh.mode = xh;
    c->xh.up.link.fd = fd;
    c->xh.up.link.plain = 1;
    snprintf(c->xh.authority, sizeof(c->xh.authority), "stand.example");
    xh_opts_parse(NULL, "", NULL, 0, &c->xh.opts, NULL, 0);
    snprintf(c->xh.base_path, sizeof(c->xh.base_path), "/xh/");
    snprintf(c->xh.sid, sizeof(c->xh.sid), "0f1e2d3c");
}

static int new_pair(int *cli) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    if (g_srv >= 0) close(g_srv);
    g_srv = sp[1];
    g_seen_n = 0;
    *cli = sp[0];
    return 0;
}

static const unsigned char piece[] = "upload chunk";

/* packet-up: the answer to chunk 0 arrives when chunk 1 is already open. */
static void t_packet_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0, stream 1 */
    srv_drain();
    srv_headers(1, hpack, 1);                                /* answer to chunk 0 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* chunk 1, stream 3 */
    srv_drain();
    if (want_refused)
        check(rc0 == 0 && rc1 == H2_ESTATUS &&
              strstr(transport_strerror(rc1), "400") != NULL, what);
    else
        check(rc0 == 0 && rc1 == 0 && !unread(fd), what);
    if (!want_refused)
        check(seen("/xh/0f1e2d3c/0") && seen("/xh/0f1e2d3c/1") && !seen("/xh/0f1e2d3c/2"),
              "packet-up: the two chunks go as requests numbered 0 and 1");
    close(fd);
}

/* packet-up: the answer to a chunk already in the socket when the chunk is written, ended by
 * RST_STREAM(NO_ERROR) as a Go server ends a finished handler's stream. up_drain then sees the
 * reset on the current stream: the normal end of an answer, not a failure of the write. */
static void t_packet_up_rst(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    srv_headers(1, 0x88, 1);
    srv_rst(1);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0 reads its own answer */
    srv_drain();
    int rc1 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    check(rc0 == 0 && rc1 == 0 && !unread(fd),
          "packet-up: a chunk's 200 ended by RST_STREAM(NO_ERROR) is read, not a refusal");
    close(fd);
}

/* packet-up with the connection window too small for a chunk: the write is refused before its
 * request opens, so the retry opens chunk 1 once, not a second stream for it. */
static void t_packet_up_window(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0, stream 1 */
    srv_drain();
    srv_headers(1, 0x88, 1);
    int32_t win = c.xh.up.h2.send_win_conn;
    c.xh.up.h2.send_win_conn = (int32_t)sizeof(piece) - 1;
    int rc1 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    int opened = seen("/xh/0f1e2d3c/1");
    c.xh.up.h2.send_win_conn = win;
    int rc2 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    check(rc0 == 0 && rc1 == H2_EWINDOW && !opened,
          "packet-up: a chunk the window cannot take opens no request");
    check(rc2 == 0 && seen("/xh/0f1e2d3c/1") && !seen("/xh/0f1e2d3c/2"),
          "packet-up: the retry sends it as chunk 1");
    close(fd);
}

/* stream-up: one long POST, and the refusal comes on that same stream. */
static void t_stream_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_STREAM_UP, fd);
    int ro = up_request(&c, -1);                        /* as up_open does: the POST opens at once */
    srv_drain();
    srv_headers(1, hpack, 0);
    int rc = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    if (want_refused)
        check(ro == 0 && rc == H2_ESTATUS && strstr(transport_strerror(rc), "400") != NULL, what);
    else
        check(ro == 0 && rc == 0 && !unread(fd), what);
    close(fd);
}

/* packet-up: the server answers chunks in any order. Here the CURRENT chunk (stream 3) is
 * answered first, and the older one (stream 1) in a later read. up_drain used to stop once the
 * current stream was done, so the older answer stayed unread: the chunk counted as unanswered for
 * good, the window over seq filled, and the upload stalled with no chunk left to send. */
static void t_packet_up_order(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0, stream 1 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* chunk 1, stream 3 */
    srv_drain();
    srv_headers(3, 0x88, 1);                                 /* the newer chunk first */
    long r1 = transport_room(&c);
    srv_headers(1, 0x88, 1);                                 /* then the older one */
    long r2 = transport_room(&c);
    check(rc0 == 0 && rc1 == 0 && r1 >= 0 && r2 > 0 && h2_open_streams(&c.xh.up.h2) == 0 &&
          !unread(fd), "packet-up: an older chunk's 200 after the current one's is read");
    close(fd);
}

static unsigned char g_down[1 << 20];
static size_t g_down_n;
static int g_dsrv = -1;
static struct hr_block g_hb;

static void slurp(int fd, unsigned char *buf, size_t cap, size_t *n) {
    ssize_t r;
    while ((r = recv(fd, buf + *n, cap - *n, MSG_DONTWAIT)) > 0) *n += (size_t)r;
}

static struct tr_node xnode(const char *mode, const char *xhx, const char *headers) {
    struct tr_node n;
    memset(&n, 0, sizeof n);
    n.host = "10.0.0.1";
    n.port = 443;
    n.type = "xhttp";
    n.security = "none";
    n.sni = "";
    n.path = "/xp";
    n.http_host = "a";
    n.mode = mode;
    n.xhx = xhx;
    n.headers = headers;
    return n;
}

static int xopen(struct transport *c, const struct tr_node *n, int *fds) {
    int d[2], u[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, d) || socketpair(AF_UNIX, SOCK_STREAM, 0, u)) return -1;
    memset(c, 0, sizeof *c);
    c->fr = &tr_xhttp;
    c->link.fd = d[0];
    c->link.plain = 1;
    c->xh.up.link.fd = u[0];
    c->xh.up.link.plain = 1;
    if (g_dsrv >= 0) close(g_dsrv);
    if (g_srv >= 0) close(g_srv);
    g_dsrv = d[1];
    g_srv = u[1];
    g_down_n = 0;
    g_seen_n = 0;
    fds[0] = d[0];
    fds[1] = u[0];
    int rc = xh_init(c, n);
    if (!rc) rc = down_request(c);
    if (!rc && c->xh.mode != XH_STREAM_ONE) rc = up_start(c);
    slurp(g_dsrv, g_down, sizeof g_down, &g_down_n);
    srv_drain();
    return rc;
}

static void xclose(int *fds) { close(fds[0]); close(fds[1]); }

static const char *fval(const struct hr_block *b, const char *name) {
    int i = hr_find(b, name);
    return i < 0 ? NULL : b->f[i].value;
}

static int all_x(const char *s, size_t lo, size_t hi) {
    size_t k = strspn(s, "X");
    return s[k] == '\0' && k >= lo && k <= hi;
}

static int down_block(struct hr_block *b) { return hr_nth_headers(g_down, g_down_n, 0, b); }
static int up_block(int k, struct hr_block *b) { return hr_nth_headers(g_seen, g_seen_n, k, b); }

static void t_referer_without_session(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", NULL, NULL);
    int rc = xopen(&c, &n, fds);
    char want[200];
    snprintf(want, sizeof want, "/xp/%s", c.xh.sid);
    const char *ref = down_block(&g_hb) ? NULL : fval(&g_hb, "referer");
    const char *pre = "https://a/xp/?x_padding=";
    check(rc == 0 && strlen(c.xh.sid) == 36 && fval(&g_hb, ":path") &&
          !strcmp(fval(&g_hb, ":path"), want), "default: the download GET goes to /xp/<uuid>");
    check(ref && !strncmp(ref, pre, strlen(pre)) && all_x(ref + strlen(pre), 100, 1000),
          "default: referer is https://a/xp/?x_padding=X... without the session");
    xclose(fds);
}

static void t_session_header(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "sessionIDPlacement=header", NULL);
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    const char *p = fval(&g_hb, ":path"), *s = fval(&g_hb, "x-session");
    check(rc == 0 && p && !strcmp(p, "/xp/"), "session in a header, seq in the path: GET /xp/");
    check(s && !strcmp(s, c.xh.sid), "session in a header: x-session carries the id");
    xclose(fds);
}

static void t_session_and_seq_header(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "sessionIDPlacement=header\nseqPlacement=header", NULL);
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    const char *p = fval(&g_hb, ":path");
    check(rc == 0 && p && !strcmp(p, "/xp"), "session and seq in headers: GET /xp, no slash");
    int wr = transport_write(&c, piece, sizeof piece);
    srv_drain();
    int ub = up_block(0, &g_hb);
    p = fval(&g_hb, ":path");
    const char *s = fval(&g_hb, "x-session"), *q = fval(&g_hb, "x-seq");
    check(wr == 0 && ub == 0 && p && !strcmp(p, "/xp") && s && !strcmp(s, c.xh.sid) && q &&
          !strcmp(q, "0"), "session and seq in headers: upload /xp, x-session, x-seq 0");
    xclose(fds);
}

static void t_seq_and_session_query_sorted(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up",
                             "seqPlacement=query\nsessionIDPlacement=query\nsessionIDKey=b\nseqKey=a",
                             NULL);
    int rc = xopen(&c, &n, fds);
    int wr = transport_write(&c, piece, sizeof piece);
    srv_drain();
    up_block(0, &g_hb);
    char want[200];
    snprintf(want, sizeof want, "/xp?a=0&b=%s", c.xh.sid);
    const char *p = fval(&g_hb, ":path");
    check(rc == 0 && wr == 0 && p && !strcmp(p, want), "seq and session in the query: keys sorted");
    xclose(fds);
}

static void t_obfs_cookie(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up",
                             "xPaddingObfsMode=true\nxPaddingPlacement=cookie\nxPaddingKey=pk\n"
                             "sessionIDPlacement=cookie", NULL);
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    int c1 = hr_find(&g_hb, "cookie"), c2 = c1 < 0 ? -1 : hr_find_from(&g_hb, "cookie", c1 + 1);
    char want[200];
    snprintf(want, sizeof want, "x_session=%s", c.xh.sid);
    check(rc == 0 && c1 >= 0 && !strncmp(g_hb.f[c1].value, "pk=", 3) &&
          all_x(g_hb.f[c1].value + 3, 100, 1000), "obfs cookie: first cookie pk=<padding>");
    check(c2 >= 0 && !strcmp(g_hb.f[c2].value, want) && hr_find_from(&g_hb, "cookie", c2 + 1) < 0,
          "obfs cookie: second cookie x_session=<id>, no third");
    check(hr_find(&g_hb, "referer") < 0, "obfs cookie: no referer");
    xclose(fds);
}

static void t_obfs_query_in_header_default(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "xPaddingObfsMode=true", NULL);
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    const char *v = fval(&g_hb, "x-padding");
    const char *pre = "https://a/xp/?x_padding=";
    check(rc == 0 && v && !strncmp(v, pre, strlen(pre)) && all_x(v + strlen(pre), 100, 1000) &&
          hr_find(&g_hb, "referer") < 0, "obfs default: x-padding carries the URL, no referer");
    xclose(fds);
}

static void t_obfs_query_long(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "xPaddingObfsMode=true\nxPaddingPlacement=query", NULL);
    n.pad_from = n.pad_to = 1000;
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    static char want[1200];
    int k = snprintf(want, sizeof want, "/xp/%s?x_padding=", c.xh.sid);
    memset(want + k, 'X', 1000);
    want[k + 1000] = '\0';
    const char *p = fval(&g_hb, ":path");
    check(rc == 0 && p && !strcmp(p, want), "obfs query, padding 1000: the whole padding in :path");
    xclose(fds);
}

static void t_method_put(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("stream-up", "uplinkHTTPMethod=PUT", NULL);
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    const char *dm = fval(&g_hb, ":method");
    int dget = dm && !strcmp(dm, "GET");
    up_block(0, &g_hb);
    const char *um = fval(&g_hb, ":method"), *ct = fval(&g_hb, "content-type");
    check(rc == 0 && dget && um && !strcmp(um, "PUT") && ct && !strcmp(ct, "application/grpc"),
          "uplinkHTTPMethod=PUT: upload PUT with application/grpc, download GET");
    xclose(fds);
}

static size_t gather_data(const char *key, int k0, int k1, char *out, size_t cap, size_t *lens,
                          int *bad) {
    size_t n = 0;
    *bad = 0;
    for (int k = k0; k < k1; k++) {
        if (up_block(k, &g_hb)) { *bad = 1; return n; }
        for (int i = 0;; i++) {
            char name[80];
            snprintf(name, sizeof name, "%s-%d", key, i);
            const char *v = fval(&g_hb, name);
            if (!v) break;
            if (lens && i < 8) lens[i] = strlen(v);
            if (n + strlen(v) >= cap) { *bad = 1; return n; }
            memcpy(out + n, v, strlen(v));
            n += strlen(v);
        }
    }
    out[n] = '\0';
    return n;
}

static size_t decode_reqs(int k0, int k1, unsigned char *out, size_t cap, int *bad) {
    static char b64[32768];
    size_t n = 0;
    *bad = 0;
    for (int k = k0; k < k1 && !*bad; k++) {
        gather_data("x-data", k, k + 1, b64, sizeof b64, NULL, bad);
        int dn = *bad ? -1 : xc_b64url_decode(b64, out + n, cap - n);
        if (dn <= 0) *bad = 1;
        else n += (size_t)dn;
    }
    return n;
}

static void t_data_header(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "uplinkDataPlacement=header\nuplinkChunkSize=64", NULL);
    int rc = xopen(&c, &n, fds);
    unsigned char pl[100];
    for (int i = 0; i < 100; i++) pl[i] = (unsigned char)(i * 37 + 11);
    int wr = transport_write(&c, pl, sizeof pl);
    srv_drain();
    static char b64[4096];
    size_t lens[8] = { 0 };
    int bad;
    gather_data("x-data", 0, 1, b64, sizeof b64, lens, &bad);
    unsigned char dec[200];
    int dn = xc_b64url_decode(b64, dec, sizeof dec);
    check(rc == 0 && wr == 0 && hr_count_frames(g_seen, g_seen_n, 0x00) == 0,
          "data in headers: no DATA frame on the upload");
    check((hr_nth_headers_flags(g_seen, g_seen_n, 0) & 0x01) == 0x01,
          "data in headers: the request ends with its HEADERS");
    check(!bad && lens[0] == 64 && lens[1] == 64 && lens[2] == 6 && lens[3] == 0,
          "data in headers: x-data-0..2 of 64, 64 and 6 characters");
    check(dn == 100 && !memcmp(dec, pl, 100), "data in headers: the pieces decode to the payload");
    xclose(fds);
}

static void t_data_budget_first_request(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "uplinkDataPlacement=header", NULL);
    n.post_from = n.post_to = 1000000;
    int rc = xopen(&c, &n, fds);
    static unsigned char pl[16000];
    for (size_t i = 0; i < sizeof pl; i++) pl[i] = (unsigned char)(i * 131 + 7);
    int wr = transport_write(&c, pl, sizeof pl);
    srv_drain();
    int reqs = hr_count_frames(g_seen, g_seen_n, 0x01), over = 0;
    for (int k = 0; k < reqs; k++) {
        if (up_block(k, &g_hb)) { over = 1; break; }
        if (hr_list_size(&g_hb) > 8192) over = 1;
    }
    static unsigned char dec[20000];
    int bad;
    size_t dn = decode_reqs(0, reqs, dec, sizeof dec, &bad);
    check(rc == 0 && wr == 0 && reqs > 1 && !over,
          "data in headers before SETTINGS: every request within 8192, several requests");
    check(!bad && dn == sizeof pl && !memcmp(dec, pl, sizeof pl),
          "data in headers before SETTINGS: the bytes arrive whole and in order");
    xclose(fds);
}

static void t_data_budget_after_settings(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "uplinkDataPlacement=header", NULL);
    n.post_from = n.post_to = 1000000;
    int rc = xopen(&c, &n, fds);
    int w0 = transport_write(&c, piece, sizeof piece);
    unsigned char st[15] = { 0, 0, 6, 0x04, 0, 0, 0, 0, 0, 0, 0x06, 0, 0, 0x0F, 0xA0 };
    if (write(g_srv, st, sizeof st) != (ssize_t)sizeof st) { perror("write"); exit(2); }
    srv_drain();
    size_t before = g_seen_n;
    static unsigned char pl[6000];
    for (size_t i = 0; i < sizeof pl; i++) pl[i] = (unsigned char)(i * 29 + 3);
    int wr = transport_write(&c, pl, sizeof pl);
    srv_drain();
    int first = hr_count_frames(g_seen, before, 0x01);
    int reqs = hr_count_frames(g_seen, g_seen_n, 0x01), over = 0;
    for (int k = first; k < reqs; k++) {
        if (up_block(k, &g_hb)) { over = 1; break; }
        if (hr_list_size(&g_hb) > 4000) over = 1;
    }
    static unsigned char dec[8000];
    int bad;
    size_t dn = decode_reqs(first, reqs, dec, sizeof dec, &bad);
    check(rc == 0 && w0 == 0 && wr == 0 && reqs - first > 1 && !over && !bad &&
          dn == sizeof pl && !memcmp(dec, pl, sizeof pl),
          "data in headers after SETTINGS 0x06=4000: every request within 4000, bytes whole");
    xclose(fds);
}

static void t_budget_too_small_fails_with_reason(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "uplinkDataPlacement=header", NULL);
    int rc = xopen(&c, &n, fds);
    int w0 = transport_write(&c, piece, sizeof piece);
    unsigned char st[15] = { 0, 0, 6, 0x04, 0, 0, 0, 0, 0, 0, 0x06, 0, 0, 0x01, 0xF4 };
    if (write(g_srv, st, sizeof st) != (ssize_t)sizeof st) { perror("write"); exit(2); }
    srv_drain();
    size_t before = g_seen_n;
    int wr = transport_write(&c, piece, sizeof piece);
    srv_drain();
    check(rc == 0 && w0 == 0 && wr == TR_EIO && c.why &&
          !strcmp(c.why, "xhttp: the server's header limit leaves no room for data") &&
          hr_count_frames(g_seen + before, g_seen_n - before, 0x01) == 0,
          "header limit 500: the write fails with TR_EIO and the reason, nothing sent");
    xclose(fds);
}

static void t_custom_headers_first(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", NULL, "X-A: 1\n");
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    size_t i = 0;
    while (i < g_hb.n && g_hb.f[i].name[0] == ':') i++;
    check(rc == 0 && i < g_hb.n && !strcmp(g_hb.f[i].name, "x-a") && !strcmp(g_hb.f[i].value, "1"),
          "custom headers: x-a is the first field after the pseudo-headers");
    xclose(fds);
}

static void t_ipv6_authority_in_brackets(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", NULL, NULL);
    n.host = "2001:db8::1";
    n.http_host = NULL;
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    int a = hr_find(&g_hb, ":authority");
    check(rc == 0 && a >= 0 && !strcmp(g_hb.f[a].value, "[2001:db8::1]"),
          "IPv6 address as :authority: in brackets, no port");
    n.host = "10.0.0.1";
    xclose(fds);
    rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    a = hr_find(&g_hb, ":authority");
    check(rc == 0 && a >= 0 && !strcmp(g_hb.f[a].value, "10.0.0.1"),
          "IPv4 address as :authority: as it is");
    xclose(fds);
}

static void t_custom_accept_replaces(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", NULL, "Accept: text/html\n");
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    int a = hr_find(&g_hb, "accept");
    check(rc == 0 && a >= 0 && !strcmp(g_hb.f[a].value, "text/html") &&
          hr_find_from(&g_hb, "accept", a + 1) < 0, "custom Accept: one accept field, ours");
    xclose(fds);
}

static void t_literal_ua_drops_look(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", NULL, "User-Agent: MyApp/1\n");
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    const char *ua = fval(&g_hb, "user-agent");
    int fetch = 0;
    for (size_t i = 0; i < g_hb.n; i++) fetch |= !strncmp(g_hb.f[i].name, "sec-fetch-", 10);
    check(rc == 0 && ua && !strcmp(ua, "MyApp/1") && hr_find(&g_hb, "sec-ch-ua") < 0 && !fetch,
          "literal User-Agent: ours, no sec-ch-ua, no sec-fetch-*");
    xclose(fds);
}

static void t_chrome_ua_keeps_look(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", NULL, "User-Agent: chrome\n");
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    const char *ua = fval(&g_hb, "user-agent");
    check(rc == 0 && ua && !strcmp(ua, UA_CHROME) && hr_find(&g_hb, "sec-ch-ua") >= 0 &&
          hr_find_from(&g_hb, "user-agent", hr_find(&g_hb, "user-agent") + 1) < 0,
          "User-Agent chrome: the look's user-agent, once");
    xclose(fds);
}

static void t_room_worst_padding(void) {
    int ok = 1;
    for (int it = 0; it < 24 && ok; it++) {
        int fds[2];
        struct transport c;
        struct tr_node n = xnode("packet-up", "uplinkDataPlacement=header", NULL);
        n.pad_from = 100;
        n.pad_to = 1000;
        if (xopen(&c, &n, fds)) { ok = 0; break; }
        long room = transport_room(&c);
        static unsigned char pl[1 << 17];
        if (room <= 0 || room > (long)sizeof pl) { ok = 0; xclose(fds); break; }
        memset(pl, 0x5A, (size_t)room);
        int wr = transport_write(&c, pl, (size_t)room);
        srv_drain();
        if (wr != 0 || hr_count_frames(g_seen, g_seen_n, 0x01) > PACKET_INFLIGHT) ok = 0;
        xclose(fds);
    }
    check(ok, "data in headers: a write of the whole room fits the free slots");
}

static int cookies(const struct hr_block *b, const char **out, int cap) {
    int k = 0;
    for (size_t i = 0; i < b->n && k < cap; i++)
        if (!strcmp(b->f[i].name, "cookie")) out[k++] = b->f[i].value;
    return k;
}

static void t_seq_cookie_after_session(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "seqPlacement=cookie\nsessionIDPlacement=cookie", NULL);
    int rc = xopen(&c, &n, fds);
    int wr = transport_write(&c, piece, sizeof piece);
    srv_drain();
    up_block(0, &g_hb);
    const char *ck[8];
    int k = cookies(&g_hb, ck, 8);
    char want[200];
    snprintf(want, sizeof want, "x_session=%s", c.xh.sid);
    const char *p = fval(&g_hb, ":path");
    check(rc == 0 && wr == 0 && k == 2 && !strcmp(ck[0], want) && !strcmp(ck[1], "x_seq=0") &&
          p && !strcmp(p, "/xp"), "seq and session in cookies: x_session=<id> then x_seq=0");
    xclose(fds);
}

static void t_tokenish_without_obfs_is_repeat_x(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "xPaddingMethod=tokenish", NULL);
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    const char *ref = fval(&g_hb, "referer");
    const char *pre = "https://a/xp/?x_padding=";
    check(rc == 0 && ref && !strncmp(ref, pre, strlen(pre)) && all_x(ref + strlen(pre), 100, 1000),
          "tokenish without obfs: the referer padding is all X");
    xclose(fds);
    struct tr_node a = xnode("packet-up", "uplinkDataPlacement=header\nxPaddingMethod=tokenish", NULL);
    struct tr_node b = xnode("packet-up", "uplinkDataPlacement=header", NULL);
    long ra = -1, rb = -2;
    if (!xopen(&c, &a, fds)) ra = transport_room(&c);
    xclose(fds);
    if (!xopen(&c, &b, fds)) rb = transport_room(&c);
    xclose(fds);
    check(ra == rb && ra > 0, "tokenish without obfs: the room is repeat-X's");
}

static void t_xray_fields_replace_custom(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("stream-up", "sessionIDPlacement=header",
                             "Referer: https://x/\nX-Session: bad\nContent-Type: text/plain\n");
    int rc = xopen(&c, &n, fds);
    down_block(&g_hb);
    int r = hr_find(&g_hb, "referer"), s = hr_find(&g_hb, "x-session");
    check(rc == 0 && r >= 0 && hr_find_from(&g_hb, "referer", r + 1) < 0 &&
          strstr(g_hb.f[r].value, "x_padding=") != NULL,
          "custom Referer: one referer field, the padded one");
    check(s >= 0 && hr_find_from(&g_hb, "x-session", s + 1) < 0 && !strcmp(g_hb.f[s].value, c.xh.sid),
          "custom X-Session: one x-session field, the session id");
    up_block(0, &g_hb);
    int t = hr_find(&g_hb, "content-type");
    check(t >= 0 && hr_find_from(&g_hb, "content-type", t + 1) < 0 &&
          !strcmp(g_hb.f[t].value, "application/grpc"),
          "custom Content-Type: one content-type, application/grpc");
    xclose(fds);
}

static void t_custom_data_header_replaced(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "uplinkDataPlacement=header\nuplinkChunkSize=64",
                             "X-Data-0: bad\n");
    int rc = xopen(&c, &n, fds);
    unsigned char pl[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    int wr = transport_write(&c, pl, sizeof pl);
    srv_drain();
    up_block(0, &g_hb);
    int d = hr_find(&g_hb, "x-data-0");
    check(rc == 0 && wr == 0 && d >= 0 && hr_find_from(&g_hb, "x-data-0", d + 1) < 0 &&
          strcmp(g_hb.f[d].value, "bad"), "custom X-Data-0: one x-data-0, the data");
    xclose(fds);
}

static size_t decode_cookie_req(int k, unsigned char *out, size_t cap, int *bad, size_t *lens,
                                int *order_ok) {
    static char b64[32768];
    static const char *ck[HR_MAX];
    size_t n = 0;
    *bad = 1;
    if (up_block(k, &g_hb)) return 0;
    int m = cookies(&g_hb, ck, HR_MAX), i = 0;
    for (; i < m; i++) {
        char pre[32];
        snprintf(pre, sizeof pre, "x_data_%d=", i);
        if (strncmp(ck[i], pre, strlen(pre))) break;
        const char *v = ck[i] + strlen(pre);
        if (lens && i < 8) lens[i] = strlen(v);
        if (n + strlen(v) >= sizeof b64) return 0;
        memcpy(b64 + n, v, strlen(v));
        n += strlen(v);
    }
    b64[n] = '\0';
    if (order_ok) *order_ok = i > 0 && i + 3 == m && !strncmp(ck[i], "x_padding=", 10) &&
                             !strncmp(ck[i + 1], "x_session=", 10) && !strncmp(ck[i + 2], "x_seq=", 6);
    int dn = xc_b64url_decode(b64, out, cap);
    *bad = dn <= 0;
    return dn > 0 ? (size_t)dn : 0;
}

static void t_data_cookie(void) {
    int fds[2];
    struct transport c;
    const char *xhx = "uplinkDataPlacement=cookie\nuplinkChunkSize=64\nxPaddingObfsMode=true\n"
                      "xPaddingPlacement=cookie\nsessionIDPlacement=cookie\nseqPlacement=cookie";
    struct tr_node n = xnode("packet-up", xhx, NULL);
    int rc = xopen(&c, &n, fds);
    unsigned char pl[100];
    for (int i = 0; i < 100; i++) pl[i] = (unsigned char)(i * 53 + 5);
    int wr = transport_write(&c, pl, sizeof pl);
    srv_drain();
    unsigned char dec[200];
    size_t lens[8] = { 0 };
    int bad, order = 0;
    size_t dn = decode_cookie_req(0, dec, sizeof dec, &bad, lens, &order);
    check(rc == 0 && wr == 0 && hr_count_frames(g_seen, g_seen_n, 0x00) == 0 &&
          (hr_nth_headers_flags(g_seen, g_seen_n, 0) & 0x01),
          "data in cookies: no DATA frame, the request ends with its HEADERS");
    check(lens[0] == 64 && lens[1] == 64 && lens[2] == 6 && lens[3] == 0,
          "data in cookies: x_data_0..2 of 64, 64 and 6 characters");
    check(order, "data in cookies: data cookies, then padding, session, seq");
    check(!bad && dn == 100 && !memcmp(dec, pl, 100), "data in cookies: the pieces decode to the payload");
    xclose(fds);
}

static void t_data_cookie_budget(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "uplinkDataPlacement=cookie\nuplinkChunkSize=64", NULL);
    n.post_from = n.post_to = 1000000;
    int rc = xopen(&c, &n, fds);
    static unsigned char pl[12000], dec[16000];
    for (size_t i = 0; i < sizeof pl; i++) pl[i] = (unsigned char)(i * 71 + 1);
    int wr = transport_write(&c, pl, sizeof pl);
    srv_drain();
    int reqs = hr_count_frames(g_seen, g_seen_n, 0x01), over = 0, bad = 0;
    size_t got = 0;
    for (int k = 0; k < reqs && !over && !bad; k++) {
        got += decode_cookie_req(k, dec + got, sizeof dec - got, &bad, NULL, NULL);
        if (hr_list_size(&g_hb) > 8192) over = 1;
    }
    check(rc == 0 && wr == 0 && reqs > 1 && !over && !bad && got == sizeof pl &&
          !memcmp(dec, pl, sizeof pl),
          "data in cookies, 64-char pieces: every request within 8192, bytes whole");
    xclose(fds);
}

static int unanswered_until_full(struct transport *c) {
    int k = 0;
    while (k < 200 && transport_write(c, piece, sizeof piece) == 0) { srv_drain(); k++; }
    srv_drain();
    return k;
}

static void t_packet_window_follows_posts(void) {
    int fds[2];
    struct transport c;
    struct tr_node n = xnode("packet-up", "scMaxBufferedPosts=12", NULL);
    int rc = xopen(&c, &n, fds);
    check(rc == 0 && unanswered_until_full(&c) == 12, "packet-up: scMaxBufferedPosts 12 leaves 12 chunks unanswered");
    xclose(fds);
    n = xnode("packet-up", NULL, NULL);
    rc = xopen(&c, &n, fds);
    check(rc == 0 && unanswered_until_full(&c) == 24, "packet-up: without scMaxBufferedPosts 24 chunks unanswered");
    xclose(fds);
    n = xnode("packet-up", "scMaxBufferedPosts=500", NULL);
    rc = xopen(&c, &n, fds);
    check(rc == 0 && unanswered_until_full(&c) == H2_OPEN_MAX, "packet-up: a large scMaxBufferedPosts stops at H2_OPEN_MAX");
    xclose(fds);
    n = xnode("packet-up", "scMaxBufferedPosts=40", NULL);
    rc = xopen(&c, &n, fds);
    int w0 = transport_write(&c, piece, sizeof piece);
    unsigned char st[15] = { 0, 0, 6, 0x04, 0, 0, 0, 0, 0, 0, 0x03, 0, 0, 0, 5 };
    if (write(g_srv, st, sizeof st) != (ssize_t)sizeof st) { perror("write"); exit(2); }
    srv_drain();
    check(rc == 0 && w0 == 0 && unanswered_until_full(&c) == 4,
          "packet-up: the server's MAX_CONCURRENT_STREAMS 5 bounds the unanswered chunks");
    xclose(fds);
}

int main(void) {
    t_seq_cookie_after_session();
    t_tokenish_without_obfs_is_repeat_x();
    t_xray_fields_replace_custom();
    t_custom_data_header_replaced();
    t_data_cookie();
    t_data_cookie_budget();
    t_referer_without_session();
    t_session_header();
    t_session_and_seq_header();
    t_seq_and_session_query_sorted();
    t_obfs_cookie();
    t_obfs_query_in_header_default();
    t_obfs_query_long();
    t_method_put();
    t_data_header();
    t_data_budget_first_request();
    t_data_budget_after_settings();
    t_budget_too_small_fails_with_reason();
    t_custom_headers_first();
    t_custom_accept_replaces();
    t_ipv6_authority_in_brackets();
    t_literal_ua_drops_look();
    t_chrome_ua_keeps_look();
    t_room_worst_padding();
    t_packet_up_order();
    t_packet_up(0x8C, 1, "packet-up: 400 to the previous chunk fails the next write, naming 400");
    t_packet_up(0x88, 0, "packet-up: 200 to the previous chunk is read and is not a refusal");
    t_packet_up_window();
    t_packet_window_follows_posts();
    t_packet_up_rst();
    t_stream_up(0x8C, 1, "stream-up: 400 to the upload fails the write, naming 400");
    t_stream_up(0x88, 0, "stream-up: 200 to the upload is read and is not a refusal");
    printf(g_fail ? "\nxhupmatch: FAILED\n" : "\nall checks passed\n");
    return g_fail;
}

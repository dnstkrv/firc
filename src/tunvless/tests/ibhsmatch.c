#include "unit.h"
#include "../src/tunnel/ibhs.h"
#include <stdlib.h>

static struct ibhs H;
static struct ib_cfg C;
static unsigned char O[IBHS_OUT];
static size_t ON;

static void reset(const char *user, const char *pass) {
    memset(&C, 0, sizeof C);
    if (user) strcpy(C.user, user);
    if (pass) strcpy(C.pass, pass);
    memset(&H, 0xaa, sizeof H);
    ibhs_init(&H, &C);
    ON = 0;
}

static size_t unhex(const char *hex, unsigned char *b) {
    size_t n = 0;
    for (; *hex; hex++) {
        if (*hex == ' ') continue;
        char t[3] = {hex[0], hex[1], 0};
        b[n++] = (unsigned char)strtol(t, NULL, 16);
        hex++;
    }
    return n;
}

static enum ibhs_rc fb(const unsigned char *b, size_t n) { return ibhs_feed(&H, &C, b, n, O, &ON); }

static enum ibhs_rc fh(const char *hex) {
    unsigned char b[2048];
    size_t n = unhex(hex, b);
    return fb(b, n);
}

static enum ibhs_rc fs(const char *s) { return fb((const unsigned char *)s, strlen(s)); }

static void out_is(const char *what, const char *hex) {
    unsigned char w[IBHS_OUT];
    size_t n = unhex(hex, w);
    check(what, (long)n, (long)ON);
    if (ON == n) check_mem(what, w, O, n);
}

static void out_str(const char *what, const char *s) {
    check(what, (long)strlen(s), (long)ON);
    if (ON == strlen(s)) check_mem(what, s, O, ON);
}

/* catches: a method choice answered with anything but 05 00, or a dest parsed wrong */
static void socks_no_auth_connect_ipv4(void) {
    reset(NULL, NULL);
    check("greeting rc", IBHS_REPLY, fh("05 01 00"));
    out_is("greeting out", "05 00");
    check("request rc", IBHS_CONNECT, fh("05 01 00 01 5d b8 d8 22 01 bb"));
    check("ip", 0x5db8d822, (long)H.ip);
    check("port", 443, H.port);
    check_str("host empty", "", H.host);
    check("no out", 0, (long)ON);
}

/* catches: a domain length byte mis-read or the port taken from the wrong offset */
static void socks_domain(void) {
    reset(NULL, NULL);
    fh("05 01 00");
    check("rc", IBHS_CONNECT, fh("05 01 00 03 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 00 50"));
    check_str("host", "example.com", H.host);
    check("port", 80, H.port);
    check("ip", 0, (long)H.ip);
}

/* catches: bytes after the greeting dropped or the request not parsed in the same call */
static void greeting_and_request_in_one_read(void) {
    reset(NULL, NULL);
    check("rc", IBHS_CONNECT, fh("05 01 00 05 01 00 01 01 02 03 04 00 50"));
    out_is("out", "05 00");
    check("ip", 0x01020304, (long)H.ip);
    check("port", 80, H.port);
}

/* catches: state lost between reads, or a reply sent twice */
static void request_a_byte_at_a_time(void) {
    unsigned char b[32];
    size_t n = unhex("05 01 00 05 01 00 01 01 02 03 04 00 50", b);
    reset(NULL, NULL);
    for (size_t i = 0; i < n; i++) {
        enum ibhs_rc rc = fb(b + i, 1);
        if (i == 2) {
            check("greeting rc", IBHS_REPLY, rc);
            out_is("greeting out", "05 00");
        } else if (i == n - 1) {
            check("final rc", IBHS_CONNECT, rc);
            check("no out", 0, (long)ON);
        } else {
            check("more", IBHS_MORE, rc);
            check("silent", 0, (long)ON);
        }
    }
    check("ip", 0x01020304, (long)H.ip);
    check("port", 80, H.port);
}

/* catches: a phase left in buf, so three phases over 600 bytes overflow it */
static void pipelined_greeting_auth_request(void) {
    unsigned char in[1100], tail[] = "early";
    char u[256], p[256], host[256];
    memset(u, 'u', 255);
    u[255] = 0;
    memset(p, 'p', 255);
    p[255] = 0;
    memset(host, 'h', 255);
    host[255] = 0;
    reset(u, p);
    size_t n = unhex("05 01 02", in);
    in[n++] = 0x01;
    in[n++] = 255;
    memcpy(in + n, u, 255);
    n += 255;
    in[n++] = 255;
    memcpy(in + n, p, 255);
    n += 255;
    n += unhex("05 01 00 03 ff", in + n);
    memcpy(in + n, host, 255);
    n += 255;
    n += unhex("1f 90", in + n);
    memcpy(in + n, tail, 5);
    n += 5;
    check("total over one buf", 1, n > sizeof H.buf);
    check("rc", IBHS_CONNECT, fb(in, n));
    out_is("out", "05 02 01 00");
    check_str("host", host, H.host);
    check("port", 8080, H.port);
    const unsigned char *r;
    size_t rn = ibhs_rest(&H, &r);
    check("rest len", 5, (long)rn);
    if (rn == 5) check_mem("rest", "early", r, 5);
}

/* catches: no-auth accepted by a listener that has credentials */
static void auth_required_offers_only_02(void) {
    reset("alice", "s t");
    check("rc", IBHS_FAIL, fh("05 01 00"));
    out_is("out", "05 ff");
    reset("alice", "s t");
    check("offered rc", IBHS_REPLY, fh("05 02 00 02"));
    out_is("offered out", "05 02");
}

/* catches: a correct login refused */
static void auth_good(void) {
    reset("alice", "s t");
    fh("05 01 02");
    check("rc", IBHS_REPLY, fh("01 05 61 6c 69 63 65 03 73 20 74"));
    out_is("out", "01 00");
    check("request", IBHS_CONNECT, fh("05 01 00 01 01 02 03 04 00 50"));
}

/* catches: a wrong password, wrong user or short login let through */
static void auth_bad(void) {
    reset("alice", "s t");
    fh("05 01 02");
    check("wrong pass rc", IBHS_FAIL, fh("01 05 61 6c 69 63 65 03 73 20 78"));
    out_is("wrong pass out", "01 01");
    reset("alice", "s t");
    fh("05 01 02");
    check("wrong user rc", IBHS_FAIL, fh("01 05 61 6c 69 63 66 03 73 20 74"));
    out_is("wrong user out", "01 01");
    reset("alice", "s t");
    fh("05 01 02");
    check("prefix pass rc", IBHS_FAIL, fh("01 05 61 6c 69 63 65 02 73 20"));
    reset("alice", "s t");
    fh("05 01 02");
    check("bad version rc", IBHS_FAIL, fh("02 05 61 6c 69 63 65 03 73 20 74"));
    out_is("bad version out", "01 01");
}

/* catches: an empty configured password matching the PLEN 0 of a login (fail open) */
static void auth_empty_password_never_matches(void) {
    reset("alice", NULL);
    fh("05 01 02");
    check("rc", IBHS_FAIL, fh("01 05 61 6c 69 63 65 00"));
    out_is("out", "01 01");
}

/* catches: BIND served, or the reply carrying the wrong code or address */
static void bind_is_07(void) {
    reset(NULL, NULL);
    fh("05 01 00");
    check("rc", IBHS_FAIL, fh("05 02 00 01 00 00 00 00 00 00"));
    out_is("out", "05 07 00 01 00 00 00 00 00 00");
}

/* catches: an unknown command treated as CONNECT */
static void unknown_cmd_is_07(void) {
    reset(NULL, NULL);
    fh("05 01 00");
    check("rc", IBHS_FAIL, fh("05 09 00 01 01 02 03 04 00 50"));
    out_is("out", "05 07 00 01 00 00 00 00 00 00");
}

/* catches: ATYP 4 read as ATYP 1 and the next bytes taken as a port */
static void ipv6_atyp_is_refused(void) {
    reset(NULL, NULL);
    fh("05 01 00");
    check("rc", IBHS_FAIL, fh("05 01 00 04 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 00 50"));
    out_is("out", "05 08 00 01 00 00 00 00 00 00");
}

/* catches: an empty domain dialled */
static void domain_len_zero_is_refused(void) {
    reset(NULL, NULL);
    fh("05 01 00");
    check("rc", IBHS_FAIL, fh("05 01 00 03 00 00 50"));
    out_is("out", "05 08 00 01 00 00 00 00 00 00");
}

/* catches: UDP ASSOCIATE answered as a stream */
static void udp_associate(void) {
    reset(NULL, NULL);
    fh("05 01 00");
    check("rc", IBHS_UDP, fh("05 03 00 01 00 00 00 00 00 00"));
}

/* catches: host, port or early data taken from the wrong place of the request line */
static void http_connect(void) {
    reset(NULL, NULL);
    check("rc", IBHS_CONNECT, fs("CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\nEARLY"));
    check_str("host", "example.com", H.host);
    check("port", 443, H.port);
    check("ip", 0, (long)H.ip);
    check("http", 1, H.http != 0);
    check("no out", 0, (long)ON);
    const unsigned char *r;
    size_t rn = ibhs_rest(&H, &r);
    check("rest len", 5, (long)rn);
    if (rn == 5) check_mem("rest", "EARLY", r, 5);
}

/* catches: a request split mid-header dropped, or no rest with a bare request */
static void http_connect_split_reads(void) {
    reset(NULL, NULL);
    check("part 1", IBHS_MORE, fs("CONNECT a.b:8"));
    check("part 2", IBHS_MORE, fs("0 HTTP/1.1\r\nX: y\r"));
    check("part 3", IBHS_CONNECT, fs("\n\r\n"));
    check_str("host", "a.b", H.host);
    check("port", 80, H.port);
    const unsigned char *r;
    check("rest empty", 0, (long)ibhs_rest(&H, &r));
}

/* catches: an IP literal dialled as a name */
static void http_ip_literal_fills_ip(void) {
    reset(NULL, NULL);
    check("rc", IBHS_CONNECT, fs("CONNECT 1.2.3.4:25 HTTP/1.1\r\n\r\n"));
    check("ip", 0x01020304, (long)H.ip);
    check_str("host empty", "", H.host);
    check("port", 25, H.port);
}

/* catches: another method tunnelled */
static void http_get_is_405(void) {
    reset(NULL, NULL);
    check("rc", IBHS_FAIL, fs("GET http://x/ HTTP/1.1\r\n\r\n"));
    out_str("out", "HTTP/1.1 405 Method Not Allowed\r\n\r\n");
}

/* catches: a request without credentials served by a listener that has them */
static void http_no_auth_is_407(void) {
    reset("alice", "s t");
    check("rc", IBHS_FAIL, fs("CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"));
    out_str("out",
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"firc\"\r\n\r\n");
}

/* catches: Basic credentials mis-decoded, the header name case-sensitive, or a wrong login let in */
static void http_basic_auth(void) {
    reset("alice", "s t");
    check("good", IBHS_CONNECT,
          fs("CONNECT e.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cyB0\r\n\r\n"));
    reset("alice", "s t");
    check("lower case", IBHS_CONNECT,
          fs("CONNECT e.com:443 HTTP/1.1\r\nHost: x\r\nproxy-authorization:   basic YWxpY2U6cyB0\r\n\r\n"));
    reset("alice", "s t");
    check("wrong pass", IBHS_FAIL,
          fs("CONNECT e.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cyB4\r\n\r\n"));
    check("407", 1, ON > 12 && memcmp(O, "HTTP/1.1 407", 12) == 0);
    reset("alice", "s t");
    check("not base64", IBHS_FAIL,
          fs("CONNECT e.com:443 HTTP/1.1\r\nProxy-Authorization: Basic !!!!\r\n\r\n"));
    reset("alice", "s t");
    check("bearer", IBHS_FAIL,
          fs("CONNECT e.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer YWxpY2U6cyB0\r\n\r\n"));
}

/* catches: a password holding ':' cut at the wrong colon */
static void http_basic_password_with_colon(void) {
    reset("alice", "a:b");
    check("rc", IBHS_CONNECT,
          fs("CONNECT e.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6YTpi\r\n\r\n"));
}

/* catches: an unbounded header buffer */
static void http_header_over_600_fails(void) {
    char big[700];
    memset(big, 'a', sizeof big);
    memcpy(big, "CONNECT x:1 HTTP/1.1\r\nX: ", 25);
    reset(NULL, NULL);
    check("rc", IBHS_FAIL, fb((unsigned char *)big, sizeof big));
    out_str("out", "HTTP/1.1 400 Bad Request\r\n\r\n");
    reset(NULL, NULL);
    check("trickle", IBHS_MORE, fb((unsigned char *)big, 599));
    check("600th byte", IBHS_FAIL, fb((unsigned char *)big, 1));
}

/* catches: a host the dialer would truncate, a port out of range, an IPv6 literal */
static void http_bad_target_is_400(void) {
    char req[400], host[300];
    memset(host, 'h', 256);
    host[256] = 0;
    snprintf(req, sizeof req, "CONNECT %s:443 HTTP/1.1\r\n\r\n", host);
    reset(NULL, NULL);
    check("host 256", IBHS_FAIL, fs(req));
    out_str("out", "HTTP/1.1 400 Bad Request\r\n\r\n");
    host[255] = 0;
    snprintf(req, sizeof req, "CONNECT %s:443 HTTP/1.1\r\n\r\n", host);
    reset(NULL, NULL);
    check("host 255", IBHS_CONNECT, fs(req));
    const char *bad[] = {"CONNECT [::1]:443 HTTP/1.1\r\n\r\n", "CONNECT a.b:0 HTTP/1.1\r\n\r\n",
                         "CONNECT a.b:65536 HTTP/1.1\r\n\r\n", "CONNECT a.b HTTP/1.1\r\n\r\n",
                         "CONNECT :443 HTTP/1.1\r\n\r\n", "CONNECT a.b:4x HTTP/1.1\r\n\r\n",
                         "CONNECT a.b:443\r\n\r\n"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        reset(NULL, NULL);
        check(bad[i], IBHS_FAIL, fs(bad[i]));
        out_str("out", "HTTP/1.1 400 Bad Request\r\n\r\n");
    }
    reset(NULL, NULL);
    check("port 65535", IBHS_CONNECT, fs("CONNECT a.b:65535 HTTP/1.1\r\n\r\n"));
    check("port", 65535, H.port);
}

/* catches: a NUL, ':' or control byte inside a SOCKS domain reaching the dialer */
static void socks_domain_bad_bytes_is_08(void) {
    const char *bad[] = {"05 01 00 03 05 61 00 62 2e 63 00 50", "05 01 00 03 03 3a 3a 31 00 50",
                         "05 01 00 03 03 61 0a 62 00 50", "05 01 00 03 03 61 7f 62 00 50",
                         "05 01 00 03 03 61 1f 62 00 50"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        reset(NULL, NULL);
        fh("05 01 00");
        check(bad[i], IBHS_FAIL, fh(bad[i]));
        out_is("out", "05 08 00 01 00 00 00 00 00 00");
    }
    reset(NULL, NULL);
    fh("05 01 00");
    check("space and 0x20 ok", IBHS_CONNECT, fh("05 01 00 03 03 61 20 62 00 50"));
}

/* catches: a request with VER other than 5 answered as an unknown command or served */
static void socks_request_bad_version_is_01(void) {
    reset(NULL, NULL);
    fh("05 01 00");
    check("rc", IBHS_FAIL, fh("04 01 00 01 01 02 03 04 00 50"));
    out_is("out", "05 01 00 01 00 00 00 00 00 00");
    reset(NULL, NULL);
    fh("05 01 00");
    check("bad cmd rc", IBHS_FAIL, fh("04 09 00 01 01 02 03 04 00 50"));
    out_is("bad cmd out", "05 01 00 01 00 00 00 00 00 00");
}

/* catches: early data past buf dropped silently, or one byte too few accepted */
static void early_data_overflow_fails(void) {
    unsigned char in[700];
    size_t n = unhex("05 01 00 01 01 02 03 04 00 50", in);
    memset(in + n, 'e', 690);
    reset(NULL, NULL);
    fh("05 01 00");
    check("600 early rc", IBHS_CONNECT, fb(in, n + 600));
    const unsigned char *r;
    check("600 early rest", 600, (long)ibhs_rest(&H, &r));
    reset(NULL, NULL);
    fh("05 01 00");
    check("601 early rc", IBHS_FAIL, fb(in, n + 601));
    check("601 early out", 0, (long)ON);
}

/* catches: a NUL, ':' or control byte inside an HTTP CONNECT host reaching the dialer */
static void http_host_bad_bytes_is_400(void) {
    const char *bad[] = {"CONNECT a\x01" "b:443 HTTP/1.1\r\n\r\n", "CONNECT a\x7f" "b:443 HTTP/1.1\r\n\r\n",
                         "CONNECT ::1:443 HTTP/1.1\r\n\r\n", "CONNECT a:b:443 HTTP/1.1\r\n\r\n"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        reset(NULL, NULL);
        check(bad[i], IBHS_FAIL, fs(bad[i]));
        out_str("out", "HTTP/1.1 400 Bad Request\r\n\r\n");
    }
    unsigned char nul[] = "CONNECT a\0b:443 HTTP/1.1\r\n\r\n";
    reset(NULL, NULL);
    check("nul", IBHS_FAIL, fb(nul, sizeof nul - 1));
    out_str("nul out", "HTTP/1.1 400 Bad Request\r\n\r\n");
}

/* catches: a wrong status for a dial outcome, or a short cap overrun */
static void done_replies(void) {
    unsigned char b[128];
    check("socks ok len", 10, (long)ibhs_done(0, IBHS_END_OK, b, sizeof b));
    check_hex("socks ok", "05000001000000000000", b, 10);
    check("socks dial len", 10, (long)ibhs_done(0, IBHS_END_DIAL, b, sizeof b));
    check_hex("socks dial", "05040001000000000000", b, 10);
    ibhs_done(0, IBHS_END_GONE, b, sizeof b);
    check_hex("socks gone", "05030001000000000000", b, 10);
    ibhs_done(0, IBHS_END_FULL, b, sizeof b);
    check_hex("socks full", "05010001000000000000", b, 10);
    check("socks small cap", 0, (long)ibhs_done(0, IBHS_END_OK, b, 9));
    const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
    check("http ok len", (long)strlen(ok), (long)ibhs_done(1, IBHS_END_OK, b, sizeof b));
    check_mem("http ok", ok, b, strlen(ok));
    const char *dial = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
    check("http dial len", (long)strlen(dial), (long)ibhs_done(1, IBHS_END_DIAL, b, sizeof b));
    check_mem("http dial", dial, b, strlen(dial));
    const char *gone = "HTTP/1.1 503 Service Unavailable\r\n\r\n";
    check("http gone len", (long)strlen(gone), (long)ibhs_done(1, IBHS_END_GONE, b, sizeof b));
    check_mem("http gone", gone, b, strlen(gone));
    ibhs_done(1, IBHS_END_FULL, b, sizeof b);
    check_mem("http full", gone, b, strlen(gone));
    check("http small cap", 0, (long)ibhs_done(1, IBHS_END_OK, b, 10));
}

int main(void) {
    socks_no_auth_connect_ipv4();
    socks_domain();
    greeting_and_request_in_one_read();
    request_a_byte_at_a_time();
    pipelined_greeting_auth_request();
    auth_required_offers_only_02();
    auth_good();
    auth_bad();
    auth_empty_password_never_matches();
    bind_is_07();
    unknown_cmd_is_07();
    ipv6_atyp_is_refused();
    domain_len_zero_is_refused();
    udp_associate();
    http_connect();
    http_connect_split_reads();
    http_ip_literal_fills_ip();
    http_get_is_405();
    http_no_auth_is_407();
    http_basic_auth();
    http_basic_password_with_colon();
    http_header_over_600_fails();
    http_bad_target_is_400();
    socks_domain_bad_bytes_is_08();
    socks_request_bad_version_is_01();
    early_data_overflow_fails();
    http_host_bad_bytes_is_400();
    done_replies();
    return unit_done("ibhsmatch");
}

#define _GNU_SOURCE
#include "unit.h"
#include "../src/proto/transport/trdial.c"

static char g_err[4096];

static unsigned two_addrs(const char *host, struct in_addr out[ADDR_MAX]) {
    (void)host;
    out[0].s_addr = htonl(0x7f000002u);
    out[1].s_addr = htonl(0x7f000001u);
    return 2;
}

static int dial_logged(const char *host, uint16_t port) {
    int p[2];
    if (pipe(p) != 0) return -999;
    fflush(stderr);
    int save = dup(2);
    dup2(p[1], 2);
    int fd = tcp_connect(host, port, 2);
    fflush(stderr);
    dup2(save, 2);
    close(save);
    close(p[1]);
    ssize_t r = read(p[0], g_err, sizeof g_err - 1);
    close(p[0]);
    g_err[r > 0 ? r : 0] = 0;
    return fd;
}

static int listener(uint16_t *port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001u) };
    socklen_t al = sizeof a;
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0 ||
        getsockname(s, (struct sockaddr *)&a, &al) != 0) return -1;
    *port = ntohs(a.sin_port);
    return s;
}

int main(void) {
    uint16_t port = 0;
    int ls = listener(&port);
    check("a listener on 127.0.0.1", 1, ls >= 0);
    close(ls);
    char want[256];
    int fd = dial_logged("127.0.0.1", port);
    snprintf(want, sizeof want,
             "tunvless[warn]: 127.0.0.1:%u — node refused the TCP connection (nothing listens on that port)\n",
             port);
    /* catches: a closed port reported as a bare connect failure, or told untagged so fircd keeps it at info */
    check("closed port: refused", TR_ECONNREFUSED, fd);
    check_str("closed port: a warning naming the refusal", want, g_err);
    fd = dial_logged("127.0.0.1", port);
    /* catches: a dead node's every dial warned, flooding the journal while the pool keeps probing it */
    check("closed port again: refused", TR_ECONNREFUSED, fd);
    check_str("closed port again: held back", "", g_err);

    /* catches: an attempt still waiting at the deadline told as a refusal instead of silence */
    check("in flight at the deadline: timeout", TR_ECONNTIMEOUT, dial_fail(1, ECONNREFUSED));
    /* catches: a deadline with no answer at all told as some other failure */
    check("no error seen: timeout", TR_ECONNTIMEOUT, dial_fail(0, 0));
    /* catches: an unreachable host or network folded into refusal or timeout */
    check("host unreachable", TR_EUNREACH, dial_fail(0, EHOSTUNREACH));
    check("network unreachable", TR_EUNREACH, dial_fail(0, ENETUNREACH));
    /* catches: an unexpected errno mapped onto a specific cause it is not */
    check("other errno: generic", TR_ECONNECT, dial_fail(0, EACCES));
    /* catches: a connect code left without its own text, so the log falls back to a bare number */
    check("timeout has text", 1, tr_dial_strerror(TR_ECONNTIMEOUT) != NULL);
    check("unreachable has text", 1, tr_dial_strerror(TR_EUNREACH) != NULL);
    check("no node has text", 1, tr_dial_strerror(TR_ENONODE) != NULL);
    check("a TLS code is not a dial code", 1, tr_dial_strerror(TLS13_ETIMEOUT) == NULL);

    ls = listener(&port);
    check("a second listener on 127.0.0.1", 1, ls >= 0);
    g_resolve = two_addrs;
    check("two addresses pinned", 2, transport_pin_host("two"));
    fd = dial_logged("two", port);
    snprintf(want, sizeof want, "tunvless[info]: two:%u — connected after 1 of 2 addresses failed\n", port);
    /* catches: a connection made on a later address told untagged, or louder than the node it reached */
    check("connected after a failure: connected", 1, fd >= 0);
    check_str("connected after a failure: an info line", want, g_err);
    if (fd >= 0) close(fd);
    close(ls);
    return unit_done("dialmatch");
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

#include "../src/proto/transport/trdial.c"
#include "client.h"
#include "unit.h"

int run_quiet(const char *const argv[]) { (void)argv; return 0; }

enum act { A_END, A_CLOSE, A_WITH_DATA, A_DATA_LATER, A_HEAD_SPLIT, A_HOLD };

struct srv {
    pthread_t th;
    int fd;
    enum act act;
    unsigned char addr[16];
    size_t addr_n;
};

static struct srv g_srv[4];
static const enum act *g_plan;
static int g_dials;

static void put(int fd, const void *b, size_t n) {
    ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
    (void)w;
}

static void *srv_run(void *arg) {
    struct srv *s = arg;
    unsigned char req[1024];
    size_t n = 0;
    while (n < sizeof(req)) {
        ssize_t r = read(s->fd, req + n, sizeof(req) - n);
        if (r <= 0) break;
        n += (size_t)r;
        if (memmem(req, n, "\r\n\r\n", 4)) break;
    }
    if (n > 18) {
        size_t off = 18 + req[17];
        if (n > off + 4) {
            s->addr_n = req[off + 3] == 3 ? 16 : 4;
            if (n >= off + 4 + s->addr_n) memcpy(s->addr, req + off + 4, s->addr_n);
        }
    }
    static const unsigned char head[2] = { 0, 0 };
    static const char data[] = "HTTP/1.1 301 Moved\r\n\r\n";
    switch (s->act) {
    case A_END: break;
    case A_CLOSE: put(s->fd, head, 2); break;
    case A_WITH_DATA: {
        unsigned char both[2 + sizeof(data) - 1];
        memcpy(both, head, 2);
        memcpy(both + 2, data, sizeof(data) - 1);
        put(s->fd, both, sizeof(both));
        break;
    }
    case A_DATA_LATER:
        put(s->fd, head, 2);
        usleep(300000);
        put(s->fd, data, sizeof(data) - 1);
        break;
    case A_HEAD_SPLIT:
        put(s->fd, head, 1);
        usleep(300000);
        put(s->fd, head + 1, 1);
        usleep(300000);
        put(s->fd, data, sizeof(data) - 1);
        break;
    case A_HOLD: {
        put(s->fd, head, 2);
        unsigned char b;
        while (read(s->fd, &b, 1) > 0) {}
        break;
    }
    }
    close(s->fd);
    return NULL;
}

static int fake_dial(const char *host, uint16_t port, int timeout_s) {
    (void)host; (void)port;
    if (g_dials >= 4 || g_plan[g_dials] == A_END) return TR_ECONNECT;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return TR_ESOCK;
    struct srv *s = &g_srv[g_dials++];
    memset(s, 0, sizeof(*s));
    s->fd = sv[1];
    s->act = g_plan[g_dials - 1];
    pthread_create(&s->th, NULL, srv_run, s);
    sock_ready(sv[0], timeout_s);
    return sv[0];
}

static void node_plain(struct vless_node *n) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124");
    snprintf(n->type, sizeof(n->type), "%s", "tcp");
    snprintf(n->security, sizeof(n->security), "%s", "none");
}

static int run(int v6, const enum act *plan, int timeout_s, char *why, size_t why_n) {
    struct vless_node n;
    node_plain(&n);
    g_plan = plan;
    g_dials = 0;
    g_tcp_dial = fake_dial;
    why[0] = 0;
    int rc = v6 ? vless_probe6(&n, timeout_s, why, why_n) : vless_probe(&n, timeout_s, why, why_n);
    g_tcp_dial = NULL;
    for (int i = 0; i < g_dials; i++) pthread_join(g_srv[i].th, NULL);
    return rc;
}

static const unsigned char CF6[16] = { 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11 };
static const unsigned char GG6[16] = { 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88 };

static void check_sub(const char *what, const char *want, const char *got) {
    int ok = strstr(got, want) != NULL;
    printf("%-62s %s\n", what, ok ? "ok" : "FAIL");
    if (ok) { unit_pass++; return; }
    unit_fail++;
    printf("     want substring: %s\n     got:            %s\n", want, got);
}

int main(void) {
    char why[256];

    {
        /* catches: the IPv6 check passing on the VLESS response header alone */
        static const enum act p[] = { A_CLOSE, A_CLOSE, A_END };
        int rc = run(1, p, 3, why, sizeof why);
        check("v6 header then close: fails", TR_EIO, rc);
        check("v6 header then close: the second target is tried", 2, g_dials);
        check_mem("v6 header then close: first target 2606:4700:4700::1111", CF6, g_srv[0].addr, 16);
        check_mem("v6 header then close: second target 2001:4860:4860::8888", GG6, g_srv[1].addr, 16);
        check_sub("v6 header then close: the reason names the target", "the target sent no data", why);
    }
    {
        /* catches: a silent first target ending the IPv6 check before the second */
        static const enum act p[] = { A_CLOSE, A_WITH_DATA, A_END };
        int rc = run(1, p, 3, why, sizeof why);
        check("v6 first silent, second answers: passes", 0, rc);
        check("v6 first silent, second answers: two dials", 2, g_dials);
    }
    {
        /* catches: data in the same read as the header not counted as the target's answer */
        static const enum act p[] = { A_WITH_DATA, A_END };
        int rc = run(1, p, 3, why, sizeof why);
        check("v6 header and data in one read: passes", 0, rc);
        check("v6 header and data in one read: one dial", 1, g_dials);
        check_mem("v6 header and data in one read: target 2606:4700:4700::1111", CF6, g_srv[0].addr, 16);
    }
    {
        /* catches: the probe giving up after the read that carried the header */
        static const enum act p[] = { A_DATA_LATER, A_END };
        int rc = run(1, p, 3, why, sizeof why);
        check("v6 header, data in the next read: passes", 0, rc);
        check("v6 header, data in the next read: one dial", 1, g_dials);
    }
    {
        /* catches: a response header split over two reads taken as too short */
        static const enum act p[] = { A_HEAD_SPLIT, A_END };
        int rc = run(1, p, 3, why, sizeof why);
        check("v6 header split over reads, then data: passes", 0, rc);
    }
    {
        /* catches: silence after the header until the timeout counted as a pass */
        static const enum act p[] = { A_HOLD, A_HOLD, A_END };
        int rc = run(1, p, 1, why, sizeof why);
        check("v6 header then silence: fails", TR_EIO, rc);
        check("v6 header then silence: the second target is tried", 2, g_dials);
        check_sub("v6 header then silence: the reason names the target", "the target sent no data", why);
    }
    {
        /* catches: the IPv4 node check requiring the target's data */
        static const enum act p[] = { A_CLOSE, A_END };
        int rc = run(0, p, 3, why, sizeof why);
        check("v4 header then close: passes", 0, rc);
        check("v4 header then close: one dial", 1, g_dials);
        static const unsigned char one[4] = { 1, 1, 1, 1 };
        check_mem("v4 header then close: target 1.1.1.1", one, g_srv[0].addr, 4);
    }
    {
        /* catches: the IPv4 node check taking a header split over two reads as too short */
        static const enum act p[] = { A_HEAD_SPLIT, A_END };
        int rc = run(0, p, 3, why, sizeof why);
        check("v4 header split over reads: passes", 0, rc);
    }

    return unit_done("probematch");
}

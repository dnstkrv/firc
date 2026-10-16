#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */

#include "firc/listen.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "firc/log.h"

bool firc_listen_addr(const char *addr, uint16_t port, bool empty_is_any,
                      struct sockaddr_storage *sa, socklen_t *sa_len)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", addr != NULL ? addr : "");
    char *host = buf;
    size_t n = strlen(host);
    if (n >= 2 && host[0] == '[' && host[n - 1] == ']') {
        host[n - 1] = '\0';
        host++;
    }

    memset(sa, 0, sizeof(*sa));
    if (strchr(host, ':') != NULL || (empty_is_any && host[0] == '\0')) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        if (host[0] == '\0') {
            s6->sin6_addr = in6addr_any;
        } else if (inet_pton(AF_INET6, host, &s6->sin6_addr) != 1) {
            return false;
        }
        *sa_len = sizeof(*s6);
        return true;
    }
    struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &s4->sin_addr) != 1) { return false; }
    *sa_len = sizeof(*s4);
    return true;
}

static const char *proto_name(int type)
{
    return type == SOCK_DGRAM ? "udp" : "tcp";
}

static bool any6(const struct sockaddr_storage *sa)
{
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
    return sa->ss_family == AF_INET6 && memcmp(&s6->sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0;
}

static int open_one(int type, const struct sockaddr_storage *sa, socklen_t sa_len, unsigned opts);

static void describe_sa(char *out, size_t cap, const struct sockaddr_storage *sa, int type, int err)
{
    char host[INET6_ADDRSTRLEN] = "";
    uint16_t port = 0;
    if (sa->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &s6->sin6_addr, host, sizeof(host));
        port = ntohs(s6->sin6_port);
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &s4->sin_addr, host, sizeof(host));
        port = ntohs(s4->sin_port);
    }
    firc_listen_describe(out, cap, host, port, type, err);
}

static int open_any(const char *who, int type, const struct sockaddr_storage *sa, socklen_t sa_len,
                    unsigned opts, struct sockaddr_storage *tried)
{
    *tried = *sa;
    int fd = open_one(type, sa, sa_len, opts);
    if (fd != -EAFNOSUPPORT || !any6(sa)) { return fd; }
    uint16_t port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    struct sockaddr_storage v4;
    memset(&v4, 0, sizeof(v4));
    struct sockaddr_in *s4 = (struct sockaddr_in *)&v4;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(port);
    s4->sin_addr.s_addr = htonl(INADDR_ANY);
    fd = open_one(type, &v4, sizeof(*s4), opts);
    if (fd >= 0 && who != NULL) {
        FIRC_WARN("%s: IPv6 is not available on this router; listening on 0.0.0.0:%u/%s instead of [::]:%u", who,
                  port, proto_name(type), port);
    }
    *tried = v4;
    return fd;
}

int firc_listen_open(const char *who, int type, const struct sockaddr_storage *sa, socklen_t sa_len,
                     unsigned opts, char *why, size_t why_cap)
{
    struct sockaddr_storage tried;
    int fd = open_any(who, type, sa, sa_len, opts, &tried);
    if (fd < 0 && why != NULL) { describe_sa(why, why_cap, &tried, type, -fd); }
    return fd;
}

void firc_listen_name(int fd, int type, char *out, size_t cap)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    if (getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        snprintf(out, cap, "?/%s", proto_name(type));
        return;
    }
    char host[INET6_ADDRSTRLEN] = "";
    uint16_t port;
    if (sa.ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&sa;
        inet_ntop(AF_INET6, &s6->sin6_addr, host, sizeof(host));
        port = ntohs(s6->sin6_port);
        snprintf(out, cap, "[%s]:%u/%s", host, port, proto_name(type));
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)&sa;
        inet_ntop(AF_INET, &s4->sin_addr, host, sizeof(host));
        port = ntohs(s4->sin_port);
        snprintf(out, cap, "%s:%u/%s", host, port, proto_name(type));
    }
}

void firc_listen_describe(char *out, size_t cap, const char *addr, uint16_t port, int type, int err)
{
    const char *a = addr != NULL ? addr : "";
    bool bare6 = strchr(a, ':') != NULL && a[0] != '[';
    char reason[128];
    switch (err) {
    case EADDRINUSE:
        snprintf(reason, sizeof(reason), "address already in use (is another program using this port?)");
        break;
    case EADDRNOTAVAIL:
        snprintf(reason, sizeof(reason), "address not available (not an address of this router)");
        break;
    case EAFNOSUPPORT:
        snprintf(reason, sizeof(reason), "address family not supported (is IPv6 off on this router?)");
        break;
    default:
        snprintf(reason, sizeof(reason), "%s", strerror(err));
        if (reason[0] >= 'A' && reason[0] <= 'Z') { reason[0] = (char)(reason[0] - 'A' + 'a'); }
        break;
    }
    snprintf(out, cap, "%s%s%s:%u/%s: %s", bare6 ? "[" : "", a, bare6 ? "]" : "", port, proto_name(type), reason);
}

static int open_one(int type, const struct sockaddr_storage *sa, socklen_t sa_len, unsigned opts)
{
    int fd = socket(sa->ss_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { return -errno; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if ((opts & FIRC_LISTEN_DUAL_STACK) != 0 && sa->ss_family == AF_INET6) {
        int zero = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    }
    if ((opts & FIRC_LISTEN_PKTINFO) != 0) {
        if (sa->ss_family == AF_INET6) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
        }
        setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
    }
    if (bind(fd, (const struct sockaddr *)sa, sa_len) != 0 ||
        (type == SOCK_STREAM && listen(fd, 128) != 0)) {
        int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}

size_t firc_web_ports(uint16_t configured, uint16_t skip, uint16_t out[FIRC_WEB_PORTS_MAX]) {
    static const uint16_t fallback[] = {666, 999, 1666, 2666, 9999};
    size_t n = 0;
    out[n++] = configured;
    for (size_t i = 0; i < sizeof(fallback) / sizeof(fallback[0]); i++) {
        if (fallback[i] != configured && fallback[i] != skip) { out[n++] = fallback[i]; }
    }
    return n;
}

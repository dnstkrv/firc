#include "greatest.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <unistd.h>

#include "firc/events.h"
#include "firc/log.h"
#include "firc/logrep.h"
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>

#include "firc/loop.h"
#include "firc/netlink_watcher.h"
#include "firc/rtnl.h"

/* The one interface a message names, 0 for none, -1 for more than one. */
static int one_oif(const struct nlmsghdr *h) {
    int oifs[FIRC_NL_WATCHER_MAX_NEXTHOPS];
    size_t n = firc_nl_watcher_default_route_oifs(h, oifs, sizeof(oifs) / sizeof(oifs[0]));
    return n == 1 ? oifs[0] : n == 0 ? 0 : -1;
}

/* One route message as the kernel would send it. */
static struct nlmsghdr *route_msg(uint8_t *buf, uint16_t type, uint8_t dst_len, uint8_t rtm_type,
                                  uint8_t protocol, uint32_t oif) {
    memset(buf, 0, 256);
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = type;
    struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = dst_len;
    rtm->rtm_type = rtm_type;
    rtm->rtm_protocol = protocol;
    rtm->rtm_table = RT_TABLE_MAIN;
    if (oif != 0) { mnl_attr_put_u32(nlh, RTA_OIF, oif); }
    return nlh;
}

TEST a_default_route_names_its_interface(void) {
    uint8_t buf[256];
    ASSERT_EQ_FMT(7, one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("a default going away just as much", 7,
                   one_oif(route_msg(buf, RTM_DELROUTE, 0, RTN_UNICAST, RTPROT_DHCP, 7)), "%d");
    PASS();
}

/* Catches: a route firc wrote itself naming an interface, so every write triggers another. */
TEST a_route_of_firc_s_own_names_nothing(void) {
    uint8_t buf[256];
    ASSERT_EQ_FMT(0, one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, FIRC_RTPROT, 7)), "%d");
    PASS();
}

TEST only_default_routes_of_a_forwarding_type_name_an_interface(void) {
    uint8_t buf[256];
    ASSERT_EQ_FMTm("a more-specific route is not the interface's gateway", 0,
                   one_oif(route_msg(buf, RTM_NEWROUTE, 24, RTN_UNICAST, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("nor is a reject route at /0", 0,
                   one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNREACHABLE, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("nor an address or link message", 0,
                   one_oif(route_msg(buf, RTM_NEWADDR, 0, RTN_UNICAST, RTPROT_BOOT, 7)), "%d");
    ASSERT_EQ_FMTm("a default with no device names none", 0,
                   one_oif(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 0)), "%d");
    PASS();
}

static struct nlmsghdr *addr_msg(uint8_t *buf, uint16_t type, int family, uint32_t ifindex)
{
    memset(buf, 0, 256);
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = type;
    struct ifaddrmsg *ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
    ifa->ifa_family = (uint8_t)family;
    ifa->ifa_index = ifindex;
    return nlh;
}

/* Catches: an address going away not re-reading its interface, so a lost IPv6 address keeps its v6 route. */
TEST an_address_added_or_removed_names_its_interface(void) {
    uint8_t buf[256];
    ASSERT_EQ_FMT(5, firc_nl_watcher_addr_ifindex(addr_msg(buf, RTM_NEWADDR, AF_INET6, 5)), "%d");
    ASSERT_EQ_FMT(5, firc_nl_watcher_addr_ifindex(addr_msg(buf, RTM_DELADDR, AF_INET6, 5)), "%d");
    ASSERT_EQ_FMT(0, firc_nl_watcher_addr_ifindex(route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 5)), "%d");
    memset(buf, 0xff, sizeof(buf));
    struct nlmsghdr *bare = mnl_nlmsg_put_header(buf);
    bare->nlmsg_type = RTM_DELADDR;
    ASSERT_EQ_FMTm("a message too short for its header names nothing", 0, firc_nl_watcher_addr_ifindex(bare), "%d");
    PASS();
}

static struct nlmsghdr *link_msg(uint8_t *buf, uint16_t type, unsigned flags, const char *name) {
    memset(buf, 0, 256);
    struct nlmsghdr *h = mnl_nlmsg_put_header(buf);
    h->nlmsg_type = type;
    struct ifinfomsg *ifi = mnl_nlmsg_put_extra_header(h, sizeof(*ifi));
    ifi->ifi_flags = flags;
    ifi->ifi_index = 7;
    if (name != NULL) { mnl_attr_put_strz(h, IFLA_IFNAME, name); }
    return h;
}

TEST a_link_without_iff_up_or_deleted_is_reported_down(void) {
    uint8_t buf[256];
    char name[16];
    bool up = true;
    ASSERT(firc_nl_watcher_link_event(link_msg(buf, RTM_NEWLINK, 0, "nwg9"), name, sizeof(name), &up));
    ASSERT_STR_EQ("nwg9", name);
    ASSERT_FALSE(up);
    up = true;
    ASSERT(firc_nl_watcher_link_event(link_msg(buf, RTM_DELLINK, IFF_UP, "nwg9"), name, sizeof(name), &up));
    ASSERT_FALSEm("a deleted link is down whatever its last flags", up);
    ASSERT(firc_nl_watcher_link_event(link_msg(buf, RTM_NEWLINK, IFF_UP, "nwg9"), name, sizeof(name), &up));
    ASSERT(up);
    ASSERT_FALSE(firc_nl_watcher_link_event(link_msg(buf, RTM_NEWADDR, IFF_UP, "nwg9"), name, sizeof(name), &up));
    ASSERT_FALSEm("a link with no name is not reported",
                  firc_nl_watcher_link_event(link_msg(buf, RTM_NEWLINK, IFF_UP, NULL), name, sizeof(name), &up));
    struct nlmsghdr *exact = calloc(1, sizeof(*exact));
    ASSERT(exact != NULL);
    exact->nlmsg_len = sizeof(*exact);
    exact->nlmsg_type = RTM_NEWLINK;
    bool read = firc_nl_watcher_link_event(exact, name, sizeof(name), &up);
    free(exact);
    ASSERT_FALSEm("a message too short for its header is not read", read);
    PASS();
}

/* Catches: only the first leg of an ECMP default named. */
TEST a_multipath_default_names_every_one_of_its_legs(void) {
    uint8_t buf[256];
    struct nlmsghdr *nlh = route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 0);
    uint8_t nhbuf[64];
    memset(nhbuf, 0, sizeof(nhbuf));
    size_t off = 0;
    for (int k = 0; k < 2; k++) {
        struct rtnexthop *nh = (struct rtnexthop *)(void *)(nhbuf + off);
        nh->rtnh_len = (unsigned short)sizeof(*nh);
        nh->rtnh_ifindex = 8 + k;
        off += sizeof(*nh);
    }
    struct rtnexthop *again = (struct rtnexthop *)(void *)(nhbuf + off);
    again->rtnh_len = (unsigned short)sizeof(*again);
    again->rtnh_ifindex = 8;
    off += sizeof(*again);
    mnl_attr_put(nlh, RTA_MULTIPATH, (uint16_t)off, nhbuf);
    int oifs[FIRC_NL_WATCHER_MAX_NEXTHOPS];
    size_t n = firc_nl_watcher_default_route_oifs(nlh, oifs, sizeof(oifs) / sizeof(oifs[0]));
    ASSERT_EQ_FMTm("both legs, each once", (size_t)2, n, "%zu");
    ASSERT_EQ_FMT(8, oifs[0], "%d");
    ASSERT_EQ_FMTm("the second leg is named too", 9, oifs[1], "%d");
    PASS();
}

/* What the watcher logged while `body` ran. */
static void log_of(void (*body)(void), char *out, size_t cap) {
    out[0] = '\0';
    char path[] = "/tmp/firc-watcher-log.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { return; }
    firc_log_set_fd(fd);
    body();
    firc_log_set_fd(2);
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, out, cap - 1);
    out[n > 0 ? (size_t)n : 0] = '\0';
    close(fd);
    unlink(path);
}

/* How many interfaces come back from one ECMP default with `legs` devices. */
static size_t legs_named(int legs, int *oifs, size_t cap) {
    uint8_t buf[1024];
    struct nlmsghdr *nlh = route_msg(buf, RTM_NEWROUTE, 0, RTN_UNICAST, RTPROT_BOOT, 0);
    uint8_t nhbuf[256];
    memset(nhbuf, 0, sizeof(nhbuf));
    size_t off = 0;
    for (int k = 0; k < legs; k++) {
        struct rtnexthop *nh = (struct rtnexthop *)(void *)(nhbuf + off);
        nh->rtnh_len = (unsigned short)sizeof(*nh);
        nh->rtnh_ifindex = 20 + k;
        off += sizeof(*nh);
    }
    mnl_attr_put(nlh, RTA_MULTIPATH, (uint16_t)off, nhbuf);
    return firc_nl_watcher_default_route_oifs(nlh, oifs, cap);
}

static size_t probe_legs;
static size_t probe_named;
static void name_legs(void) {
    int oifs[FIRC_NL_WATCHER_MAX_NEXTHOPS];
    probe_named = legs_named((int)probe_legs, oifs, sizeof(oifs) / sizeof(oifs[0]));
}

/* Catches: a route that exactly fills the room warned about as dropped legs. */
TEST a_default_with_exactly_as_many_legs_as_there_is_room_for_keeps_them_all(void) {
    char log[512];
    probe_legs = FIRC_NL_WATCHER_MAX_NEXTHOPS;
    log_of(name_legs, log, sizeof(log));
    ASSERT_EQ_FMTm("every leg", (size_t)FIRC_NL_WATCHER_MAX_NEXTHOPS, probe_named, "%zu");
    ASSERTm("nothing was dropped, so nothing is said about dropping", strstr(log, "the rest are not looked at") == NULL);
    PASS();
}

/* Catches: a dropped leg past the room left unsaid. */
TEST a_default_with_more_legs_than_there_is_room_for_says_so(void) {
    char log[512];
    probe_legs = FIRC_NL_WATCHER_MAX_NEXTHOPS + 1;
    log_of(name_legs, log, sizeof(log));
    ASSERT_EQ_FMTm("what fits", (size_t)FIRC_NL_WATCHER_MAX_NEXTHOPS, probe_named, "%zu");
    ASSERTm("the dropped leg is reported", strstr(log, "the rest are not looked at") != NULL);
    PASS();
}

/* Catches: a truncated last message read past the buffer (seen only under sanitize). */
TEST a_truncated_route_message_at_the_end_of_the_buffer_is_not_read(void) {
    struct nlmsghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.nlmsg_len = sizeof(hdr);
    hdr.nlmsg_type = RTM_NEWROUTE;
    struct nlmsghdr *exact = malloc(sizeof(hdr));
    ASSERT(exact != NULL);
    memcpy(exact, &hdr, sizeof(hdr));
    ASSERT_EQ_FMT(0, one_oif(exact), "%d");
    free(exact);
    PASS();
}

TEST a_truncated_route_message_names_nothing(void) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWROUTE;
    struct nlmsghdr *next = mnl_nlmsg_put_header(buf + nlh->nlmsg_len);
    next->nlmsg_type = RTM_NEWROUTE;
    struct rtmsg *rtm2 = mnl_nlmsg_put_extra_header(next, sizeof(*rtm2));
    rtm2->rtm_family = AF_INET;
    rtm2->rtm_type = RTN_UNICAST;
    rtm2->rtm_protocol = RTPROT_BOOT;
    mnl_attr_put_u32(next, RTA_OIF, 7);
    ASSERT_EQ_FMTm("nothing of the message that follows is read as this one's", 0, one_oif(nlh), "%d");
    PASS();
}

/* Catches: the watcher not joining the route groups, missing a reconnected WAN's gateway. */
TEST the_watcher_listens_for_route_changes_as_well_as_links_and_addresses(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(loop, NULL, NULL, NULL, NULL, NULL, NULL, &w));
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    socklen_t len = sizeof(sa);
    ASSERT_EQ(0, getsockname(firc_nl_watcher_fd(w), (struct sockaddr *)&sa, &len));
    ASSERTm("link", (sa.nl_groups & RTMGRP_LINK) != 0);
    ASSERTm("ipv4 addresses", (sa.nl_groups & RTMGRP_IPV4_IFADDR) != 0);
    ASSERTm("ipv6 addresses", (sa.nl_groups & RTMGRP_IPV6_IFADDR) != 0);
    ASSERTm("ipv4 routes", (sa.nl_groups & RTMGRP_IPV4_ROUTE) != 0);
    ASSERTm("ipv6 routes", (sa.nl_groups & RTMGRP_IPV6_ROUTE) != 0);
    firc_nl_watcher_destroy(w);
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: ENOBUFS read as a dead socket or as nothing, instead of lost state. */
TEST an_overrun_buffer_means_lost_state_not_a_dead_socket(void) {
    ASSERT_EQ_FMT(FIRC_NL_RECV_LOST, firc_nl_watcher_recv_verdict(ENOBUFS), "%d");
    ASSERT_EQ_FMTm("nothing more to read, for now", FIRC_NL_RECV_DRAINED, firc_nl_watcher_recv_verdict(EAGAIN),
                   "%d");
    ASSERT_EQ_FMTm("interrupted, not over", FIRC_NL_RECV_RETRY, firc_nl_watcher_recv_verdict(EINTR), "%d");
    ASSERT_EQ_FMTm("a socket that is no use any more", FIRC_NL_RECV_FATAL, firc_nl_watcher_recv_verdict(EBADF),
                   "%d");
    PASS();
}

static void count_lost(void *ud) { (*(int *)ud)++; }

/* Catches: a lost message not reported to the listener, or reading stopped after it. */
TEST a_lost_message_tells_the_listener_and_reading_goes_on(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int lost = 0;
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(loop, NULL, NULL, NULL, NULL, count_lost, &lost, &w));
    ASSERTm("read on: the socket is fine", firc_nl_watcher_handle_recv_error(w, ENOBUFS));
    ASSERT_EQ_FMTm("the listener was told", 1, lost, "%d");
    ASSERTm("a datagram that did not fit is lost too", firc_nl_watcher_handle_recv_error(w, ENOSPC));
    ASSERT_EQ_FMT(2, lost, "%d");
    ASSERTm("interrupted: read again", firc_nl_watcher_handle_recv_error(w, EINTR));
    ASSERT_EQ_FMTm("...and nothing was lost", 2, lost, "%d");
    ASSERT_FALSEm("nothing more to read, for now", firc_nl_watcher_handle_recv_error(w, EAGAIN));
    ASSERT_FALSEm("a socket that is no use any more", firc_nl_watcher_handle_recv_error(w, EBADF));
    ASSERT_EQ_FMTm("neither of those is a loss", 2, lost, "%d");
    firc_nl_watcher_destroy(w);
    firc_loop_destroy(loop);
    PASS();
}

static int warned_lost(const char *tail) {
    firc_event_t ev[32];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 32, &next, &dropped);
    int c = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].u.log.level == FIRC_LOG_WARN && strstr(ev[i].u.log.text, "netlink watcher lost messages") != NULL &&
            (tail == NULL || strstr(ev[i].u.log.text, tail) != NULL)) {
            c++;
        }
    }
    return c;
}

static uint64_t g_lost_ms;
static uint64_t lost_clock(void) { return g_lost_ms; }

/* Catches: every lost message warned, so a route burst floods the warnings, or the held ones never counted. */
TEST lost_messages_are_warned_once_a_minute_with_the_count(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(loop, NULL, NULL, NULL, NULL, NULL, NULL, &w));
    g_lost_ms = 1000;
    firc_logrep_set_clock_for_test(lost_clock);
    firc_event_reset_for_test();
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    for (int i = 0; i < 3; i++) { (void)firc_nl_watcher_handle_recv_error(w, ENOBUFS); }
    int first = warned_lost(NULL);
    g_lost_ms += 60000;
    (void)firc_nl_watcher_handle_recv_error(w, ENOBUFS);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    firc_logrep_set_clock_for_test(NULL);
    firc_nl_watcher_destroy(w);
    firc_loop_destroy(loop);
    ASSERT_EQ_FMT(1, first, "%d");
    ASSERT_EQ_FMT(1, warned_lost(" (2 more since the last)"), "%d");
    PASS();
}

typedef struct {
    firc_loop_t *loop;
    firc_nl_watcher_t *w;
    int lost;
    int fd_while_refused;
    struct rlimit saved;
    int64_t at[8];
    int64_t failed_at;
} reopen_t;

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void lost_then_stop(void *ud) {
    reopen_t *t = ud;
    if (t->lost < 8) { t->at[t->lost] = mono_ms(); }
    t->lost++;
    firc_loop_stop(t->loop);
}

static void lift_the_limit(firc_loop_t *loop, void *ud) {
    (void)loop;
    reopen_t *t = ud;
    t->fd_while_refused = firc_nl_watcher_fd(t->w);
    setrlimit(RLIMIT_NOFILE, &t->saved);
}

static void give_up(firc_loop_t *loop, void *ud) {
    (void)ud;
    firc_loop_stop(loop);
}

static uint64_t g_rep_ms = 1000;
static uint64_t rep_clock(void) { return g_rep_ms; }

static void five_minutes_pass(firc_loop_t *loop, void *ud) {
    (void)loop;
    (void)ud;
    g_rep_ms += 5 * 60 * 1000;
}

static int open_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) { return -1; }
    int n = 0;
    while (readdir(d) != NULL) { n++; }
    closedir(d);
    return n;
}

static int lowest_free_fd(void) {
    int fd = 0;
    while (fcntl(fd, F_GETFD) != -1) { fd++; }
    return fd;
}

/* Catches: a dead watcher socket left registered and deaf, retried at a fixed pace, warned at every try, not raised to ERROR after five minutes, left open, reopened without the state re-read, or its reopening not said with the count. */
TEST a_dead_socket_is_reopened_until_it_works_and_the_listener_told(void) {
    reopen_t t;
    memset(&t, 0, sizeof(t));
    t.fd_while_refused = -2;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&t.loop));
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(t.loop, NULL, NULL, NULL, NULL, lost_then_stop, &t, &t.w));
    int fds_before = open_fds();

    char logpath[] = "/tmp/firc_watcher_log_XXXXXX";
    int logfd = mkstemp(logpath);
    ASSERT(logfd >= 0);
    unlink(logpath);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    firc_log_set_fd(logfd);
    g_rep_ms = 1000;
    firc_logrep_set_clock_for_test(rep_clock);
    int64_t failed_at = mono_ms();
    ASSERT_FALSEm("a socket that is no use any more", firc_nl_watcher_handle_recv_error(t.w, EBADF));
    ASSERT_EQ_FMTm("closed, not left registered", -1, firc_nl_watcher_fd(t.w), "%d");
    ASSERT_EQ_FMTm("and nobody told yet", 0, t.lost, "%d");
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(t.loop, 1600, 0, lift_the_limit, &t, NULL));
    int bump = 0;
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(t.loop, 500, 3600000, five_minutes_pass, NULL, &bump));
    int guard = 0;
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(t.loop, 5000, 0, give_up, &t, &guard));
    ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &t.saved));
    struct rlimit tight = t.saved;
    tight.rlim_cur = (rlim_t)lowest_free_fd();
    ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &tight));

    ASSERT_EQ(FIRC_OK, firc_loop_run(t.loop));
    setrlimit(RLIMIT_NOFILE, &t.saved);
    firc_logrep_set_clock_for_test(NULL);
    firc_log_set_fd(2);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    firc_loop_del_timer(t.loop, guard);
    firc_loop_del_timer(t.loop, bump);
    char logbuf[4096] = {0};
    ssize_t got = pread(logfd, logbuf, sizeof(logbuf) - 1, 0);
    close(logfd);
    ASSERT(got > 0);
    int warned = 0;
    for (const char *p = logbuf; (p = strstr(p, " WRN ")) != NULL; p++) { warned++; }
    ASSERT_EQ_FMTm("four refused tries, one warning", 1, warned, "%d");
    ASSERTm(logbuf, strstr(logbuf, " WRN netlink watcher recv error: ") != NULL);
    int errs = 0;
    for (const char *p = logbuf; (p = strstr(p, " ERR netlink watcher socket not reopened yet: ")) != NULL; p++) { errs++; }
    ASSERT_EQ_FMTm("five minutes without a socket: one error", 1, errs, "%d");
    ASSERTm(logbuf, strstr(logbuf, " INF netlink watcher socket: recovered after 5 failures over ") != NULL);
    ASSERT_EQ_FMTm("the first reopens were refused", -1, t.fd_while_refused, "%d");
    ASSERT_EQ_FMTm("a later one worked and the listener re-read the state", 1, t.lost, "%d");
    ASSERTm("tries at 0.1, 0.3, 0.7, 1.5 s, so the one that works is at 3.1 s", t.at[0] - failed_at >= 3000);
    int fd = firc_nl_watcher_fd(t.w);
    ASSERT(fd >= 0);
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    socklen_t len = sizeof(sa);
    ASSERT_EQ(0, getsockname(fd, (struct sockaddr *)&sa, &len));
    ASSERT_EQ_FMTm("the same groups joined", (unsigned)(RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                                                       RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE),
                   sa.nl_groups, "%u");
    ASSERT_EQ_FMTm("the old socket is not kept open beside the new one", fds_before, open_fds(), "%d");
    ASSERT_EQ_FMTm("the new socket is read by the loop", FIRC_OK, firc_loop_del_fd(t.loop, fd), "%d");
    firc_nl_watcher_destroy(t.w);
    firc_loop_destroy(t.loop);
    PASS();
}

/* Catches: a reopen still pending when the watcher is destroyed, run on freed memory. */
TEST a_destroyed_watcher_reopens_nothing(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    int fds_before = open_fds();
    int lost = 0;
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(loop, NULL, NULL, NULL, NULL, count_lost, &lost, &w));
    ASSERT_FALSE(firc_nl_watcher_handle_recv_error(w, EBADF));
    firc_nl_watcher_destroy(w);
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 300, 0, give_up, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    ASSERT_EQ_FMT(0, lost, "%d");
    ASSERT_EQ_FMTm("nothing of the watcher is left open", fds_before, open_fds(), "%d");
    firc_loop_destroy(loop);
    PASS();
}

/* Catches: the reopen wait not doubling, not capped, or growing past five seconds. */
TEST the_reopen_wait_doubles_up_to_five_seconds(void) {
    const uint32_t want[] = {100, 200, 400, 800, 1600, 3200, 5000, 5000};
    for (unsigned i = 0; i < 8; i++) {
        ASSERT_EQ_FMT(want[i], firc_nl_watcher_reopen_delay_ms(i + 1), "%u");
    }
    ASSERT_EQ_FMT(5000u, firc_nl_watcher_reopen_delay_ms(1000), "%u");
    PASS();
}

static void fail_again_or_stop(void *ud) {
    reopen_t *t = ud;
    if (t->lost < 8) { t->at[t->lost] = mono_ms(); }
    t->lost++;
    if (t->lost < 2) {
        (void)firc_nl_watcher_handle_recv_error(t->w, EBADF);
    } else {
        firc_loop_stop(t->loop);
    }
}

/* Catches: the wait reset by a reopen alone, so a socket that dies at once is retried every 100 ms for ever. */
TEST a_socket_failing_again_before_it_reads_waits_longer(void) {
    reopen_t t;
    memset(&t, 0, sizeof(t));
    ASSERT_EQ(FIRC_OK, firc_loop_create(&t.loop));
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(t.loop, NULL, NULL, NULL, NULL, fail_again_or_stop, &t, &t.w));
    ASSERT_FALSE(firc_nl_watcher_handle_recv_error(t.w, EBADF));
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(t.loop, 5000, 0, give_up, &t, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(t.loop));
    ASSERT_EQ_FMT(2, t.lost, "%d");
    ASSERTm("the second reopen waited 200 ms", t.at[1] - t.at[0] >= 190);
    firc_nl_watcher_destroy(t.w);
    firc_loop_destroy(t.loop);
    PASS();
}

static bool poke_watcher(int fd) {
    struct sockaddr_nl me;
    memset(&me, 0, sizeof(me));
    socklen_t len = sizeof(me);
    if (getsockname(fd, (struct sockaddr *)&me, &len) != 0) { return false; }
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (s < 0) { return false; }
    struct sockaddr_nl to;
    memset(&to, 0, sizeof(to));
    to.nl_family = AF_NETLINK;
    to.nl_pid = me.nl_pid;
    struct nlmsghdr h;
    memset(&h, 0, sizeof(h));
    h.nlmsg_len = sizeof(h);
    h.nlmsg_type = NLMSG_NOOP;
    bool sent = sendto(s, &h, sizeof(h), 0, (struct sockaddr *)&to, sizeof(to)) == (ssize_t)sizeof(h);
    close(s);
    return sent;
}

static bool can_poke(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) { return false; }
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    bool ok = bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0 && poke_watcher(fd);
    close(fd);
    return ok;
}

static void fail_after_the_read(firc_loop_t *loop, void *ud) {
    (void)loop;
    reopen_t *t = ud;
    t->failed_at = mono_ms();
    (void)firc_nl_watcher_handle_recv_error(t->w, EBADF);
}

static void fail_thrice_then_read(void *ud) {
    reopen_t *t = ud;
    if (t->lost < 8) { t->at[t->lost] = mono_ms(); }
    t->lost++;
    if (t->lost < 3) {
        (void)firc_nl_watcher_handle_recv_error(t->w, EBADF);
    } else if (t->lost == 3) {
        (void)poke_watcher(firc_nl_watcher_fd(t->w));
        (void)firc_loop_add_timer(t->loop, 50, 0, fail_after_the_read, t, NULL);
    } else {
        firc_loop_stop(t->loop);
    }
}

/* Catches: a socket that read again still waited on as if it never had. */
TEST a_read_on_the_reopened_socket_resets_the_wait(void) {
    if (!can_poke()) { SKIPm("a netlink unicast needs CAP_NET_ADMIN; the gates run this in a user namespace"); }
    reopen_t t;
    memset(&t, 0, sizeof(t));
    ASSERT_EQ(FIRC_OK, firc_loop_create(&t.loop));
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(t.loop, NULL, NULL, NULL, NULL, fail_thrice_then_read, &t, &t.w));
    ASSERT_FALSE(firc_nl_watcher_handle_recv_error(t.w, EBADF));
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(t.loop, 5000, 0, give_up, &t, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(t.loop));
    ASSERT_EQ_FMT(4, t.lost, "%d");
    ASSERTm("100 ms after a read, not 800", t.at[3] - t.failed_at < 500);
    firc_nl_watcher_destroy(t.w);
    firc_loop_destroy(t.loop);
    PASS();
}

static bool send_to_watcher(int fd, const struct nlmsghdr *h) {
    struct sockaddr_nl me;
    memset(&me, 0, sizeof(me));
    socklen_t len = sizeof(me);
    if (getsockname(fd, (struct sockaddr *)&me, &len) != 0) { return false; }
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (s < 0) { return false; }
    struct sockaddr_nl to;
    memset(&to, 0, sizeof(to));
    to.nl_family = AF_NETLINK;
    to.nl_pid = me.nl_pid;
    bool sent = sendto(s, h, h->nlmsg_len, 0, (struct sockaddr *)&to, sizeof(to)) == (ssize_t)h->nlmsg_len;
    close(s);
    return sent;
}

typedef struct {
    firc_loop_t *loop;
    char names[4][16];
    bool ups[4];
    int n;
} links_seen_t;

static void record_link(const char *name, bool up, void *ud) {
    links_seen_t *s = ud;
    if (s->n < 4) {
        snprintf(s->names[s->n], sizeof(s->names[0]), "%s", name);
        s->ups[s->n] = up;
    }
    if (++s->n == 3) { firc_loop_stop(s->loop); }
}

TEST a_link_going_down_or_away_reaches_the_listener(void) {
    if (!can_poke()) { SKIPm("a netlink unicast needs CAP_NET_ADMIN; the gates run this in a user namespace"); }
    links_seen_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(FIRC_OK, firc_loop_create(&s.loop));
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(s.loop, record_link, &s, NULL, NULL, NULL, NULL, &w));
    uint8_t buf[256];
    int fd = firc_nl_watcher_fd(w);
    ASSERT(send_to_watcher(fd, link_msg(buf, RTM_NEWLINK, 0, "nwg1")));
    ASSERT(send_to_watcher(fd, link_msg(buf, RTM_DELLINK, IFF_UP, "nwg2")));
    ASSERT(send_to_watcher(fd, link_msg(buf, RTM_NEWLINK, IFF_UP, "nwg3")));
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(s.loop, 3000, 0, give_up, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(s.loop));
    ASSERT_EQ_FMT(3, s.n, "%d");
    ASSERT_STR_EQ("nwg1", s.names[0]);
    ASSERT_FALSE(s.ups[0]);
    ASSERT_STR_EQ("nwg2", s.names[1]);
    ASSERT_FALSE(s.ups[1]);
    ASSERT_STR_EQ("nwg3", s.names[2]);
    ASSERT(s.ups[2]);
    firc_nl_watcher_destroy(w);
    firc_loop_destroy(s.loop);
    PASS();
}

/* Catches: a failure reported while a reopen already waits arming a second timer. */
TEST a_second_failure_while_a_reopen_waits_adds_nothing(void) {
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_nl_watcher_t *w = NULL;
    ASSERT_EQ(FIRC_OK, firc_nl_watcher_create(loop, NULL, NULL, NULL, NULL, NULL, NULL, &w));
    ASSERT_FALSE(firc_nl_watcher_handle_recv_error(w, EBADF));
    int fds = open_fds();
    ASSERT_FALSE(firc_nl_watcher_handle_recv_error(w, EBADF));
    ASSERT_EQ_FMT(fds, open_fds(), "%d");
    firc_nl_watcher_destroy(w);
    firc_loop_destroy(loop);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_default_route_names_its_interface);
    RUN_TEST(an_address_added_or_removed_names_its_interface);
    RUN_TEST(a_link_without_iff_up_or_deleted_is_reported_down);
    RUN_TEST(a_route_of_firc_s_own_names_nothing);
    RUN_TEST(only_default_routes_of_a_forwarding_type_name_an_interface);
    RUN_TEST(a_multipath_default_names_every_one_of_its_legs);
    RUN_TEST(a_default_with_exactly_as_many_legs_as_there_is_room_for_keeps_them_all);
    RUN_TEST(a_default_with_more_legs_than_there_is_room_for_says_so);
    RUN_TEST(a_truncated_route_message_names_nothing);
    RUN_TEST(a_truncated_route_message_at_the_end_of_the_buffer_is_not_read);
    RUN_TEST(the_watcher_listens_for_route_changes_as_well_as_links_and_addresses);
    RUN_TEST(an_overrun_buffer_means_lost_state_not_a_dead_socket);
    RUN_TEST(a_lost_message_tells_the_listener_and_reading_goes_on);
    RUN_TEST(a_dead_socket_is_reopened_until_it_works_and_the_listener_told);
    RUN_TEST(lost_messages_are_warned_once_a_minute_with_the_count);
    RUN_TEST(a_destroyed_watcher_reopens_nothing);
    RUN_TEST(the_reopen_wait_doubles_up_to_five_seconds);
    RUN_TEST(a_socket_failing_again_before_it_reads_waits_longer);
    RUN_TEST(a_read_on_the_reopened_socket_resets_the_wait);
    RUN_TEST(a_second_failure_while_a_reopen_waits_adds_nothing);
    RUN_TEST(a_link_going_down_or_away_reaches_the_listener);
    GREATEST_MAIN_END();
}

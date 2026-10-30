#include "greatest.h"

#include <string.h>

#include "fake_nflog.h"
#include "firc/autolistrules.h"
#include "firc/autolistsvc.h"

static fake_nflog_t *kernels[3];
static uint16_t bound_group[3];
static int opened;

static firc_nflog_t *open_fake(uint16_t group, uint16_t copy_range) {
    if (opened >= 3) { return NULL; }
    int fd = -1;
    kernels[opened] = fake_nflog_start(&fd);
    if (kernels[opened] == NULL) { return NULL; }
    bound_group[opened] = group;
    opened++;
    return firc_nflog_open_fd(fd, group, copy_range);
}

static int64_t clock_now = 1000;
static int64_t fake_clock(void) { return clock_now; }

typedef struct {
    int listed;
    char host[FIRC_AUTOLIST_NAME_MAX];
    bool refuse;
} seen_t;

static bool eligible(void *ud, const firc_ip_t *client) {
    (void)client;
    return !((seen_t *)ud)->refuse;
}

static void listed(void *ud, const firc_autolist_failure_t *f) {
    seen_t *s = ud;
    s->listed++;
    memcpy(s->host, f->host, sizeof(s->host));
}

static const uint8_t CLIENT[4] = {192, 168, 1, 10};
static const uint8_t SERVER[4] = {203, 0, 113, 7};

static firc_autolist_svc_t *start(seen_t *seen) {
    memset(seen, 0, sizeof(*seen));
    opened = 0;
    firc_autolist_deps_t deps = {
        .nflog_open = open_fake, .now = fake_clock, .eligible = eligible, .listed = listed, .ud = seen};
    firc_err_t err;
    firc_autolist_svc_t *s = firc_autolist_svc_start(&deps, &err);
    if (s != NULL) {
        firc_autolist_params_t p = {2, 60, 1};
        firc_autolist_svc_set_params(s, &p);
    }
    return s;
}

static void stop(firc_autolist_svc_t *s) {
    firc_autolist_svc_stop(s);
    for (int i = 0; i < opened; i++) { fake_nflog_stop(kernels[i]); }
    opened = 0;
}

static bool push(firc_autolist_svc_t *s, int which, const uint8_t *pkt, size_t len) {
    _Alignas(4) uint8_t dg[2400];
    size_t dg_len = fake_nflog_msg(dg, pkt, len);
    if (!fake_nflog_send(kernels[which], dg, dg_len)) { return false; }
    return firc_autolist_svc_drain(s, which) == FIRC_OK;
}

static void set_ports(uint8_t *pkt, uint16_t sport, uint16_t dport) {
    pkt[20] = (uint8_t)(sport >> 8);
    pkt[21] = (uint8_t)sport;
    pkt[22] = (uint8_t)(dport >> 8);
    pkt[23] = (uint8_t)dport;
}

static bool hello(firc_autolist_svc_t *s, uint16_t client_port, const char *sni) {
    uint8_t rec[1024], pkt[1200];
    size_t rec_len = fake_nflog_hello(rec, sni);
    size_t len = fake_nflog_packet(pkt, CLIENT, SERVER, 443, rec, rec_len);
    set_ports(pkt, client_port, 443);
    pkt[27] = 7;
    return push(s, 0, pkt, len);
}

static bool reply(firc_autolist_svc_t *s, int which, uint16_t client_port, uint8_t flags) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, SERVER, CLIENT, client_port, none, 0);
    set_ports(pkt, 443, client_port);
    pkt[33] = flags;
    return push(s, which, pkt, len);
}

TEST the_readers_bind_the_three_groups(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ASSERT_EQ(3, opened);
    ASSERT_EQ(FIRC_AUTOLIST_GROUP_HELLO, bound_group[0]);
    ASSERT_EQ(FIRC_AUTOLIST_GROUP_RESET, bound_group[1]);
    ASSERT_EQ(FIRC_AUTOLIST_GROUP_WORKS, bound_group[2]);
    stop(s);
    PASS();
}

TEST resets_on_two_connections_list_the_host(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ASSERT(hello(s, 50001, "blocked.example.com"));
    ASSERT(reply(s, 1, 50001, 0x14));
    ASSERT_EQ(0, seen.listed);
    ASSERT(hello(s, 50002, "blocked.example.com"));
    ASSERT(reply(s, 1, 50002, 0x14));
    ASSERT_EQ(1, seen.listed);
    ASSERT_STR_EQ("blocked.example.com", seen.host);
    uint64_t failures = 0, n_listed = 0;
    firc_autolist_svc_counts(s, &failures, &n_listed);
    ASSERT_EQ(2u, (unsigned)failures);
    ASSERT_EQ(1u, (unsigned)n_listed);
    stop(s);
    PASS();
}

TEST a_hello_sent_again_is_a_failure(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "silent.example.com"));
        ASSERT(hello(s, port, "silent.example.com"));
    }
    ASSERT_EQ(1, seen.listed);
    stop(s);
    PASS();
}

TEST a_working_reply_keeps_the_host_off(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ASSERT(hello(s, 50001, "fine.example.com"));
    ASSERT(reply(s, 1, 50001, 0x14));
    ASSERT(hello(s, 50002, "fine.example.com"));
    ASSERT(reply(s, 2, 50002, 0x10));
    ASSERT(hello(s, 50003, "fine.example.com"));
    ASSERT(reply(s, 1, 50003, 0x14));
    ASSERT_EQ(0, seen.listed);
    stop(s);
    PASS();
}

TEST a_packet_on_the_reset_socket_without_rst_is_nothing(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "x.example.com"));
        ASSERT(reply(s, 1, port, 0x10));
    }
    ASSERT_EQ(0, seen.listed);
    stop(s);
    PASS();
}

TEST a_device_the_group_would_not_route_is_not_watched(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    seen.refuse = true;
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "x.example.com"));
        ASSERT(reply(s, 1, port, 0x14));
    }
    ASSERT_EQ(0, seen.listed);
    stop(s);
    PASS();
}

TEST a_hello_without_sni_is_named_by_the_dns_answer(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    firc_ip_t client = {{0}, 4}, server = {{0}, 4};
    memcpy(client.b, CLIENT, 4);
    memcpy(server.b, SERVER, 4);
    firc_autolist_svc_hint(s, &client, "asked.example.com", &server, 1);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, ""));
        ASSERT(reply(s, 1, port, 0x14));
    }
    ASSERT_EQ(1, seen.listed);
    ASSERT_STR_EQ("asked.example.com", seen.host);
    stop(s);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_readers_bind_the_three_groups);
    RUN_TEST(resets_on_two_connections_list_the_host);
    RUN_TEST(a_hello_sent_again_is_a_failure);
    RUN_TEST(a_working_reply_keeps_the_host_off);
    RUN_TEST(a_packet_on_the_reset_socket_without_rst_is_nothing);
    RUN_TEST(a_device_the_group_would_not_route_is_not_watched);
    RUN_TEST(a_hello_without_sni_is_named_by_the_dns_answer);
    GREATEST_MAIN_END();
}

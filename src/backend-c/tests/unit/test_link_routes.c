#include "greatest.h"

#include <sys/socket.h>
#include <linux/if.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <string.h>

#include "fake_iptables.h"
#include "fake_rtnl.h"
#include "firc/events.h"
#include "firc/ipset_to_link.h"
#include "firc/logrep.h"
#include "firc/pool_reject.h"
#include "firc/mark.h"
#include "firc/netfilter_cleaner.h"

typedef struct {
    firc_fake_ipt_t *fipt;
    firc_ipt_t *ipt;
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    firc_ipset_to_link_t *link;
} fixture_t;

/* A FIRC_g1 link on "lo" over fake iptables and rtnetlink with `link_flags`; every host has "lo". */
static bool up(fixture_t *f, unsigned link_flags) {
    memset(f, 0, sizeof(*f));
    f->fipt = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    f->ipt = f->fipt ? firc_ipt_new(firc_fake_ipt_as_xt(f->fipt), "FIRC_") : NULL;
    if (f->ipt == NULL) { return false; }
    firc_netfilter_register_base_chains(f->ipt, NULL);
    f->kernel = fake_rtnl_start(&f->rtnl);
    if (f->kernel == NULL) { return false; }
    fake_rtnl_set_link_flags(f->kernel, link_flags);
    f->link = firc_ipset_to_link_new("FIRC_g1", "lo", f->ipt, NULL, f->rtnl, 100, NULL, "g1", NULL, NULL);
    return f->link != NULL;
}

static void down(fixture_t *f) {
    firc_ipset_to_link_free(f->link);
    firc_rtnl_close(f->rtnl);
    fake_rtnl_stop(f->kernel);
    firc_ipt_free(f->ipt);
}

static firc_err_t pass_with(fixture_t *f, bool group) {
    firc_err_t err = firc_netfilter_register_base_chains(f->ipt, NULL);
    if (err == FIRC_OK && group) { err = firc_ipset_to_link_stage_for_test(f->link); }
    return err == FIRC_OK ? firc_ipt_commit(f->ipt) : err;
}

static size_t iface_routes(fixture_t *f, uint16_t type) {
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f->kernel, m, 64), c = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == type && m[i].rtm_type == RTN_UNICAST && m[i].oif == 1 && m[i].priority == 10 &&
            m[i].table == 100) {
            c++;
        }
    }
    return c;
}

/* Catches: a link-up skipping the default route add because the group remembers adding it once. */
TEST link_up_reinstalls_the_interface_route_even_when_nothing_changed(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    ASSERT_EQ_FMTm("enable installs the route once", (size_t)1, iface_routes(&f, RTM_NEWROUTE), "%zu");

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_link_up(f.link));
    ASSERT_EQ_FMTm("link-up re-adds it (a replace: a route still there is overwritten, a missing one made)",
                   (size_t)2, iface_routes(&f, RTM_NEWROUTE), "%zu");
    ASSERT_EQ_FMTm("without deleting anything first", (size_t)0, iface_routes(&f, RTM_DELROUTE), "%zu");
    down(&f);
    PASS();
}

/* Catches: a group's default or blackhole route written with EXCL, keeping a stale leftover. */
TEST a_groups_own_routes_replace_what_sits_at_the_key(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    size_t seen = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || (m[i].rtm_type != RTN_UNICAST && m[i].rtm_type != RTN_BLACKHOLE)) { continue; }
        seen++;
        ASSERTm("a replace", (m[i].flags & NLM_F_REPLACE) != 0);
        ASSERT_FALSEm("never exclusive", (m[i].flags & NLM_F_EXCL) != 0);
    }
    ASSERTm("the default and the blackhole", seen >= 2);
    down(&f);
    PASS();
}

/* Catches: a moved gateway added beside the old route, or read back from firc's own route. */
TEST a_changed_gateway_replaces_the_route(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1}, gw_b[4] = {10, 0, 0, 2};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_set_gateway(f.kernel, 1, gw_b, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));

    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    int seen_add_b = -1;
    size_t deletes = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].rtm_type != RTN_UNICAST || m[i].oif != 1) { continue; }
        if (m[i].type == RTM_DELROUTE) { deletes++; }
        if (m[i].type == RTM_NEWROUTE && m[i].gw_len == 4 && memcmp(m[i].gw, gw_b, 4) == 0 && (m[i].flags & NLM_F_REPLACE)) {
            seen_add_b = (int)i;
        }
    }
    ASSERTm("the route via the new gateway replaces the old one", seen_add_b >= 0);
    ASSERT_EQ_FMTm("nothing was deleted first: the table kept a default throughout", (size_t)0, deletes, "%zu");
    down(&f);
    PASS();
}

/* Catches: a teardown naming a gateway the route no longer has, so the default survives the group. */
TEST the_teardown_deletes_the_route_by_the_gateway_it_last_wrote(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1}, gw_b[4] = {10, 0, 0, 2};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_set_gateway(f.kernel, 1, gw_b, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(f.link));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    size_t dels = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_DELROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1) { continue; }
        dels++;
        ASSERT_EQ_FMTm("with the gateway last written", 4, m[i].gw_len, "%d");
        ASSERT_EQ_FMTm("the new gateway, not the one from enable", 0, memcmp(m[i].gw, gw_b, 4), "%d");
    }
    ASSERT_EQ_FMT((size_t)1, dels, "%zu");
    down(&f);
    PASS();
}

/* Catches: a failed gateway lookup rewriting the route as a device route. */
TEST a_failed_gateway_lookup_keeps_the_gateway_last_written(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_fail_next_of(f.kernel, RTM_GETROUTE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_link_up(f.link));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1) { continue; }
        adds++;
        ASSERT_EQ_FMTm("every add carries the gateway", 4, m[i].gw_len, "%d");
        ASSERT_EQ(0, memcmp(m[i].gw, gw_a, 4));
    }
    ASSERT_EQ_FMTm("enable, then the re-add", (size_t)2, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: the gateway taken by dump order instead of main's default at its lowest metric. */
TEST the_gateway_is_the_interfaces_default_from_main_at_its_lowest_metric(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0}, corner[4] = {10, 0, 0, 0};
    const uint8_t gw_policy[4] = {10, 0, 0, 9}, gw_backup[4] = {10, 0, 0, 2}, gw_main[4] = {10, 0, 0, 1},
                  gw_spare[4] = {10, 0, 0, 3}, gw_corner[4] = {10, 0, 0, 7};
    fake_rtnl_add_route(f.kernel, AF_INET, 4096, RTN_UNICAST, RTPROT_BOOT, any, 0, 5);
    fake_rtnl_route_via(f.kernel, 1, gw_policy, 4);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, any, 0, 1024);
    fake_rtnl_route_via(f.kernel, 1, gw_backup, 4);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, any, 0, 10);
    fake_rtnl_route_via(f.kernel, 1, gw_main, 4);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, any, 0, 2048);
    fake_rtnl_route_via(f.kernel, 1, gw_spare, 4);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, corner, 8, 1);
    fake_rtnl_route_via(f.kernel, 1, gw_corner, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1 || m[i].table != 100) { continue; }
        adds++;
        ASSERT_EQ_FMTm("via a gateway", 4, m[i].gw_len, "%d");
        ASSERT_EQ_FMTm("main's default at metric 10: not the policy table's, not the backup, not the corner route's", 0,
                       memcmp(m[i].gw, gw_main, 4), "%d");
    }
    ASSERT_EQ_FMT((size_t)1, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: the gateway lookup reading the group's own default back when main has none. */
TEST the_lookup_never_reads_the_groups_own_default_back(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0}, gw_real[4] = {10, 0, 0, 1}, gw_ours[4] = {10, 0, 0, 9};
    fake_rtnl_add_route(f.kernel, AF_INET, 4097, RTN_UNICAST, FIRC_RTPROT, any, 0, 10);
    fake_rtnl_route_via(f.kernel, 1, gw_ours, 4);
    fake_rtnl_add_route(f.kernel, AF_INET, 4096, RTN_UNICAST, RTPROT_BOOT, any, 0, 1024);
    fake_rtnl_route_via(f.kernel, 1, gw_real, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1 || m[i].table != 100) { continue; }
        adds++;
        ASSERT_EQ_FMTm("via the firmware's gateway", 4, m[i].gw_len, "%d");
        ASSERT_EQ_FMTm("not the one firc itself wrote", 0, memcmp(m[i].gw, gw_real, 4), "%d");
    }
    ASSERT_EQ_FMT((size_t)1, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: a gatewayless default on the interface ignored, keeping a gateway that is gone. */
TEST a_default_that_lost_its_gateway_for_good_is_followed(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0}, gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_set_gateway(f.kernel, 1, NULL, 0);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, any, 0, 10);
    fake_rtnl_route_via(f.kernel, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    int last = -1;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == RTM_NEWROUTE && m[i].rtm_type == RTN_UNICAST && m[i].oif == 1 && m[i].table == 100) {
            last = (int)i;
        }
    }
    ASSERT(last >= 0);
    ASSERT_EQ_FMTm("the group's default follows it on-link", 0, m[last].gw_len, "%d");
    down(&f);
    PASS();
}

/* Catches: a reject default on the interface taken for an on-link one, forgetting the gateway. */
TEST a_reject_default_on_the_interface_is_not_a_gatewayless_one(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0}, gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_set_gateway(f.kernel, 1, NULL, 0);
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNREACHABLE, RTPROT_BOOT, any, 0, 10);
    fake_rtnl_route_via(f.kernel, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    int last = -1;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == RTM_NEWROUTE && m[i].rtm_type == RTN_UNICAST && m[i].oif == 1 && m[i].table == 100) {
            last = (int)i;
        }
    }
    ASSERT(last >= 0);
    ASSERT_EQ_FMTm("the gateway stands", 4, m[last].gw_len, "%d");
    ASSERT_EQ(0, memcmp(m[last].gw, gw_a, 4));
    down(&f);
    PASS();
}

/* Catches: routes written back while the link is down, which the kernel refuses. */
TEST an_event_while_the_link_is_down_writes_nothing(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    size_t before = fake_rtnl_count(f.kernel, RTM_NEWROUTE, RTN_UNICAST);
    fake_rtnl_set_link_flags(f.kernel, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));
    ASSERT_EQ_FMTm("nothing written while it is down", before,
                   fake_rtnl_count(f.kernel, RTM_NEWROUTE, RTN_UNICAST), "%zu");
    down(&f);
    PASS();
}

static size_t journal_at(firc_log_level_t level, const char *needle) {
    firc_event_t ev[32];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 32, &next, &dropped), c = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && ev[i].u.log.level == level && strstr(ev[i].u.log.text, needle) != NULL) {
            c++;
        }
    }
    return c;
}

/* Catches: a down link warned at every link event, or its coming up not said. */
TEST a_down_link_is_warned_once_and_its_return_said(void) {
    fixture_t f;
    ASSERT(up(&f, 0));
    firc_event_reset_for_test();
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_link_up(f.link));
    fake_rtnl_set_link_flags(f.kernel, IFF_UP);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_link_up(f.link));
    down(&f);
    ASSERT_EQ_FMT((size_t)1, journal_at(FIRC_LOG_WARN, "interface lo is down"), "%zu");
    ASSERT_EQ_FMT((size_t)1, journal_at(FIRC_LOG_DEBUG, "interface lo is down"), "%zu");
    ASSERT_EQ_FMT((size_t)1, journal_at(FIRC_LOG_INFO, "interface lo: recovered after 2 failures over "), "%zu");
    PASS();
}

static uint64_t g_rep_ms = 1000;
static uint64_t rep_clock(void) { return g_rep_ms; }

/* Catches: an interface that never appears said once and never again, a reminder sooner than ten minutes, a DEBUG line at every sweep, its return seen by the sweep but not said, or a later loss taken as the old run. */
TEST a_missing_interface_is_said_again_every_ten_minutes(void) {
    fixture_t f;
    ASSERT(up(&f, 0));
    g_rep_ms = 1000;
    firc_logrep_set_clock_for_test(rep_clock);
    firc_event_reset_for_test();
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    g_rep_ms += FIRC_LOGREP_REMIND_MS - 1;
    firc_ipset_to_link_remind(f.link);
    size_t quiet = journal_at(FIRC_LOG_DEBUG, "interface lo");
    g_rep_ms += 1;
    firc_ipset_to_link_remind(f.link);
    size_t reminded = journal_at(FIRC_LOG_WARN, "interface lo is down (still failing, 2 times for 10 min)");
    fake_rtnl_set_link_flags(f.kernel, IFF_UP);
    g_rep_ms += FIRC_LOGREP_REMIND_MS;
    firc_ipset_to_link_remind(f.link);
    size_t back = journal_at(FIRC_LOG_INFO, "interface lo: recovered after 2 failures over 20 min");
    fake_rtnl_set_link_flags(f.kernel, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_link_up(f.link));
    firc_logrep_set_clock_for_test(NULL);
    down(&f);
    ASSERT_EQ_FMTm("no line between reminders", (size_t)0, quiet, "%zu");
    ASSERT_EQ_FMT((size_t)1, reminded, "%zu");
    ASSERT_EQ_FMT((size_t)1, back, "%zu");
    ASSERT_EQ_FMTm("the first, the reminder and a fresh one after the return", (size_t)3,
                   journal_at(FIRC_LOG_WARN, "interface lo is down"), "%zu");
    PASS();
}

/* Catches: one family's refusal skipping the other family's route refresh. */
TEST one_familys_failure_does_not_cost_the_other_its_refresh(void) {
    fixture_t f;
    memset(&f, 0, sizeof(f));
    f.fipt = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_fake_ipt_t *fipt6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    ASSERT(f.fipt != NULL && fipt6 != NULL);
    f.ipt = firc_ipt_new(firc_fake_ipt_as_xt(f.fipt), "FIRC_");
    firc_ipt_t *ipt6 = firc_ipt_new(firc_fake_ipt_as_xt(fipt6), "FIRC_");
    ASSERT(f.ipt != NULL && ipt6 != NULL);
    firc_netfilter_register_base_chains(f.ipt, ipt6);
    f.kernel = fake_rtnl_start(&f.rtnl);
    ASSERT(f.kernel != NULL);
    fake_rtnl_set_link_flags(f.kernel, IFF_UP);
    f.link = firc_ipset_to_link_new("FIRC_g1", "lo", f.ipt, ipt6, f.rtnl, 100, NULL, "g1", NULL, NULL);
    ASSERT(f.link != NULL);
    fake_rtnl_add_addr(f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, 0);
    const uint8_t gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));

    size_t before = fake_rtnl_messages(f.kernel, NULL, 0);
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWROUTE, EPERM);
    ASSERT_FALSEm("the refusal is reported", firc_ipset_to_link_on_addr_change(f.link) == FIRC_OK);
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), v6 = 0;
    for (size_t i = before; i < n; i++) {
        if (m[i].type == RTM_NEWROUTE && m[i].rtm_type == RTN_UNICAST && m[i].family == AF_INET6) { v6++; }
    }
    ASSERTm("the v6 route was written even though v4 was refused", v6 >= 1);
    firc_ipset_to_link_free(f.link);
    firc_rtnl_close(f.rtnl);
    fake_rtnl_stop(f.kernel);
    firc_ipt_free(f.ipt);
    firc_ipt_free(ipt6);
    PASS();
}

typedef struct {
    fixture_t f;
    firc_fake_ipt_t *fipt6;
    firc_ipt_t *ipt6;
} dual_t;

static bool up_dual(dual_t *d) {
    memset(d, 0, sizeof(*d));
    d->f.fipt = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    d->fipt6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    if (d->f.fipt == NULL || d->fipt6 == NULL) { return false; }
    d->f.ipt = firc_ipt_new(firc_fake_ipt_as_xt(d->f.fipt), "FIRC_");
    d->ipt6 = firc_ipt_new(firc_fake_ipt_as_xt(d->fipt6), "FIRC_");
    if (d->f.ipt == NULL || d->ipt6 == NULL) { return false; }
    firc_netfilter_register_base_chains(d->f.ipt, d->ipt6);
    d->f.kernel = fake_rtnl_start(&d->f.rtnl);
    if (d->f.kernel == NULL) { return false; }
    fake_rtnl_set_link_flags(d->f.kernel, IFF_UP);
    fake_rtnl_add_addr(d->f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, 0);
    const uint8_t gw[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(d->f.kernel, 1, gw, 4);
    d->f.link = firc_ipset_to_link_new("FIRC_g1", "lo", d->f.ipt, d->ipt6, d->f.rtnl, 100, NULL, "g1", NULL, NULL);
    return d->f.link != NULL && firc_ipset_to_link_enable(d->f.link, NULL) == FIRC_OK;
}

static void down_dual(dual_t *d) {
    down(&d->f);
    firc_ipt_free(d->ipt6);
}

static size_t iface_routes_since(fixture_t *f, size_t from, int family) {
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f->kernel, m, 64), c = 0;
    for (size_t i = from; i < n && i < 64; i++) {
        if (m[i].type == RTM_NEWROUTE && m[i].rtm_type == RTN_UNICAST && m[i].family == family && m[i].oif == 1) {
            c++;
        }
    }
    return c;
}

/* Catches: a refused blackhole of either family on link-up costing the group its defaults. */
TEST a_refused_blackhole_on_link_up_still_writes_both_defaults(void) {
    for (unsigned refused = 0; refused < 2; refused++) {
        dual_t d;
        ASSERT(up_dual(&d));
        size_t before = fake_rtnl_messages(d.f.kernel, NULL, 0);
        fake_rtnl_fail_after_of(d.f.kernel, RTM_NEWROUTE, EPERM, refused);
        ASSERT_FALSEm("the refusal is reported", firc_ipset_to_link_on_link_up(d.f.link) == FIRC_OK);
        ASSERT_EQ_FMTm("the v4 default was written", (size_t)1, iface_routes_since(&d.f, before, AF_INET), "%zu");
        ASSERT_EQ_FMTm("and the v6 one", (size_t)1, iface_routes_since(&d.f, before, AF_INET6), "%zu");
        down_dual(&d);
    }
    PASS();
}

/* Catches: a link-up whose interface lookup was refused reported as done. */
TEST a_refused_interface_lookup_on_link_up_is_reported(void) {
    dual_t d;
    ASSERT(up_dual(&d));
    fake_rtnl_fail_next_of(d.f.kernel, RTM_GETLINK, EPERM);
    ASSERT_EQ_FMT(firc_err_from_errno(EPERM), firc_ipset_to_link_on_link_up(d.f.link), "%d");
    down_dual(&d);
    PASS();
}

/* Catches: a refused v4 default on link-up costing the v6 group its default. */
TEST a_refused_v4_default_on_link_up_still_writes_the_v6_one(void) {
    dual_t d;
    ASSERT(up_dual(&d));
    size_t before = fake_rtnl_messages(d.f.kernel, NULL, 0);
    fake_rtnl_fail_after_of(d.f.kernel, RTM_NEWROUTE, EPERM, 2);
    ASSERT_FALSEm("the refusal is reported", firc_ipset_to_link_on_link_up(d.f.link) == FIRC_OK);
    ASSERT_EQ_FMTm("the v6 default was written", (size_t)1, iface_routes_since(&d.f, before, AF_INET6), "%zu");
    down_dual(&d);
    PASS();
}

/* Catches: a link going down under the write read as a failure, or its purged route still taken as present. */
TEST a_link_down_under_the_write_is_a_skip_not_an_error(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    ASSERT(firc_ipset_to_link_has_iface_route(f.link, AF_INET));
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWROUTE, ENETDOWN);
    ASSERT_EQ_FMT(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link), "%d");
    ASSERT_FALSEm("the route is not there", firc_ipset_to_link_has_iface_route(f.link, AF_INET));
    down(&f);
    PASS();
}

/* Catches: an unreachable gateway taken as a missing route, so a disable leaves the old default behind. */
TEST an_unreachable_gateway_is_reported_and_the_old_route_still_deleted(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWROUTE, ENETUNREACH);
    ASSERT_EQ_FMT(firc_err_from_errno(ENETUNREACH), firc_ipset_to_link_on_addr_change(f.link), "%d");
    ASSERTm("the refused replace left the old route", firc_ipset_to_link_has_iface_route(f.link, AF_INET));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(f.link));
    ASSERT_EQ_FMTm("the disable deletes it", (size_t)1, iface_routes(&f, RTM_DELROUTE), "%zu");
    down(&f);
    PASS();
}

/* Catches: a family skipped with ENODEV forgetting its gateway. */
TEST an_enodev_skip_does_not_forget_the_gateway(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWROUTE, ENODEV);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));
    fake_rtnl_fail_next_of(f.kernel, RTM_GETROUTE, EPERM);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1) { continue; }
        adds++;
        ASSERT_EQ_FMTm("every add carries the gateway", 4, m[i].gw_len, "%d");
        ASSERT_EQ(0, memcmp(m[i].gw, gw_a, 4));
    }
    ASSERT_EQ_FMTm("enable, the refused one, the re-add", (size_t)3, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: a vanished default rewritten as a device route instead of via the last gateway. */
TEST a_default_route_that_vanished_keeps_the_gateway_last_written(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t gw_a[4] = {10, 0, 0, 1};
    fake_rtnl_set_gateway(f.kernel, 1, gw_a, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_set_gateway(f.kernel, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(f.link));

    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0, deletes = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].rtm_type != RTN_UNICAST || m[i].oif != 1) { continue; }
        if (m[i].type == RTM_DELROUTE) { deletes++; }
        if (m[i].type != RTM_NEWROUTE) { continue; }
        adds++;
        ASSERT_EQ_FMTm("no device route: every add carries the gateway", 4, m[i].gw_len, "%d");
        ASSERT_EQ(0, memcmp(m[i].gw, gw_a, 4));
    }
    ASSERT_EQ_FMTm("enable, then the re-add", (size_t)2, adds, "%zu");
    ASSERT_EQ_FMTm("nothing deleted in between", (size_t)0, deletes, "%zu");
    down(&f);
    PASS();
}

/* Catches: a group that never learned a gateway writing no route at all. */
TEST a_group_that_never_saw_a_gateway_writes_a_device_route(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1) { continue; }
        adds++;
        ASSERT_EQ_FMTm("a device route", 0, m[i].gw_len, "%d");
    }
    ASSERT_EQ_FMT((size_t)1, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: a default found only in a firmware policy table ignored. */
TEST a_default_only_in_a_policy_table_is_still_the_gateway(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0}, gw_policy[4] = {10, 0, 0, 9};
    fake_rtnl_add_route(f.kernel, AF_INET, 4096, RTN_UNICAST, RTPROT_BOOT, any, 0, 5);
    fake_rtnl_route_via(f.kernel, 1, gw_policy, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1 || m[i].table != 100) { continue; }
        adds++;
        ASSERT_EQ_FMTm("via the policy table's gateway", 4, m[i].gw_len, "%d");
        ASSERT_EQ(0, memcmp(m[i].gw, gw_policy, 4));
    }
    ASSERT_EQ_FMT((size_t)1, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: a gatewayless default in main shadowing a gatewayed default elsewhere. */
TEST a_gatewayless_default_in_main_does_not_shadow_a_gatewayed_one(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0}, gw_policy[4] = {10, 0, 0, 9};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, any, 0, 1);
    fake_rtnl_route_via(f.kernel, 1, NULL, 0);
    fake_rtnl_add_route(f.kernel, AF_INET, 4096, RTN_UNICAST, RTPROT_BOOT, any, 0, 5);
    fake_rtnl_route_via(f.kernel, 1, gw_policy, 4);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1 || m[i].table != 100) { continue; }
        adds++;
        ASSERT_EQ_FMTm("via the only real next hop", 4, m[i].gw_len, "%d");
        ASSERT_EQ(0, memcmp(m[i].gw, gw_policy, 4));
    }
    ASSERT_EQ_FMT((size_t)1, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: an ECMP default read only at its top level, missing the interface's next hop. */
TEST the_gateway_of_a_multipath_default_is_read_from_its_nexthops(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP));
    const uint8_t any[4] = {0, 0, 0, 0}, gw_mp[4] = {10, 0, 0, 5};
    fake_rtnl_add_route(f.kernel, AF_INET, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, any, 0, 10);
    fake_rtnl_route_via(f.kernel, 1, gw_mp, 4);
    fake_rtnl_route_multipath(f.kernel);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), adds = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNICAST || m[i].oif != 1 || m[i].table != 100) { continue; }
        adds++;
        ASSERT_EQ_FMTm("via the nexthop for this interface", 4, m[i].gw_len, "%d");
        ASSERT_EQ(0, memcmp(m[i].gw, gw_mp, 4));
    }
    ASSERT_EQ_FMT((size_t)1, adds, "%zu");
    down(&f);
    PASS();
}

/* Catches: the pool reject routes installed in another table or at another metric. */
TEST the_reject_routes_land_in_the_groups_own_table(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18; c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37; c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ipset_to_link_free(f.link);
    f.link = firc_ipset_to_link_new("FIRC_g1", "lo", f.ipt, NULL, f.rtnl, 100, pool, "g1", NULL, NULL);
    ASSERT(f.link != NULL);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    uint32_t table = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == RTM_NEWRULE && m[i].priority == FIRC_RULE_PRIORITY) {
            table = m[i].table;
            break;
        }
    }
    ASSERTm("the group got a table of its own", table != 0 && table != RT_TABLE_MAIN);

    size_t rejects = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWROUTE || m[i].rtm_type != RTN_UNREACHABLE) { continue; }
        rejects++;
        ASSERT_EQ_FMTm("the group's table, not main", table, m[i].table, "%u");
        ASSERT_EQ_FMTm("and the group's metric, not main's",
                       (uint32_t)FIRC_POOL_REJECT_METRIC_GROUP, m[i].priority, "%u");
    }
    ASSERT_EQ_FMTm("one per family", (size_t)2, rejects, "%zu");
    down(&f);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the ip rule added before its table's reject routes. */
TEST the_reject_routes_precede_the_rule(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18; c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37; c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_ipset_to_link_free(f.link);
    f.link = firc_ipset_to_link_new("FIRC_g1", "lo", f.ipt, NULL, f.rtnl, 100, pool, "g1", NULL, NULL);
    ASSERT(f.link != NULL);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    int first_reject = -1, first_rule = -1;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == RTM_NEWROUTE && m[i].rtm_type == RTN_UNREACHABLE && first_reject < 0) { first_reject = (int)i; }
        if (m[i].type == RTM_NEWRULE && first_rule < 0) { first_rule = (int)i; }
    }
    ASSERT(first_reject >= 0 && first_rule >= 0);
    ASSERTm("unreachable routes first, the rule after", first_reject < first_rule);
    int last_route = -1;
    for (size_t i = 0; i < n; i++) { if (m[i].type == RTM_NEWROUTE) { last_route = (int)i; } }
    ASSERTm("the rule is the last thing enable adds", last_route < first_rule);

    size_t before = n;
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(f.link));
    n = fake_rtnl_messages(f.kernel, m, 64);
    int del_rule = -1, first_del_route = -1;
    for (size_t i = before; i < n; i++) {
        if (m[i].type == RTM_DELRULE && del_rule < 0) { del_rule = (int)i; }
        if (m[i].type == RTM_DELROUTE && first_del_route < 0) { first_del_route = (int)i; }
    }
    ASSERT(del_rule >= 0 && first_del_route >= 0);
    ASSERTm("the rule is the first thing disable removes", del_rule < first_del_route);
    down(&f);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a disable leaving the ip rule, a route, a chain or a jump behind, or touching others. */
TEST disable_takes_back_the_rule_the_routes_and_the_chains(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    const char *foreign[] = {"-i", "br0", "-j", "ACCEPT"};
    const char *const *rules[] = {foreign};
    const size_t lens[] = {4};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(f.fipt, "filter", "FORWARD", rules, lens, 1));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    ASSERT_EQ(FIRC_OK, pass_with(&f, true));
    ASSERT(firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));
    size_t dels_before = fake_rtnl_count(f.kernel, RTM_DELRULE, 0);

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(f.link));
    ASSERT_EQ(FIRC_OK, pass_with(&f, false));
    ASSERT_EQ_FMTm("the ip rule and its reply twin are gone", dels_before + 2, fake_rtnl_count(f.kernel, RTM_DELRULE, 0), "%zu");
    ASSERT_EQ_FMTm("the blackhole is gone", (size_t)1, fake_rtnl_count(f.kernel, RTM_DELROUTE, RTN_BLACKHOLE), "%zu");
    ASSERT_EQ_FMTm("the interface route is gone", (size_t)1, iface_routes(&f, RTM_DELROUTE), "%zu");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fipt, "filter", "FIRC_g1"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fipt, "nat", "FIRC_g1"));
    firc_ipt_rule_t *const *got = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(f.fipt, "filter", "FORWARD", &got, &n));
    ASSERT_EQ_FMTm("only the foreign rule is left in FORWARD", (size_t)1, n, "%zu");
    ASSERT_STR_EQ("br0", got[0]->parts[1]);
    down(&f);
    PASS();
}

/* Catches: the reply twin at priority 49 missing, without suppress or iif, or pointing at the group. */
TEST a_group_s_rule_has_a_reply_twin_ahead_of_it_in_main(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    int twin = -1, rule = -1;
    uint32_t mark = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWRULE) { continue; }
        if (m[i].priority == FIRC_RULE_PRIORITY) { rule = (int)i; mark = m[i].mark; }
        if (m[i].priority == 49u) {
            ASSERT_EQ_FMTm("one twin", -1, twin, "%d");
            twin = (int)i;
        }
    }
    ASSERT(rule >= 0 && twin >= 0);
    ASSERT_EQ_FMT((unsigned)AF_INET, (unsigned)m[twin].family, "%u");
    ASSERT_EQ_FMTm("the twin looks in main", (uint32_t)RT_TABLE_MAIN, m[twin].table, "%u");
    ASSERT_EQ_FMTm("and ignores main's default", 0, m[twin].suppress, "%d");
    ASSERT_STR_EQm("for what came in on the group's interface", "lo", m[twin].iif);
    ASSERT_EQ_FMTm("over the group's own mark", mark, m[twin].mark, "%#x");
    ASSERT_EQ_FMT(FIRC_MARK_GROUP_MASK, m[twin].mask, "%#x");
    ASSERT_EQ_FMTm("the group's rule itself is plain", -1, m[rule].suppress, "%d");
    ASSERTm("installed before the rule it guards", twin < rule);

    size_t before = n;
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(f.link));
    n = fake_rtnl_messages(f.kernel, m, 64);
    int del_twin = -1, del_rule = -1;
    for (size_t i = before; i < n; i++) {
        if (m[i].type != RTM_DELRULE) { continue; }
        if (m[i].priority == 49u && m[i].table == RT_TABLE_MAIN && m[i].mark == mark) { del_twin = (int)i; }
        if (m[i].priority == FIRC_RULE_PRIORITY && m[i].mark == mark) { del_rule = (int)i; }
    }
    ASSERT(del_twin >= 0 && del_rule >= 0);
    ASSERTm("and removed after it", del_rule < del_twin);
    down(&f);
    PASS();
}

static int nth_of(const fake_rtnl_msg_t *m, size_t n, uint16_t type, unsigned nth) {
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == type && nth-- == 0) { return (int)i; }
    }
    return -1;
}

/* Catches: a failed enable leaving its reply twin behind. */
TEST a_refused_group_rule_takes_its_twin_back(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_fail_after_of(f.kernel, RTM_NEWRULE, EPERM, 1);
    ASSERT(firc_ipset_to_link_enable(f.link, NULL) != FIRC_OK);
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    int refused = nth_of(m, n, RTM_NEWRULE, 1);
    ASSERT(refused >= 0);
    ASSERT_EQ_FMTm("the refused add is the group's own rule", FIRC_RULE_PRIORITY, m[refused].priority, "%u");
    bool twin_deleted = false;
    for (size_t i = (size_t)refused + 1; i < n; i++) {
        if (m[i].type == RTM_DELRULE && m[i].priority == 49u && m[i].table == RT_TABLE_MAIN) { twin_deleted = true; }
    }
    ASSERTm("the twin is deleted after the refusal", twin_deleted);
    down(&f);
    PASS();
}

/* Catches: an enable that succeeds without its reply twin. */
TEST a_refused_twin_fails_the_enable(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWRULE, EPERM);
    ASSERT(firc_ipset_to_link_enable(f.link, NULL) != FIRC_OK);
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64);
    for (size_t i = 0; i < n; i++) {
        ASSERTm("the group's rule never goes in", !(m[i].type == RTM_NEWRULE && m[i].priority == FIRC_RULE_PRIORITY));
    }
    ASSERT(nth_of(m, n, RTM_NEWRULE, 0) >= 0);
    down(&f);
    PASS();
}

/* Catches: a reply twin written for a blackhole group or for IPv6. */
TEST no_twin_for_a_blackhole_group_or_for_ipv6(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    firc_ipset_to_link_free(f.link);
    f.link = firc_ipset_to_link_new("FIRC_g1", FIRC_IPSET_TO_LINK_BLACKHOLE, f.ipt, NULL, f.rtnl, 100, NULL, "g1",
                                    NULL, NULL);
    ASSERT(f.link != NULL);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f.kernel, m, 64), group = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWRULE) { continue; }
        ASSERTm("no twin for a blackhole group", m[i].priority != 49u);
        group += m[i].priority == FIRC_RULE_PRIORITY;
    }
    ASSERT_EQ_FMT((size_t)1, group, "%zu");
    down(&f);

    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    firc_fake_ipt_t *fipt6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt6 = fipt6 ? firc_ipt_new(firc_fake_ipt_as_xt(fipt6), "FIRC_") : NULL;
    ASSERT(ipt6 != NULL);
    firc_netfilter_register_base_chains(ipt6, NULL);
    firc_ipset_to_link_free(f.link);
    f.link = firc_ipset_to_link_new("FIRC_g1", "lo", f.ipt, ipt6, f.rtnl, 100, NULL, "g1", NULL, NULL);
    ASSERT(f.link != NULL);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    n = fake_rtnl_messages(f.kernel, m, 64);
    size_t v6_group = 0, v4_twin = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type != RTM_NEWRULE) { continue; }
        if (m[i].family == AF_INET6) {
            ASSERTm("no IPv6 twin", m[i].priority != 49u);
            v6_group += m[i].priority == FIRC_RULE_PRIORITY;
        } else {
            v4_twin += m[i].priority == 49u;
        }
    }
    ASSERT_EQ_FMT((size_t)1, v6_group, "%zu");
    ASSERT_EQ_FMT((size_t)1, v4_twin, "%zu");
    down(&f);
    firc_ipt_free(ipt6);
    PASS();
}

typedef struct {
    fixture_t f;
    firc_fake_ipt_t *fipt6;
    firc_ipt_t *ipt6;
} carrier_t;

static bool up_carrier(carrier_t *d, unsigned link_flags) {
    memset(d, 0, sizeof(*d));
    if (!up(&d->f, link_flags)) { return false; }
    d->fipt6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    d->ipt6 = d->fipt6 ? firc_ipt_new(firc_fake_ipt_as_xt(d->fipt6), "FIRC_") : NULL;
    if (d->ipt6 == NULL) { return false; }
    firc_netfilter_register_base_chains(d->f.ipt, d->ipt6);
    firc_ipset_to_link_free(d->f.link);
    d->f.link = firc_ipset_to_link_new("FIRC_g1", "lo", d->f.ipt, d->ipt6, d->f.rtnl, 100, NULL, "g1", NULL, NULL);
    return d->f.link != NULL;
}

static void down_carrier(carrier_t *d) {
    down(&d->f);
    firc_ipt_free(d->ipt6);
}

static size_t v6_routes(carrier_t *d, uint16_t type, uint8_t rtm_type, uint32_t priority) {
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(d->f.kernel, m, 64), c = 0;
    for (size_t i = 0; i < n; i++) {
        if (m[i].type == type && m[i].family == AF_INET6 && m[i].rtm_type == rtm_type && m[i].dst_len == 0 &&
            m[i].priority == priority && m[i].table == 100) {
            c++;
        }
    }
    return c;
}

/* Catches: a v6 device default written for an interface with no IPv6, or its fallback left a silent blackhole. */
TEST an_interface_without_ipv6_gets_an_unreachable_v6_table(void) {
    carrier_t d;
    ASSERT(up_carrier(&d, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_LINK, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(d.f.link, NULL));
    ASSERT_EQ_FMTm("no v6 device default", (size_t)0, v6_routes(&d, RTM_NEWROUTE, RTN_UNICAST, 10), "%zu");
    ASSERT_EQ_FMTm("the v6 default is unreachable", (size_t)1, v6_routes(&d, RTM_NEWROUTE, RTN_UNREACHABLE, 20), "%zu");
    ASSERT_EQ_FMTm("no v6 blackhole", (size_t)0, v6_routes(&d, RTM_NEWROUTE, RTN_BLACKHOLE, 20), "%zu");
    ASSERT_FALSEm("the table has no v6 route through the interface", firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    ASSERTm("v4 is untouched", firc_ipset_to_link_has_iface_route(d.f.link, AF_INET));

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(d.f.link));
    ASSERT_EQ_FMTm("the teardown takes the unreachable back", (size_t)1, v6_routes(&d, RTM_DELROUTE, RTN_UNREACHABLE, 20), "%zu");
    down_carrier(&d);
    PASS();
}

/* Catches: a usable global v6 address on the interface not read as carrying IPv6. */
TEST a_global_v6_address_makes_the_interface_carry_ipv6(void) {
    carrier_t d;
    ASSERT(up_carrier(&d, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 2, RT_SCOPE_UNIVERSE, 0);
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(d.f.link, NULL));
    ASSERT_EQ_FMT((size_t)1, v6_routes(&d, RTM_NEWROUTE, RTN_UNICAST, 10), "%zu");
    ASSERT(firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    down_carrier(&d);
    PASS();
}

/* Catches: another interface's global address, or a tentative or failed one, read as this one's IPv6. */
TEST a_tunnel_with_only_link_local_or_unready_v6_carries_none(void) {
    carrier_t d;
    ASSERT(up_carrier(&d, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 2, RT_SCOPE_UNIVERSE, 0);
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_LINK, 0);
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, IFA_F_TENTATIVE);
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, IFA_F_DADFAILED);
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_HOST, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(d.f.link, NULL));
    ASSERT_EQ_FMT((size_t)0, v6_routes(&d, RTM_NEWROUTE, RTN_UNICAST, 10), "%zu");
    ASSERT_FALSE(firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    down_carrier(&d);
    PASS();
}

/* Catches: a WAN whose IPv6 is a default route over link-local (prefix delegated to the LAN) read as v4-only. */
TEST a_v6_default_through_the_interface_makes_it_carry_ipv6(void) {
    carrier_t d;
    ASSERT(up_carrier(&d, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_LINK, 0);
    const uint8_t any6[16] = {0};
    fake_rtnl_add_route(d.f.kernel, AF_INET6, RT_TABLE_MAIN, RTN_UNICAST, RTPROT_BOOT, any6, 0, 1024);
    fake_rtnl_route_via(d.f.kernel, 1, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(d.f.link, NULL));
    ASSERT_EQ_FMT((size_t)1, v6_routes(&d, RTM_NEWROUTE, RTN_UNICAST, 10), "%zu");
    ASSERT(firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    down_carrier(&d);

    ASSERT(up_carrier(&d, IFF_UP | IFF_POINTOPOINT));
    const uint8_t router6[16] = {0xfe, 0x80, [15] = 1};
    fake_rtnl_set_gateway(d.f.kernel, 1, router6, 16);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(d.f.link, NULL));
    ASSERTm("a default via a link-local router", firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    down_carrier(&d);
    PASS();
}

/* Catches: an address event that leaves the v6 default after the address went, or never brings it back. */
TEST an_address_event_flips_the_v6_route_both_ways(void) {
    carrier_t d;
    ASSERT(up_carrier(&d, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(d.f.link, NULL));
    ASSERT(firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));

    fake_rtnl_clear_addrs(d.f.kernel);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(d.f.link));
    ASSERT_EQ_FMTm("the device default is deleted", (size_t)1, v6_routes(&d, RTM_DELROUTE, RTN_UNICAST, 10), "%zu");
    ASSERT_FALSE(firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    ASSERT_EQ_FMTm("the unreachable stays", (size_t)0, v6_routes(&d, RTM_DELROUTE, RTN_UNREACHABLE, 20), "%zu");

    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_on_addr_change(d.f.link));
    ASSERT_EQ_FMTm("written again", (size_t)2, v6_routes(&d, RTM_NEWROUTE, RTN_UNICAST, 10), "%zu");
    ASSERT(firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    down_carrier(&d);
    PASS();
}

/* Catches: an address lookup that failed read as "no IPv6", deleting a working v6 default. */
TEST a_failed_address_lookup_keeps_the_v6_route(void) {
    carrier_t d;
    ASSERT(up_carrier(&d, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_add_addr(d.f.kernel, AF_INET6, 1, RT_SCOPE_UNIVERSE, 0);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(d.f.link, NULL));
    fake_rtnl_fail_next_of(d.f.kernel, RTM_GETADDR, EPERM);
    ASSERT_FALSE(firc_ipset_to_link_on_addr_change(d.f.link) == FIRC_OK);
    ASSERT_EQ_FMT((size_t)0, v6_routes(&d, RTM_DELROUTE, RTN_UNICAST, 10), "%zu");
    ASSERT(firc_ipset_to_link_has_iface_route(d.f.link, AF_INET6));
    down_carrier(&d);
    PASS();
}

/* Whether `table`/`base` holds a rule jumping to FIRC_g1. */
static bool jumps_to_g1(fixture_t *f, const char *table, const char *base) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f->fipt, table, base, &rules, &n)) { return false; }
    bool found = false;
    for (size_t i = 0; i < n && !found; i++) {
        char *text = firc_ipt_rule_string(rules[i]);
        found = text != NULL && strstr(text, "-j FIRC_g1") != NULL;
        free(text);
    }
    return found;
}

/* Catches: an enable writing iptables, or leaving the object disabled. */
TEST enable_writes_the_rules_and_leaves_the_chain_to_the_pass(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    size_t restores = firc_fake_ipt_writes(f.fipt);
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    ASSERT_EQ_FMTm("no iptables write", restores, firc_fake_ipt_writes(f.fipt), "%zu");
    ASSERT_EQ_FMTm("the ip rule and its reply twin are in", (size_t)2,
                   fake_rtnl_count(f.kernel, RTM_NEWRULE, 0), "%zu");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_prepare_iptables(f.link));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(f.ipt));
    ASSERTm("the pass writes it", firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));
    ASSERT(jumps_to_g1(&f, "mangle", "PREROUTING"));
    down(&f);
    PASS();
}

/* Catches: a disable deleting the chain, or keeping the ip rules. */
TEST disable_takes_the_rules_and_leaves_the_chain(void) {
    fixture_t f;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    ASSERT_EQ(FIRC_OK, pass_with(&f, true));
    ASSERT(firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));
    size_t restores = firc_fake_ipt_writes(f.fipt);
    size_t dels_before = fake_rtnl_count(f.kernel, RTM_DELRULE, 0);

    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(f.link));
    ASSERT_EQ_FMTm("the ip rule and its twin are gone", dels_before + 2,
                   fake_rtnl_count(f.kernel, RTM_DELRULE, 0), "%zu");
    ASSERT_EQ_FMTm("no iptables write", restores, firc_fake_ipt_writes(f.fipt), "%zu");
    ASSERTm("the chain is the pass's to delete", firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));
    down(&f);
    PASS();
}

/* Catches: a failed enable step misnamed or left NULL. */
TEST a_failed_enable_names_its_step(void) {
    fixture_t f;
    const char *step = NULL;

    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_fail_next_of(f.kernel, RTM_GETRULE, EIO);
    ASSERT(firc_ipset_to_link_enable(f.link, &step) != FIRC_OK);
    ASSERT_STR_EQ("routing table", step);
    down(&f);

    step = NULL;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWROUTE, EPERM);
    ASSERT(firc_ipset_to_link_enable(f.link, &step) != FIRC_OK);
    ASSERT_STR_EQ("route", step);
    down(&f);

    step = NULL;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWRULE, EPERM);
    ASSERT(firc_ipset_to_link_enable(f.link, &step) != FIRC_OK);
    ASSERT_STR_EQ("ip rule", step);
    down(&f);
    PASS();
}

/* Catches: an enable's rollback committing a chain delete. */
TEST an_enable_that_rolls_back_writes_no_iptables(void) {
    fixture_t f;
    const char *step = NULL;
    ASSERT(up(&f, IFF_UP | IFF_POINTOPOINT));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_enable(f.link, NULL));
    ASSERT_EQ(FIRC_OK, pass_with(&f, true));
    ASSERT_EQ(FIRC_OK, firc_ipset_to_link_disable(f.link));
    ASSERTm("fixture: the chain outlived the teardown", firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));
    size_t restores = firc_fake_ipt_writes(f.fipt);
    size_t route_dels = fake_rtnl_count(f.kernel, RTM_DELROUTE, 0);

    fake_rtnl_fail_next_of(f.kernel, RTM_NEWRULE, EPERM);
    ASSERT(firc_ipset_to_link_enable(f.link, &step) != FIRC_OK);
    ASSERT_STR_EQm("it failed after the route", "ip rule", step);
    ASSERTm("the rollback ran: it took the route back",
            fake_rtnl_count(f.kernel, RTM_DELROUTE, 0) > route_dels);
    ASSERT_EQ_FMTm("and wrote no iptables", restores, firc_fake_ipt_writes(f.fipt), "%zu");
    ASSERT(firc_fake_ipt_chain_exists(f.fipt, "mangle", "FIRC_g1"));
    ASSERT(jumps_to_g1(&f, "mangle", "PREROUTING"));
    down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(link_up_reinstalls_the_interface_route_even_when_nothing_changed);
    RUN_TEST(a_groups_own_routes_replace_what_sits_at_the_key);
    RUN_TEST(a_changed_gateway_replaces_the_route);
    RUN_TEST(the_teardown_deletes_the_route_by_the_gateway_it_last_wrote);
    RUN_TEST(a_failed_gateway_lookup_keeps_the_gateway_last_written);
    RUN_TEST(an_enodev_skip_does_not_forget_the_gateway);
    RUN_TEST(a_link_down_under_the_write_is_a_skip_not_an_error);
    RUN_TEST(an_unreachable_gateway_is_reported_and_the_old_route_still_deleted);
    RUN_TEST(the_lookup_never_reads_the_groups_own_default_back);
    RUN_TEST(a_default_that_lost_its_gateway_for_good_is_followed);
    RUN_TEST(a_reject_default_on_the_interface_is_not_a_gatewayless_one);
    RUN_TEST(an_event_while_the_link_is_down_writes_nothing);
    RUN_TEST(a_down_link_is_warned_once_and_its_return_said);
    RUN_TEST(a_missing_interface_is_said_again_every_ten_minutes);
    RUN_TEST(one_familys_failure_does_not_cost_the_other_its_refresh);
    RUN_TEST(a_refused_blackhole_on_link_up_still_writes_both_defaults);
    RUN_TEST(a_refused_interface_lookup_on_link_up_is_reported);
    RUN_TEST(a_refused_v4_default_on_link_up_still_writes_the_v6_one);
    RUN_TEST(the_gateway_is_the_interfaces_default_from_main_at_its_lowest_metric);
    RUN_TEST(a_default_route_that_vanished_keeps_the_gateway_last_written);
    RUN_TEST(a_group_that_never_saw_a_gateway_writes_a_device_route);
    RUN_TEST(a_default_only_in_a_policy_table_is_still_the_gateway);
    RUN_TEST(a_gatewayless_default_in_main_does_not_shadow_a_gatewayed_one);
    RUN_TEST(the_gateway_of_a_multipath_default_is_read_from_its_nexthops);
    RUN_TEST(the_reject_routes_land_in_the_groups_own_table);
    RUN_TEST(the_reject_routes_precede_the_rule);
    RUN_TEST(a_group_s_rule_has_a_reply_twin_ahead_of_it_in_main);
    RUN_TEST(a_refused_group_rule_takes_its_twin_back);
    RUN_TEST(a_refused_twin_fails_the_enable);
    RUN_TEST(no_twin_for_a_blackhole_group_or_for_ipv6);
    RUN_TEST(disable_takes_back_the_rule_the_routes_and_the_chains);
    RUN_TEST(enable_writes_the_rules_and_leaves_the_chain_to_the_pass);
    RUN_TEST(an_interface_without_ipv6_gets_an_unreachable_v6_table);
    RUN_TEST(a_global_v6_address_makes_the_interface_carry_ipv6);
    RUN_TEST(a_tunnel_with_only_link_local_or_unready_v6_carries_none);
    RUN_TEST(a_v6_default_through_the_interface_makes_it_carry_ipv6);
    RUN_TEST(an_address_event_flips_the_v6_route_both_ways);
    RUN_TEST(a_failed_address_lookup_keeps_the_v6_route);
    RUN_TEST(disable_takes_the_rules_and_leaves_the_chain);
    RUN_TEST(a_failed_enable_names_its_step);
    RUN_TEST(an_enable_that_rolls_back_writes_no_iptables);
    GREATEST_MAIN_END();
}

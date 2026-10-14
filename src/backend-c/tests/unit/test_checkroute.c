#include "greatest.h"

#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/socket.h>

#include "fake_rtnl.h"
#include "firc/checkroute.h"
#include "firc/mark.h"
#include "firc/rtnl.h"

typedef struct {
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
} fx_t;

static unsigned names(const char *n) { return strcmp(n, "up0") == 0 ? 7u : 0u; }

static bool up(fx_t *f, unsigned flags) {
    f->kernel = fake_rtnl_start(&f->rtnl);
    if (f->kernel == NULL) { return false; }
    fake_rtnl_set_link_flags(f->kernel, flags);
    firc_rtnl_set_nametoindex_for_test(names);
    return true;
}

static void down(fx_t *f) {
    firc_rtnl_set_nametoindex_for_test(NULL);
    firc_rtnl_close(f->rtnl);
    fake_rtnl_stop(f->kernel);
}

static size_t seen(fx_t *f, uint16_t type, uint8_t rtm_type, uint32_t table, uint32_t priority, uint32_t oif) {
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f->kernel, m, 64), c = 0;
    if (n > 64) { n = 64; }
    for (size_t i = 0; i < n; i++) {
        bool rule = type == RTM_NEWRULE || type == RTM_DELRULE;
        if (m[i].type != type || m[i].table != table || m[i].priority != priority) { continue; }
        if (!rule && (m[i].rtm_type != rtm_type || (oif != 0 && m[i].oif != oif))) { continue; }
        c++;
    }
    return c;
}

TEST a_check_route_is_a_rule_at_48_a_blackhole_and_a_default_through_the_interface(void) {
    fx_t f;
    ASSERT(up(&f, 0x1 | 0x10));
    firc_checkroute_t c;
    ASSERT_EQ(FIRC_OK, firc_checkroute_apply(f.rtnl, 500, "up0", &c));
    ASSERT_EQ_FMT(0x10000u, c.mark, "%x");
    ASSERT_EQ_FMT(500u, c.table, "%u");
    ASSERT_EQ_FMT((size_t)1, seen(&f, RTM_NEWROUTE, RTN_BLACKHOLE, 500, 20, 0), "%zu");
    ASSERT_EQ_FMT((size_t)1, seen(&f, RTM_NEWRULE, 0, 500, FIRC_RULE_PRIORITY_TUNNEL, 0), "%zu");
    ASSERT_EQ_FMT((size_t)1, seen(&f, RTM_NEWROUTE, RTN_UNICAST, 500, 10, 7), "%zu");
    down(&f);
    PASS();
}

TEST a_check_mark_never_takes_a_seeded_group_field(void) {
    fx_t f;
    ASSERT(up(&f, 0x1 | 0x10));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "0a1b2c3d", 1));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, FIRC_MARK_TUNNEL_OWNER "t0", 2));
    firc_checkroute_t c;
    ASSERT_EQ(FIRC_OK, firc_checkroute_apply(f.rtnl, 500, "up0", &c));
    ASSERT_EQ_FMT(0x30000u, c.mark, "%x");
    down(&f);
    PASS();
}

static void count_fields(void *ud, const firc_rtnl_field_t *v, size_t n) {
    (void)v;
    (void)n;
    (*(int *)ud)++;
}

TEST a_check_field_never_reaches_the_fields_file(void) {
    fx_t f;
    ASSERT(up(&f, 0x1 | 0x10));
    int calls = 0;
    firc_rtnl_watch_mark_fields(f.rtnl, count_fields, &calls);
    firc_checkroute_t c;
    ASSERT_EQ(FIRC_OK, firc_checkroute_apply(f.rtnl, 500, "up0", &c));
    ASSERT_EQ_FMT(0, calls, "%d");
    firc_rtnl_watch_mark_fields(f.rtnl, NULL, NULL);
    down(&f);
    PASS();
}

TEST a_check_route_on_a_down_link_writes_its_default_on_refresh(void) {
    fx_t f;
    ASSERT(up(&f, 0));
    firc_checkroute_t c;
    ASSERT_EQ(FIRC_OK, firc_checkroute_apply(f.rtnl, 500, "up0", &c));
    ASSERT_EQ_FMT((size_t)0, seen(&f, RTM_NEWROUTE, RTN_UNICAST, 500, 10, 7), "%zu");
    fake_rtnl_set_link_flags(f.kernel, 0x1 | 0x10);
    ASSERT_EQ(FIRC_OK, firc_checkroute_refresh(f.rtnl, &c));
    ASSERT_EQ_FMT((size_t)1, seen(&f, RTM_NEWROUTE, RTN_UNICAST, 500, 10, 7), "%zu");
    down(&f);
    PASS();
}

TEST remove_takes_back_the_rule_the_default_and_the_blackhole(void) {
    fx_t f;
    ASSERT(up(&f, 0x1 | 0x10));
    firc_checkroute_t c;
    ASSERT_EQ(FIRC_OK, firc_checkroute_apply(f.rtnl, 500, "up0", &c));
    ASSERT_EQ(FIRC_OK, firc_checkroute_remove(f.rtnl, &c));
    ASSERT_EQ_FMT((size_t)1, seen(&f, RTM_DELRULE, 0, 500, FIRC_RULE_PRIORITY_TUNNEL, 0), "%zu");
    ASSERT_EQ_FMT((size_t)1, seen(&f, RTM_DELROUTE, RTN_UNICAST, 500, 10, 7), "%zu");
    ASSERT_EQ_FMT((size_t)1, seen(&f, RTM_DELROUTE, RTN_BLACKHOLE, 500, 20, 0), "%zu");
    ASSERT_EQ_FMT(0u, c.mark, "%u");
    down(&f);
    PASS();
}

TEST a_stale_check_rule_is_swept_at_start(void) {
    fx_t f;
    ASSERT(up(&f, 0x1 | 0x10));
    firc_checkroute_t c;
    ASSERT_EQ(FIRC_OK, firc_checkroute_apply(f.rtnl, 500, "up0", &c));
    size_t removed = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_clean_stale_rules(f.rtnl, &removed));
    ASSERT_EQ_FMTm("a check rule at any other priority would outlive a crash", (size_t)1, removed, "%zu");
    ASSERT_EQ_FMTm("the swept table keeps no blackhole", (size_t)1, seen(&f, RTM_DELROUTE, RTN_BLACKHOLE, 500, 20, 0), "%zu");
    ASSERT_EQ_FMTm("the swept table keeps no default", (size_t)1, seen(&f, RTM_DELROUTE, RTN_UNICAST, 500, 10, 7), "%zu");
    down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_check_route_is_a_rule_at_48_a_blackhole_and_a_default_through_the_interface);
    RUN_TEST(a_check_mark_never_takes_a_seeded_group_field);
    RUN_TEST(a_check_field_never_reaches_the_fields_file);
    RUN_TEST(a_check_route_on_a_down_link_writes_its_default_on_refresh);
    RUN_TEST(remove_takes_back_the_rule_the_default_and_the_blackhole);
    RUN_TEST(a_stale_check_rule_is_swept_at_start);
    GREATEST_MAIN_END();
}

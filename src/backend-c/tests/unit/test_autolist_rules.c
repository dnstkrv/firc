#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake_iptables.h"
#include "firc/autolistrules.h"
#include "firc/netfilter_cleaner.h"

#define PREFIX "FIRC_"
#define AL_CHAIN PREFIX FIRC_AUTOLIST_CHAIN_SUFFIX

static firc_fakeip_t *make_pool(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *f = NULL;
    return firc_fakeip_new(&c, &f) == FIRC_OK ? f : NULL;
}

static bool joined(firc_fake_ipt_t *f, const char *table, const char *chain, char *out, size_t cap) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    out[0] = '\0';
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        char *s = firc_ipt_rule_string(rules[i]);
        if (s == NULL) { return false; }
        size_t len = strlen(out);
        snprintf(out + len, cap - len, "%s%s", len ? "\n" : "", s);
        free(s);
    }
    return true;
}

TEST the_rules_go_in_a_chain_of_their_own(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    char buf[2048];
    ASSERT(joined(fake, "mangle", AL_CHAIN, buf, sizeof(buf)));
    ASSERT_STR_EQ("-i br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m mark ! --mark 0x40000000/0x40000000 "
                  "-m tcp --dport 443 --tcp-flags SYN,ACK ACK "
                  "-m length --length 100:65535 "
                  "-m connbytes --connbytes 2:12 --connbytes-mode packets --connbytes-dir original "
                  "-m string --hex-string \"|1603|\" --algo bm --from 40 --to 84 "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 6 --nflog-threshold 1\n"
                  "-o br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m tcp --sport 443 --tcp-flags RST RST "
                  "-m connbytes --connbytes 0:4096 --connbytes-mode bytes --connbytes-dir reply "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 7 --nflog-threshold 1\n"
                  "-o br0 -p tcp -m conntrack ! --ctorigdst 198.18.0.0/15 "
                  "-m tcp --sport 443 "
                  "-m connbytes --connbytes 4097:16384 --connbytes-mode bytes --connbytes-dir reply "
                  "-m limit --limit 500/sec --limit-burst 500 "
                  "-j NFLOG --nflog-group 8 --nflog-threshold 1",
                  buf);

    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERT_STR_EQm("and FORWARD jumps to it", "-j " AL_CHAIN, buf);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST the_preflight_leaves_nothing_behind(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_supported(ipt, PREFIX, pool, lan, 1));
    ASSERTm("the kernel was asked", firc_fake_ipt_writes_log(fake) != NULL);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN FIRC_AUTOLIST_PROBE_SUFFIX));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN));

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_chain_left_unstaged_goes_away(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN));
    ASSERT_EQ(FIRC_OK, firc_netfilter_register_base_chains(ipt, NULL));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERTm("switched off, the next pass takes the chain away",
            !firc_fake_ipt_chain_exists(fake, "mangle", AL_CHAIN));
    char buf[1024];
    ASSERT(joined(fake, "mangle", "FORWARD", buf, sizeof(buf)));
    ASSERTm("and the jump to it", strstr(buf, AL_CHAIN) == NULL);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST each_family_and_interface_gets_its_three(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);

    const char *lan[] = {"br0", "br1"};
    ASSERT_EQ(FIRC_OK, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", AL_CHAIN, &rules, &n));
    ASSERT_EQ(6u, (unsigned)n);
    char buf[4096];
    ASSERT(joined(fake, "mangle", AL_CHAIN, buf, sizeof(buf)));
    ASSERTm("the v6 hello is searched for past the longer header", strstr(buf, "--from 60 --to 104") != NULL);
    ASSERTm("the pool excluded is the v6 one", strstr(buf, "! --ctorigdst fd37::/48") != NULL);

    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

TEST a_bad_interface_registers_nothing(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_xt(fake), "FIRC_");
    ASSERT(ipt != NULL);
    const char *lan[] = {"br0 -j ACCEPT"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 1));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_autolist_rules_install(ipt, PREFIX, pool, lan, 0));
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_rules_go_in_a_chain_of_their_own);
    RUN_TEST(the_preflight_leaves_nothing_behind);
    RUN_TEST(a_chain_left_unstaged_goes_away);
    RUN_TEST(each_family_and_interface_gets_its_three);
    RUN_TEST(a_bad_interface_registers_nothing);
    GREATEST_MAIN_END();
}

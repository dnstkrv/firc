#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firc/subparse.h"

typedef struct got {
    firc_sub_rules_t rs;
    firc_sub_parse_stats_t st;
    firc_err_t err;
} got_t;

static got_t parse(const char *body) {
    got_t g;
    memset(&g, 0, sizeof(g));
    firc_sub_rules_init(&g.rs);
    g.err = firc_sub_parse_rules_stats(body, strlen(body), &g.rs, &g.st, NULL, NULL);
    return g;
}

static const char *row(const got_t *g, size_t i) {
    static char buf[512];
    snprintf(buf, sizeof(buf), "%s %s", firc_sub_rules_type(&g->rs, i), firc_sub_rules_text(&g->rs, i));
    return buf;
}

/* Catches: a typed domain line read as a namespace, a keyword as a name, or the type word kept as a rule. */
TEST each_domain_line_takes_the_type_it_names(void) {
    got_t g = parse("DOMAIN,Exact.example.com\n"
                    "DOMAIN-SUFFIX,.suffix.example\n"
                    "domain-keyword,tube\n"
                    "HOST,host.example\n"
                    "HOST-SUFFIX,hs.example\n"
                    "HOST-KEYWORD,kw\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)6, g.rs.n, "%zu");
    ASSERT_STR_EQ("domain exact.example.com", row(&g, 0));
    ASSERT_STR_EQ("namespace suffix.example", row(&g, 1));
    ASSERT_STR_EQ("wildcard *tube*", row(&g, 2));
    ASSERT_STR_EQ("domain host.example", row(&g, 3));
    ASSERT_STR_EQ("namespace hs.example", row(&g, 4));
    ASSERT_STR_EQ("wildcard *kw*", row(&g, 5));
    ASSERT_EQ_FMT((size_t)0, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: no-resolve or the type word left behind as junk names, or a v6 prefix stored as subnet. */
TEST an_ip_line_is_one_prefix_and_nothing_else(void) {
    got_t g = parse("IP-CIDR,1.2.3.0/24,no-resolve\n"
                    "IP-CIDR6,2001:db8::/32\n"
                    "IP6-CIDR,2001:db9::/32,no-resolve\n"
                    "IP-CIDR,2001:dba::/32\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)4, g.rs.n, "%zu");
    ASSERT_STR_EQ("subnet 1.2.3.0/24", row(&g, 0));
    ASSERT_STR_EQ("subnet6 2001:db8::/32", row(&g, 1));
    ASSERT_STR_EQ("subnet6 2001:db9::/32", row(&g, 2));
    ASSERT_STR_EQ("subnet6 2001:dba::/32", row(&g, 3));
    ASSERT_EQ_FMT((size_t)0, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a regex cut at its own comma, or wrapped and folded like a guessed one. */
TEST a_regex_line_keeps_its_commas(void) {
    got_t g = parse("DOMAIN-REGEX,^Ab{1,3}\\.example$\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_STR_EQ("regex ^Ab{1,3}\\.example$", row(&g, 0));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a policy label stored as a name, or a malformed tail accepted. */
TEST a_policy_label_is_ignored_and_a_bad_tail_drops_the_line(void) {
    got_t g = parse("DOMAIN-SUFFIX,a.example,PROXY\n"
                    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n"
                    "IP-CIDR,10.1.0.0/16,src\n"
                    "DOMAIN,b.example,PROXY,DIRECT\n"
                    "DOMAIN,c.example,no-resolve\n"
                    "DOMAIN,,PROXY\n"
                    "DOMAIN,d.example,\n"
                    "IP-CIDR,10.2.0.0/16,no-resolve,DIRECT\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("namespace a.example", row(&g, 0));
    ASSERT_STR_EQ("subnet 10.0.0.0/8", row(&g, 1));
    ASSERT_EQ_FMT((size_t)6, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a rule firc cannot honour turned into a namespace named after its argument. */
TEST a_rule_firc_does_not_map_is_dropped_whole(void) {
    got_t g = parse("GEOIP,CN\n"
                    "PROCESS-NAME,curl\n"
                    "DOMAIN-WILDCARD,*.example.com\n"
                    "DST-PORT,443\n"
                    "MATCH,DIRECT\n"
                    "AND,((DOMAIN,a.com),(NETWORK,UDP))\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)0, g.rs.n, "%zu");
    ASSERT_EQ_FMT((size_t)6, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a mihomo domain-set prefix left unread. */
TEST plus_dot_and_dot_are_namespaces(void) {
    got_t g = parse("+.plus.example\n.dot.example\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)2, g.rs.n, "%zu");
    ASSERT_STR_EQ("namespace plus.example", row(&g, 0));
    ASSERT_STR_EQ("namespace dot.example", row(&g, 1));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: typed reading switched on for the whole list, or a host list read as typed lines. */
TEST untyped_lines_beside_typed_ones_read_as_before(void) {
    got_t g = parse("DOMAIN,a.example\n"
                    "b.example,c.example\n"
                    "MY-SITE,d.example\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)5, g.rs.n, "%zu");
    ASSERT_STR_EQ("domain a.example", row(&g, 0));
    ASSERT_STR_EQ("namespace b.example", row(&g, 1));
    ASSERT_STR_EQ("namespace c.example", row(&g, 2));
    ASSERT_STR_EQ("namespace my-site", row(&g, 3));
    ASSERT_STR_EQ("namespace d.example", row(&g, 4));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: a BOM keeping the first line from being read as typed. */
TEST a_bom_does_not_hide_the_first_typed_line(void) {
    got_t g = parse("\xEF\xBB\xBF" "DOMAIN-KEYWORD,tube\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)1, g.rs.n, "%zu");
    ASSERT_STR_EQ("wildcard *tube*", row(&g, 0));
    firc_sub_rules_free(&g.rs);
    PASS();
}

/* Catches: blanks around the type word, or a capitalised no-resolve, taking the line off the typed path. */
TEST blanks_and_case_around_the_type_are_read_through(void) {
    got_t g = parse("  DOMAIN,a.example\n"
                    "DOMAIN-SUFFIX ,b.example\n"
                    "\tIP-CIDR,10.0.0.0/8,NO-RESOLVE\n");
    ASSERT_EQ(FIRC_OK, g.err);
    ASSERT_EQ_FMT((size_t)3, g.rs.n, "%zu");
    ASSERT_STR_EQ("domain a.example", row(&g, 0));
    ASSERT_STR_EQ("namespace b.example", row(&g, 1));
    ASSERT_STR_EQ("subnet 10.0.0.0/8", row(&g, 2));
    ASSERT_EQ_FMT((size_t)0, g.st.dropped, "%zu");
    firc_sub_rules_free(&g.rs);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(each_domain_line_takes_the_type_it_names);
    RUN_TEST(an_ip_line_is_one_prefix_and_nothing_else);
    RUN_TEST(a_regex_line_keeps_its_commas);
    RUN_TEST(a_policy_label_is_ignored_and_a_bad_tail_drops_the_line);
    RUN_TEST(a_rule_firc_does_not_map_is_dropped_whole);
    RUN_TEST(plus_dot_and_dot_are_namespaces);
    RUN_TEST(untyped_lines_beside_typed_ones_read_as_before);
    RUN_TEST(a_bom_does_not_hide_the_first_typed_line);
    RUN_TEST(blanks_and_case_around_the_type_are_read_through);
    GREATEST_MAIN_END();
}

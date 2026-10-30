#include "greatest.h"

#include <string.h>

#include "firc/regdomain.h"

static const char *reg(const char *host) {
    static char out[256];
    return firc_regdomain(host, out, sizeof(out)) ? out : NULL;
}

TEST the_second_level_of_a_plain_name(void) {
    ASSERT_STR_EQ("example.com", reg("example.com"));
    ASSERT_STR_EQ("example.com", reg("cdn.example.com"));
    ASSERT_STR_EQ("googlevideo.com", reg("rr3---sn-abc.googlevideo.com"));
    ASSERT_STR_EQ("example.ru", reg("a.b.c.example.ru"));
    ASSERT_STR_EQ("example.com", reg("www.example.com."));
    PASS();
}

TEST a_country_s_generic_second_level_is_a_suffix(void) {
    ASSERT_STR_EQ("bbc.co.uk", reg("news.bbc.co.uk"));
    ASSERT_STR_EQ("example.com.br", reg("www.example.com.br"));
    ASSERT_STR_EQ("example.msk.ru", reg("shop.example.msk.ru"));
    ASSERTm("and a name that is only one has nothing to give", reg("co.uk") == NULL);
    PASS();
}

TEST a_platform_s_customers_stay_apart(void) {
    ASSERT_STR_EQ("someone.github.io", reg("someone.github.io"));
    ASSERT_STR_EQ("d1234.cloudfront.net", reg("d1234.cloudfront.net"));
    ASSERT(reg("github.io") == NULL);
    PASS();
}

TEST names_without_a_registrable_part(void) {
    ASSERT(reg("localhost") == NULL);
    ASSERT(reg("203.0.113.7") == NULL);
    ASSERT(reg("2001:db8::1") == NULL);
    ASSERT(reg("") == NULL);
    ASSERT(reg("a..example.com") == NULL);
    char small[5];
    ASSERTm("a result that does not fit is refused", !firc_regdomain("example.com", small, sizeof(small)));
    PASS();
}

TEST an_exclude_holds_its_subdomains(void) {
    char *list[] = {"example.com", "mail.other.org"};
    ASSERT(firc_autolist_excluded("example.com", list, 2));
    ASSERT(firc_autolist_excluded("cdn.example.com", list, 2));
    ASSERT_FALSE(firc_autolist_excluded("badexample.com", list, 2));
    ASSERT(firc_autolist_excluded("x.mail.other.org", list, 2));
    ASSERT_FALSE(firc_autolist_excluded("other.org", list, 2));
    PASS();
}

TEST what_an_exclude_entry_may_be(void) {
    ASSERT(firc_autolist_exclude_ok("example.com"));
    ASSERT(firc_autolist_exclude_ok("xn--d1acufc.xn--p1ai"));
    ASSERT_FALSE(firc_autolist_exclude_ok("Example.com"));
    ASSERT_FALSE(firc_autolist_exclude_ok("*.example.com"));
    ASSERT_FALSE(firc_autolist_exclude_ok(".example.com"));
    ASSERT_FALSE(firc_autolist_exclude_ok(""));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_second_level_of_a_plain_name);
    RUN_TEST(a_country_s_generic_second_level_is_a_suffix);
    RUN_TEST(a_platform_s_customers_stay_apart);
    RUN_TEST(names_without_a_registrable_part);
    RUN_TEST(an_exclude_holds_its_subdomains);
    RUN_TEST(what_an_exclude_entry_may_be);
    GREATEST_MAIN_END();
}

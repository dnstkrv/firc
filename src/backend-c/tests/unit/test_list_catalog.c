#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

#include "firc/list_catalog.h"

#define SAGER "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs"
#define HOAX "https://raw.githubusercontent.com/hoaxisr/rulesets/master/srs/{}.srs"

static firc_err_t parse(const char *body, cJSON **out, char *why, size_t cap) {
    return firc_list_catalog_parse(body, strlen(body), out, why, cap);
}

static void refuses(const char *body, const char *needle) {
    cJSON *out = NULL;
    char why[160] = "";
    firc_err_t err = parse(body, &out, why, sizeof why);
    if (err != FIRC_ERR_INVAL || out != NULL || strcmp(why, needle) != 0) {
        fprintf(stderr, "body %s: err %d why \"%s\" wanted \"%s\"\n", body, (int)err, why, needle);
        abort();
    }
}

/* Catches: names or urls altered on the way, unknown keys kept, or a valid index refused. */
TEST the_spec_example_parses_and_round_trips(void) {
    const char *body = "{\"generated\":\"2026-10-22T19:00:00Z\",\"extra\":1,\"sources\":["
                       "{\"id\":\"sagernet\",\"url\":\"" SAGER "\",\"junk\":true,"
                       "\"names\":[\"youtube\",\"youtube@cn\",\"category-ads-all\"]},"
                       "{\"id\":\"hoaxisr\",\"url\":\"" HOAX "\",\"names\":[\"claude\",\"discord-full\"]}]}";
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse(body, &out, why, sizeof why));
    ASSERT(out != NULL);
    ASSERT_STR_EQ("2026-10-22T19:00:00Z", cJSON_GetObjectItemCaseSensitive(out, "generated")->valuestring);
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(out, "extra"));
    cJSON *src = cJSON_GetObjectItemCaseSensitive(out, "sources");
    ASSERT_EQ(2, cJSON_GetArraySize(src));
    cJSON *s0 = cJSON_GetArrayItem(src, 0);
    ASSERT_STR_EQ("sagernet", cJSON_GetObjectItemCaseSensitive(s0, "id")->valuestring);
    ASSERT_STR_EQ(SAGER, cJSON_GetObjectItemCaseSensitive(s0, "url")->valuestring);
    ASSERT_EQ(NULL, cJSON_GetObjectItemCaseSensitive(s0, "junk"));
    cJSON *n0 = cJSON_GetObjectItemCaseSensitive(s0, "names");
    ASSERT_EQ(3, cJSON_GetArraySize(n0));
    ASSERT_STR_EQ("youtube@cn", cJSON_GetArrayItem(n0, 1)->valuestring);
    cJSON *s1 = cJSON_GetArrayItem(src, 1);
    ASSERT_STR_EQ("hoaxisr", cJSON_GetObjectItemCaseSensitive(s1, "id")->valuestring);
    ASSERT_STR_EQ("discord-full",
                  cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(s1, "names"), 1)->valuestring);
    cJSON_Delete(out);
    PASS();
}

/* Catches: an index with nothing in it refused. */
TEST an_empty_sources_array_parses(void) {
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse("{\"generated\":\"x\",\"sources\":[]}", &out, why, sizeof why));
    ASSERT_EQ(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(out, "sources")));
    cJSON_Delete(out);
    PASS();
}

/* Catches: a source id outside [a-z0-9-]{1,32} accepted. */
TEST a_bad_id_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"Bad_ID\",\"url\":\"" HOAX "\",\"names\":[]}]}", "source 1 has no valid id");
    refuses("{\"sources\":[{\"id\":\"\",\"url\":\"" HOAX "\",\"names\":[]}]}", "source 1 has no valid id");
    refuses("{\"sources\":[{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"url\":\"" HOAX "\",\"names\":[]}]}",
            "source 1 has no valid id");
    refuses("{\"sources\":[{\"id\":5,\"url\":\"" HOAX "\",\"names\":[]}]}", "source 1 has no valid id");
    PASS();
}

/* Catches: an insecure, foreign or off-host url accepted. */
TEST a_url_off_the_allowed_host_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"http://raw.githubusercontent.com/x/{}\",\"names\":[]}]}",
            "source 1 has no url on raw.githubusercontent.com");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"https://example.com/{}.srs\",\"names\":[]}]}",
            "source 1 has no url on raw.githubusercontent.com");
    PASS();
}

/* Catches: a url with no placeholder or two of them accepted; the reason must name the source. */
TEST a_url_without_exactly_one_placeholder_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[]},"
            "{\"id\":\"b\",\"url\":\"https://raw.githubusercontent.com/x/y.srs\",\"names\":[]}]}",
            "source 2 has no {} in its url");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"https://raw.githubusercontent.com/x/{}/{}.srs\","
            "\"names\":[]}]}",
            "source 1 has more than one {} in its url");
    PASS();
}

/* Catches: a name outside [A-Za-z0-9._@!-]{1,128} accepted, or the reason losing its position. */
TEST a_bad_name_is_refused_by_position(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"ok\",\"a b\"]}]}",
            "name 2 of a is not a rule-set name");
    char longname[140];
    memset(longname, 'a', 129);
    longname[129] = '\0';
    char body[512];
    snprintf(body, sizeof body, "{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"%s\"]}]}", longname);
    refuses(body, "name 1 of a is not a rule-set name");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"\"]}]}",
            "name 1 of a is not a rule-set name");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[5]}]}",
            "name 1 of a is not a rule-set name");
    PASS();
}

/* Catches: a url that is not a string, or names that are not an array, passing or sharing a reason. */
TEST a_source_missing_its_url_or_names_is_refused(void) {
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":7,\"names\":[]}]}", "source 1 has no url");
    refuses("{\"sources\":[{\"id\":\"a\",\"names\":[]}]}", "source 1 has no url");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":\"x\"}]}",
            "source 1 has no names array");
    refuses("{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\"}]}", "source 1 has no names array");
    PASS();
}

/* Catches: a name of exactly 128 characters refused. */
TEST a_name_of_128_characters_is_accepted(void) {
    char name[130];
    memset(name, 'a', 128);
    name[128] = '\0';
    char body[512];
    snprintf(body, sizeof body, "{\"sources\":[{\"id\":\"a\",\"url\":\"" HOAX "\",\"names\":[\"%s\"]}]}", name);
    cJSON *out = NULL;
    char why[160];
    ASSERT_EQ(FIRC_OK, parse(body, &out, why, sizeof why));
    cJSON_Delete(out);
    PASS();
}

/* Catches: a body that is not an index passed through. */
TEST a_body_that_is_not_an_index_is_refused(void) {
    refuses("<html>", "not JSON");
    refuses("{\"sources\":{}}", "sources is not an array");
    refuses("{}", "sources is not an array");
    refuses("[]", "sources is not an array");
    PASS();
}

/* Catches: a reason overrunning a short buffer. */
TEST a_short_why_buffer_is_cut_not_overrun(void) {
    cJSON *out = NULL;
    char why[8];
    ASSERT_EQ(FIRC_ERR_INVAL, parse("<html>", &out, why, sizeof why));
    ASSERT_EQ(7, (int)strlen(why));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_spec_example_parses_and_round_trips);
    RUN_TEST(an_empty_sources_array_parses);
    RUN_TEST(a_bad_id_is_refused);
    RUN_TEST(a_url_off_the_allowed_host_is_refused);
    RUN_TEST(a_url_without_exactly_one_placeholder_is_refused);
    RUN_TEST(a_bad_name_is_refused_by_position);
    RUN_TEST(a_source_missing_its_url_or_names_is_refused);
    RUN_TEST(a_name_of_128_characters_is_accepted);
    RUN_TEST(a_body_that_is_not_an_index_is_refused);
    RUN_TEST(a_short_why_buffer_is_cut_not_overrun);
    GREATEST_MAIN_END();
}

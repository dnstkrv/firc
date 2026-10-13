#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firc/release.h"

#define MIPSEL "mipsel-3.4_kn"
#define HEX64 "aef6175063fc5bbcfd89200f92ad01b158edf2aae0eb43724e3b55a3eb832407"
#define NAME030 "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk"
#define URL030 "https://github.com/hoaxisr/firc/releases/download/0.3.0/" NAME030

static const firc_release_want_t WANT = {MIPSEL, FIRC_UPDATE_DOWNLOAD_PREFIX};

static char json_buf[65536];
static char asset_buf[4096];

static const char *asset(const char *name, const char *state, const char *digest, const char *size,
                         const char *url) {
    snprintf(asset_buf, sizeof(asset_buf),
             "{\"name\":\"%s\",\"state\":\"%s\",\"digest\":%s,\"size\":%s,\"browser_download_url\":\"%s\"}", name,
             state, digest, size, url);
    return asset_buf;
}

static const char *good_asset(void) {
    return asset(NAME030, "uploaded", "\"sha256:" HEX64 "\"", "829104", URL030);
}

static const char *release(const char *tag, const char *draft, const char *pre, const char *assets) {
    snprintf(json_buf, sizeof(json_buf),
             "{\"tag_name\":\"%s\",\"draft\":%s,\"prerelease\":%s,\"published_at\":\"2026-10-07T20:27:40Z\","
             "\"body\":\"n\",\"assets\":[%s]}",
             tag, draft, pre, assets);
    return json_buf;
}

static firc_err_t parse(const char *json, const firc_release_want_t *want, firc_release_t *r) {
    return firc_release_parse(json, strlen(json), want, r);
}

static int reason_is(const char *json, const char *want_reason) {
    firc_release_t r;
    if (parse(json, &WANT, &r) != FIRC_OK) { return 0; }
    int ok = !r.installable && r.reason != NULL && strcmp(r.reason, want_reason) == 0;
    firc_release_clear(&r);
    return ok;
}

static firc_version_t tag_version(const char *tag) {
    firc_version_t v;
    memset(&v, 0xab, sizeof(v));
    if (!firc_version_parse_tag(tag, &v)) { memset(&v, 0, sizeof(v)); }
    return v;
}

static firc_version_t installed_version(const char *s) {
    firc_version_t v;
    memset(&v, 0xab, sizeof(v));
    if (!firc_version_parse_installed(s, 1, &v)) { memset(&v, 0, sizeof(v)); }
    return v;
}

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    char *buf = malloc(65536);
    size_t n = buf ? fread(buf, 1, 65535, f) : 0;
    fclose(f);
    if (buf != NULL) { buf[n] = '\0'; }
    *len = n;
    return buf;
}

/* Catches: a string compare (0.10 vs 0.9), a dev build ranked above its release, or the revision ignored. */
TEST versions_order_by_triple_then_dev_then_revision(void) {
    firc_version_t a = tag_version("0.2.0"), b = tag_version("0.2.1");
    ASSERT(firc_version_cmp(&a, &b) < 0);
    ASSERT(firc_version_cmp(&b, &a) > 0);
    a = tag_version("0.9.9");
    b = tag_version("0.10.0");
    ASSERT(firc_version_cmp(&a, &b) < 0);
    a = tag_version("9.0.0");
    b = tag_version("10.0.0");
    ASSERT(firc_version_cmp(&a, &b) < 0);
    a = tag_version("0.2.9");
    b = tag_version("0.2.10");
    ASSERT(firc_version_cmp(&a, &b) < 0);
    a = installed_version("0.3.0~git20261012010101.8b96350");
    b = installed_version("0.3.0");
    ASSERT(firc_version_cmp(&a, &b) < 0);
    ASSERT(firc_version_cmp(&b, &a) > 0);
    a = installed_version("0.2.9");
    b = installed_version("0.3.0~git1");
    ASSERT(firc_version_cmp(&a, &b) < 0);
    a = tag_version("0.2.0");
    b = tag_version("0.2.0-rev2");
    ASSERT(firc_version_cmp(&a, &b) < 0);
    ASSERT(firc_version_cmp(&b, &a) > 0);
    a = tag_version("0.2.1");
    b = tag_version("0.2.0-rev9");
    ASSERT(firc_version_cmp(&a, &b) > 0);
    a = tag_version("v0.2.0");
    b = installed_version("0.2.0");
    ASSERT_EQ(0, firc_version_cmp(&a, &b));
    PASS();
}

/* Catches: accepting the Makefile's unattached or an overflowing part. */
TEST an_installed_version_is_x_y_z_with_an_optional_git_suffix(void) {
    firc_version_t v;
    ASSERT(firc_version_parse_installed("0.2.0", 3, &v));
    ASSERT_EQ(0u, v.major);
    ASSERT_EQ(2u, v.minor);
    ASSERT_EQ(0u, v.patch);
    ASSERT_FALSE(v.dev);
    ASSERT_EQ(3u, v.revision);
    ASSERT(firc_version_parse_installed("0.2.1~git20261012010101.8b96350", 1, &v));
    ASSERT_EQ(1u, v.patch);
    ASSERT(v.dev);
    ASSERT(firc_version_parse_installed("123456789.0.1", 1, &v));
    ASSERT_EQ(123456789u, v.major);
    const char *bad[] = {"unattached", "0.2", "0.2.0~", "0.2.0~git", "0.2.0-1", "1.2.3.4", "", "1234567890.0.0",
                         ".2.0", "0..0", "0.2.0 ", "a.b.c", "0.2.x"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERTm(bad[i], !firc_version_parse_installed(bad[i], 1, &v));
    }
    ASSERT_FALSE(firc_version_parse_installed(NULL, 1, &v));
    PASS();
}

/* Catches: a v or -rev release becoming unknown and never offered, or a tag treated as dev. */
TEST a_tag_is_what_the_makefile_accepts(void) {
    firc_version_t v;
    ASSERT(firc_version_parse_tag("0.3.0", &v));
    ASSERT_EQ(0u, v.major);
    ASSERT_EQ(3u, v.minor);
    ASSERT_EQ(0u, v.patch);
    ASSERT_EQ(1u, v.revision);
    ASSERT_FALSE(v.dev);
    ASSERT(firc_version_parse_tag("v0.3.0", &v));
    ASSERT_EQ(3u, v.minor);
    ASSERT_EQ(1u, v.revision);
    ASSERT(firc_version_parse_tag("0.3.0-rev2", &v));
    ASSERT_EQ(2u, v.revision);
    ASSERT_FALSE(v.dev);
    ASSERT(firc_version_parse_tag("v1.20.300-rev12", &v));
    ASSERT_EQ(1u, v.major);
    ASSERT_EQ(20u, v.minor);
    ASSERT_EQ(300u, v.patch);
    ASSERT_EQ(12u, v.revision);
    const char *bad[] = {"0.3.0-rev0", "0.3.0~git1", "0.3.0-beta", "latest", "0.3.0-rev", "0.3.0-rev2x",
                         "vv0.3.0",    "V0.3.0",     "0.3",        "",       "0.3.0-1"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERTm(bad[i], !firc_version_parse_tag(bad[i], &v));
    }
    PASS();
}

/* Catches: the asset looked up by the raw tag, or the version text built from it. */
TEST the_asset_name_carries_the_version_without_v_and_the_revision(void) {
    firc_version_t v;
    ASSERT(firc_version_parse_tag("v0.3.0-rev2", &v));
    char name[160];
    size_t n = firc_release_asset_name(name, sizeof(name), &v, MIPSEL);
    ASSERT_STR_EQ("firc_0.3.0-2_entware_mipsel-3.4_kn.ipk", name);
    ASSERT_EQ(strlen("firc_0.3.0-2_entware_mipsel-3.4_kn.ipk"), n);
    char text[32];
    firc_version_text(&v, text, sizeof(text));
    ASSERT_STR_EQ("0.3.0", text);
    PASS();
}

/* Catches: a wrong field name, an inverted digest decode, or selecting another target's asset. */
TEST the_real_0_2_0_release_is_installable_for_mipsel(void) {
    static const uint8_t digest[32] = {0xae, 0xf6, 0x17, 0x50, 0x63, 0xfc, 0x5b, 0xbc, 0xfd, 0x89, 0x20,
                                       0x0f, 0x92, 0xad, 0x01, 0xb1, 0x58, 0xed, 0xf2, 0xaa, 0xe0, 0xeb,
                                       0x43, 0x72, 0x4e, 0x3b, 0x55, 0xa3, 0xeb, 0x83, 0x24, 0x07};
    size_t len = 0;
    char *json = read_file("tests/unit/fixtures/release-0.2.0.json", &len);
    ASSERT(json != NULL);
    firc_release_t r;
    firc_err_t err = firc_release_parse(json, len, &WANT, &r);
    free(json);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT(r.known);
    ASSERT(r.installable);
    ASSERT_EQ(NULL, r.reason);
    ASSERT_STR_EQ("0.2.0", r.tag);
    ASSERT_STR_EQ("0.2.0", r.version_text);
    ASSERT_EQ(2u, r.version.minor);
    ASSERT_EQ(1u, r.version.revision);
    ASSERT_STR_EQ("2026-10-07T20:27:40Z", r.published_at);
    ASSERT_STR_EQ("firc_0.2.0-1_entware_mipsel-3.4_kn.ipk", r.asset.name);
    ASSERT_EQ(829104u, r.asset.size);
    ASSERT_MEM_EQ(digest, r.asset.sha256, 32);
    ASSERT_STR_EQ("https://github.com/hoaxisr/firc/releases/download/0.2.0/firc_0.2.0-1_entware_mipsel-3.4_kn.ipk",
                  r.asset.url);
    ASSERT_EQ(0, strncmp(r.notes, "- Туннели VLESS", strlen("- Туннели VLESS")));
    firc_release_clear(&r);
    PASS();
}

/* Catches: a missing asset hiding the version, or a release offered to a target it has no build for. */
TEST a_target_without_its_asset_shows_the_version_but_cannot_install(void) {
    size_t len = 0;
    char *json = read_file("tests/unit/fixtures/release-0.2.0.json", &len);
    ASSERT(json != NULL);
    firc_release_want_t want = {"armv7-3.2_kn", FIRC_UPDATE_DOWNLOAD_PREFIX};
    firc_release_t r;
    firc_err_t err = firc_release_parse(json, len, &want, &r);
    free(json);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT(r.known);
    ASSERT_STR_EQ("0.2.0", r.version_text);
    ASSERT_FALSE(r.installable);
    ASSERT_STR_EQ("no-asset", r.reason);
    firc_release_clear(&r);
    ASSERT(reason_is(release("0.3.0", "false", "false", ""), "no-asset"));
    PASS();
}

/* Catches: the first of two same-named assets taken as the one to install. */
TEST two_assets_with_this_name_are_not_installable(void) {
    char two[2 * sizeof(asset_buf)];
    snprintf(two, sizeof(two), "%s,%s", good_asset(), good_asset());
    ASSERT(reason_is(release("0.3.0", "false", "false", two), "many-assets"));
    PASS();
}

/* Catches: the asset state left unread. */
TEST an_asset_not_yet_uploaded_is_not_installable(void) {
    ASSERT(reason_is(release("0.3.0", "false", "false",
                             asset(NAME030, "starter", "\"sha256:" HEX64 "\"", "829104", URL030)),
                     "not-uploaded"));
    PASS();
}

/* Catches: a missing, foreign or short digest accepted, leaving nothing to verify the download against. */
TEST a_digest_that_is_not_sha256_of_64_hex_is_refused(void) {
    const char *bad[] = {"null",
                         "\"sha512:" HEX64 "\"",
                         "\"sha256:aef6175063fc5bbcfd89200f92ad01b158edf2aae0eb43724e3b55a3eb83240\"",
                         "\"sha256:" HEX64 "0\"",
                         "\"sha256:zef6175063fc5bbcfd89200f92ad01b158edf2aae0eb43724e3b55a3eb832407\"",
                         "\"" HEX64 "\"",
                         "5"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERTm(bad[i], reason_is(release("0.3.0", "false", "false", asset(NAME030, "uploaded", bad[i], "829104", URL030)),
                                  "no-digest"));
    }
    PASS();
}

/* Catches: a zero size or one past the 16 MiB cap accepted, or the cap itself refused. */
TEST a_size_of_zero_or_over_16_mib_is_refused(void) {
    const char *bad[] = {"0", "16777217", "-1", "1.5", "\"829104\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERTm(bad[i], reason_is(release("0.3.0", "false", "false",
                                          asset(NAME030, "uploaded", "\"sha256:" HEX64 "\"", bad[i], URL030)),
                                  "bad-size"));
    }
    const char *json =
        release("0.3.0", "false", "false", asset(NAME030, "uploaded", "\"sha256:" HEX64 "\"", "16777216", URL030));
    firc_release_t r;
    ASSERT_EQ(FIRC_OK, parse(json, &WANT, &r));
    ASSERT(r.installable);
    ASSERT_EQ(16777216u, r.asset.size);
    firc_release_clear(&r);
    PASS();
}

/* Catches: a download URL taken from the answer without matching it to this release's tag and asset. */
TEST a_download_url_off_the_release_is_refused(void) {
    const char *bad[] = {"https://evil.org/hoaxisr/firc/releases/download/0.3.0/" NAME030,
                         "http://github.com/hoaxisr/firc/releases/download/0.3.0/" NAME030,
                         "https://github.com/hoaxisr/firc/releases/download/0.2.0/" NAME030,
                         "https://github.com/hoaxisr/firc/releases/download/0.3.0/firc_0.2.0-1_entware_mipsel-3.4_kn.ipk",
                         "https://github.com/hoaxisr/firc/releases/download/0.3.0/" NAME030 "?x=1"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERTm(bad[i], reason_is(release("0.3.0", "false", "false",
                                          asset(NAME030, "uploaded", "\"sha256:" HEX64 "\"", "829104", bad[i])),
                                  "bad-url"));
    }
    firc_release_want_t local = {MIPSEL, "http://127.0.0.1:1/d/"};
    firc_release_t r;
    const char *json = release("0.3.0", "false", "false",
                               asset(NAME030, "uploaded", "\"sha256:" HEX64 "\"", "829104",
                                     "http://127.0.0.1:1/d/0.3.0/" NAME030));
    ASSERT_EQ(FIRC_OK, parse(json, &local, &r));
    ASSERT(r.installable);
    ASSERT_STR_EQ("http://127.0.0.1:1/d/0.3.0/" NAME030, r.asset.url);
    firc_release_clear(&r);
    PASS();
}

/* Catches: draft or prerelease left unread, offering an unfinished release. */
TEST a_draft_or_prerelease_never_installs(void) {
    ASSERT(reason_is(release("0.3.0", "true", "false", good_asset()), "prerelease"));
    ASSERT(reason_is(release("0.3.0", "false", "true", good_asset()), "prerelease"));
    firc_release_t r;
    ASSERT_EQ(FIRC_OK, parse(release("0.3.0", "false", "false", good_asset()), &WANT, &r));
    ASSERT(r.installable);
    firc_release_clear(&r);
    PASS();
}

/* Catches: an unparseable tag dropped instead of shown, or offered for install. */
TEST an_unknown_tag_shows_but_never_installs(void) {
    firc_release_t r;
    ASSERT_EQ(FIRC_OK, parse(release("nightly", "true", "false", good_asset()), &WANT, &r));
    ASSERT_FALSE(r.known);
    ASSERT_FALSE(r.installable);
    ASSERT_STR_EQ("unknown-version", r.reason);
    ASSERT_STR_EQ("nightly", r.tag);
    firc_release_clear(&r);
    PASS();
}

/* Catches: an empty target building a name that happens to match some asset. */
TEST no_target_is_said_before_any_asset_is_looked_at(void) {
    firc_release_want_t none = {"", FIRC_UPDATE_DOWNLOAD_PREFIX};
    firc_release_t r;
    ASSERT_EQ(FIRC_OK, parse(release("0.3.0", "false", "false", ""), &none, &r));
    ASSERT_STR_EQ("no-target", r.reason);
    ASSERT(r.known);
    firc_release_clear(&r);
    PASS();
}

/* Catches: a byte cut of the notes splitting a 3-byte character. */
TEST notes_are_cut_at_16_kib_on_a_character_boundary(void) {
    size_t cap = 7000 * 3 + 64;
    char *json = malloc(cap);
    ASSERT(json != NULL);
    size_t n = (size_t)snprintf(json, cap, "{\"tag_name\":\"0.3.0\",\"body\":\"");
    for (int i = 0; i < 7000; i++) {
        memcpy(json + n, "\xe2\x82\xbd", 3);
        n += 3;
    }
    memcpy(json + n, "\"}", 3);
    firc_release_t r;
    firc_err_t err = firc_release_parse(json, n + 2, &WANT, &r);
    free(json);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ(16383u, strlen(r.notes));
    ASSERT_EQ(0xbd, (unsigned char)r.notes[16382]);
    firc_release_clear(&r);
    PASS();
}

/* Catches: a null or absent body leaving notes NULL. */
TEST a_null_body_is_empty_notes(void) {
    firc_release_t r;
    ASSERT_EQ(FIRC_OK, parse("{\"tag_name\":\"0.3.0\",\"body\":null}", &WANT, &r));
    ASSERT(r.notes != NULL);
    ASSERT_STR_EQ("", r.notes);
    firc_release_clear(&r);
    ASSERT_EQ(FIRC_OK, parse("{\"tag_name\":\"0.3.0\"}", &WANT, &r));
    ASSERT(r.notes != NULL);
    ASSERT_STR_EQ("", r.notes);
    firc_release_clear(&r);
    PASS();
}

/* Catches: a non-release answer read as a release with every field empty. */
TEST a_body_that_is_not_a_release_is_a_protocol_error(void) {
    const char *bad[] = {"[]", "{}", "not json", "{\"tag_name\":5}", "{\"tag_name\":null}", ""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_release_t r;
        ASSERTm(bad[i], firc_release_parse(bad[i], strlen(bad[i]), &WANT, &r) == FIRC_ERR_PROTO);
        firc_release_clear(&r);
    }
    PASS();
}

/* Catches: a host matched by substring, an http downgrade, a foreign port or userinfo let through. */
TEST the_api_url_policy(void) {
    ASSERT(firc_update_api_url_ok(FIRC_UPDATE_API_URL));
    ASSERT(firc_update_api_url_ok("https://api.github.com/repos/hoaxisr/firc/releases/latest"));
    const char *bad[] = {"http://api.github.com/repos/hoaxisr/firc/releases/latest",
                         "https://api.github.com.evil.org/",
                         "https://evil.org/?https://api.github.com/",
                         "https://api.github.com:8443/",
                         "http://api.github.com:443/",
                         "https://u@api.github.com/",
                         "https://:p@api.github.com/",
                         "https://github.com/",
                         "https://xapi.github.com/",
                         "ftp://api.github.com/",
                         "",
                         "not a url"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) { ASSERTm(bad[i], !firc_update_api_url_ok(bad[i])); }
    ASSERT_FALSE(firc_update_api_url_ok(NULL));
    PASS();
}

/* Catches: a suffix match without the dot, or an http downgrade. */
TEST the_download_url_policy(void) {
    ASSERT(firc_update_download_url_ok("https://github.com/hoaxisr/firc/releases/download/0.2.0/x.ipk"));
    ASSERT(firc_update_download_url_ok(
        "https://release-assets.githubusercontent.com/github-production-release-asset/1/2?x=y"));
    ASSERT(firc_update_download_url_ok("https://objects.githubusercontent.com/x"));
    const char *bad[] = {"https://githubusercontent.com.evil.org/",
                         "https://evilgithubusercontent.com/",
                         "https://githubusercontent.com/",
                         "http://objects.githubusercontent.com/",
                         "http://github.com:443/",
                         "https://github.com:444/",
                         "https://u@github.com/",
                         "https://github.com.evil.org/",
                         "https://evil.org/?https://github.com/",
                         "http://github.com/hoaxisr/firc/releases/download/0.2.0/x.ipk",
                         ""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERTm(bad[i], !firc_update_download_url_ok(bad[i]));
    }
    ASSERT_FALSE(firc_update_download_url_ok(NULL));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(versions_order_by_triple_then_dev_then_revision);
    RUN_TEST(an_installed_version_is_x_y_z_with_an_optional_git_suffix);
    RUN_TEST(a_tag_is_what_the_makefile_accepts);
    RUN_TEST(the_asset_name_carries_the_version_without_v_and_the_revision);
    RUN_TEST(the_real_0_2_0_release_is_installable_for_mipsel);
    RUN_TEST(a_target_without_its_asset_shows_the_version_but_cannot_install);
    RUN_TEST(two_assets_with_this_name_are_not_installable);
    RUN_TEST(an_asset_not_yet_uploaded_is_not_installable);
    RUN_TEST(a_digest_that_is_not_sha256_of_64_hex_is_refused);
    RUN_TEST(a_size_of_zero_or_over_16_mib_is_refused);
    RUN_TEST(a_download_url_off_the_release_is_refused);
    RUN_TEST(a_draft_or_prerelease_never_installs);
    RUN_TEST(an_unknown_tag_shows_but_never_installs);
    RUN_TEST(no_target_is_said_before_any_asset_is_looked_at);
    RUN_TEST(notes_are_cut_at_16_kib_on_a_character_boundary);
    RUN_TEST(a_null_body_is_empty_notes);
    RUN_TEST(a_body_that_is_not_a_release_is_a_protocol_error);
    RUN_TEST(the_api_url_policy);
    RUN_TEST(the_download_url_policy);
    GREATEST_MAIN_END();
}

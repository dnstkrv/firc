#include "greatest.h"

#include <string.h>

#include "firc/autolistcand.h"
#include "firc/autolistcheck.h"

static const firc_sub_fetch_info_t k_none = {false, false, false, false};
static const firc_sub_fetch_info_t k_none_timed_out = {false, false, false, true};
static const firc_sub_fetch_info_t k_tcp = {true, false, false, false};
static const firc_sub_fetch_info_t k_tcp_reset = {true, false, true, false};
static const firc_sub_fetch_info_t k_tcp_timed_out = {true, false, false, true};
static const firc_sub_fetch_info_t k_tls = {true, true, false, false};
static const firc_sub_fetch_info_t k_tls_reset = {true, true, true, false};
static const firc_sub_fetch_info_t k_tls_timed_out = {true, true, false, true};

static firc_autolist_result_t classify(const firc_sub_fetch_info_t *info, uint32_t bytes, bool stalled, bool complete) {
    firc_autolist_result_t r;
    memset(&r, 0xAA, sizeof(r));
    firc_autolist_classify(info, bytes, stalled, complete, &r);
    return r;
}

TEST stall_in_window_is_freeze(void) {
    firc_autolist_result_t r = classify(&k_tls, 16384, true, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_FREEZE, r.why);
    ASSERT_EQ(16384, r.bytes);
    ASSERT_FALSE(r.short_body);
    PASS();
}

TEST stall_at_both_window_edges_is_freeze(void) {
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, classify(&k_tls, 8192, true, false).verdict);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, classify(&k_tls, 32768, true, false).verdict);
    PASS();
}

TEST stall_below_window_is_unknown(void) {
    firc_autolist_result_t r = classify(&k_tls, 4096, true, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_tls, 8191, true, false).verdict);
    PASS();
}

TEST a_slow_page_without_a_stall_is_not_freeze(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_tls, 16384, false, false).verdict);
    PASS();
}

TEST past_window_is_open(void) {
    firc_autolist_result_t r = classify(&k_tls, 40000, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT_EQ(0, r.why);
    ASSERT_FALSE(r.short_body);
    ASSERT_EQ(40000, r.bytes);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, classify(&k_tls, 32769, true, false).verdict);
    PASS();
}

TEST the_capped_body_is_open(void) {
    firc_autolist_result_t r = classify(&k_tls, 65536, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT_FALSE(r.short_body);
    PASS();
}

TEST complete_small_is_open_short(void) {
    firc_autolist_result_t r = classify(&k_tls, 3000, false, true);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT(r.short_body);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST complete_big_is_open_not_short(void) {
    firc_autolist_result_t r = classify(&k_tls, 50000, false, true);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT_FALSE(r.short_body);
    PASS();
}

TEST timeout_before_tls_is_no_answer(void) {
    firc_autolist_result_t r = classify(&k_tcp_timed_out, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_NO_ANSWER, r.why);
    PASS();
}

TEST stall_before_tls_is_not_no_answer(void) {
    firc_autolist_result_t r = classify(&k_tcp, 0, true, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST timeout_without_connect_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_none_timed_out, 0, false, false).verdict);
    PASS();
}

TEST timeout_after_tls_without_body_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_tls_timed_out, 0, false, false).verdict);
    PASS();
}

TEST reset_wins_over_timeout_before_tls(void) {
    const firc_sub_fetch_info_t both = {true, false, true, true};
    firc_autolist_result_t r = classify(&both, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_RESET, r.why);
    PASS();
}

TEST reset_before_tls_is_reset(void) {
    firc_autolist_result_t r = classify(&k_tcp_reset, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_RESET, r.why);
    PASS();
}

TEST reset_after_tls_is_unknown(void) {
    firc_autolist_result_t r = classify(&k_tls_reset, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST no_connect_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_none, 0, false, false).verdict);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_none, 0, true, false).verdict);
    PASS();
}

TEST cert_error_is_unknown(void) {
    firc_autolist_result_t r = classify(&k_tcp, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST no_info_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(NULL, 50000, false, true).verdict);
    PASS();
}

TEST an_unknown_result_has_no_short_body(void) {
    firc_autolist_result_t r = classify(&k_tcp, 0, false, false);
    ASSERT_FALSE(r.short_body);
    ASSERT_EQ(0, r.bytes);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(stall_in_window_is_freeze);
    RUN_TEST(stall_at_both_window_edges_is_freeze);
    RUN_TEST(stall_below_window_is_unknown);
    RUN_TEST(a_slow_page_without_a_stall_is_not_freeze);
    RUN_TEST(past_window_is_open);
    RUN_TEST(the_capped_body_is_open);
    RUN_TEST(complete_small_is_open_short);
    RUN_TEST(complete_big_is_open_not_short);
    RUN_TEST(timeout_before_tls_is_no_answer);
    RUN_TEST(stall_before_tls_is_not_no_answer);
    RUN_TEST(timeout_without_connect_is_unknown);
    RUN_TEST(timeout_after_tls_without_body_is_unknown);
    RUN_TEST(reset_wins_over_timeout_before_tls);
    RUN_TEST(reset_before_tls_is_reset);
    RUN_TEST(reset_after_tls_is_unknown);
    RUN_TEST(no_connect_is_unknown);
    RUN_TEST(cert_error_is_unknown);
    RUN_TEST(no_info_is_unknown);
    RUN_TEST(an_unknown_result_has_no_short_body);
    GREATEST_MAIN_END();
}

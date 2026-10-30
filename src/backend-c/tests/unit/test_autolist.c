#include "greatest.h"

#include <stdio.h>
#include <string.h>

#include "firc/autolist.h"

static firc_autolist_flow_t flow(uint8_t client_last, uint16_t client_port) {
    firc_autolist_flow_t f;
    memset(&f, 0, sizeof(f));
    f.client.len = 4;
    f.client.b[0] = 192; f.client.b[1] = 168; f.client.b[2] = 1; f.client.b[3] = client_last;
    f.server.len = 4;
    f.server.b[0] = 203; f.server.b[1] = 0; f.server.b[2] = 113; f.server.b[3] = 7;
    f.client_port = client_port;
    f.server_port = 443;
    return f;
}

static firc_autolist_flow_t flow_to(uint16_t client_port, uint8_t server_last) {
    firc_autolist_flow_t f = flow(10, client_port);
    f.server.b[3] = server_last;
    return f;
}

static bool hello_times(firc_autolist_t *a, const firc_autolist_flow_t *f, const char *sni, int times, int64_t now,
                        firc_autolist_failure_t *out) {
    bool failed = false;
    for (int i = 0; i < times; i++) { failed = firc_autolist_hello(a, f, 1000, sni, now + i, out) || failed; }
    return failed;
}

TEST a_hello_sent_once_is_no_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    ASSERT(a != NULL);
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, "blocked.example", 1, 100, &out));
    ASSERT_EQ(0u, (unsigned)firc_autolist_counting(a, 100));
    firc_autolist_free(a);
    PASS();
}

TEST three_sendings_again_make_a_failure_once(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, "blocked.example", 3, 100, &out));
    ASSERT(hello_times(a, &f, "blocked.example", 1, 110, &out));
    ASSERT_STR_EQ("blocked.example", out.host);
    ASSERT_EQ(1u, out.fails);
    ASSERT_EQ(FIRC_AUTOLIST_RETRANS, out.why);
    ASSERT_FALSE(out.listed);
    ASSERTm("a fifth sending counts nothing more", !hello_times(a, &f, "blocked.example", 1, 111, &out));
    firc_autolist_free(a);
    PASS();
}

TEST three_failed_connections_list_the_host(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow(10, (uint16_t)(50000 + i));
        ASSERT(hello_times(a, &f, "blocked.example", 4, 100 + i * 10, &out));
    }
    ASSERT(out.listed);
    ASSERT_EQ(3u, out.fails);
    ASSERTm("the count starts over once listed", firc_autolist_counting(a, 130) == 0);
    firc_autolist_free(a);
    PASS();
}

TEST failures_too_far_apart_start_over(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t f1 = flow(10, 50001), f2 = flow(10, 50002), f3 = flow(10, 50003);
    ASSERT(hello_times(a, &f1, "slow.example", 4, 100, &out));
    ASSERT(hello_times(a, &f2, "slow.example", 4, 150, &out));
    ASSERT_EQ(2u, out.fails);
    ASSERT(hello_times(a, &f3, "slow.example", 4, 150 + FIRC_AUTOLIST_FAIL_SECS + 10, &out));
    ASSERT_EQ(1u, out.fails);
    ASSERT_FALSE(out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST an_early_reset_is_a_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, "reset.example", 1, 100, &out));
    ASSERT(firc_autolist_reply(a, &f, true, 101, &out));
    ASSERT_EQ(FIRC_AUTOLIST_RESET, out.why);
    ASSERT_STR_EQ("reset.example", out.host);
    ASSERTm("one verdict per connection", !firc_autolist_reply(a, &f, true, 102, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_working_connection_clears_the_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t f1 = flow(10, 50001), f2 = flow(10, 50002), f3 = flow(10, 50003), f4 = flow(10, 50004);
    ASSERT(hello_times(a, &f1, "flaky.example", 4, 100, &out));
    ASSERT(hello_times(a, &f2, "flaky.example", 4, 105, &out));
    ASSERT_FALSE(hello_times(a, &f3, "flaky.example", 1, 110, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &f3, false, 111, &out));
    ASSERT(hello_times(a, &f4, "flaky.example", 4, 112, &out));
    ASSERT_EQ(1u, out.fails);
    ASSERT_FALSE(out.listed);
    ASSERTm("and a reset after it worked is no failure", !firc_autolist_reply(a, &f3, true, 113, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_working_address_does_not_clear_another_s_failures(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t bad1 = flow_to(50001, 41), good = flow_to(50002, 215), bad2 = flow_to(50003, 41),
                         bad3 = flow_to(50004, 41);
    ASSERT(hello_times(a, &bad1, "www.linkedin.com", 4, 100, &out));
    ASSERT_FALSE(hello_times(a, &good, "www.linkedin.com", 1, 110, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &good, false, 111, &out));
    ASSERT(hello_times(a, &bad2, "www.linkedin.com", 4, 112, &out));
    ASSERT_EQ(2u, out.fails);
    ASSERT(hello_times(a, &bad3, "www.linkedin.com", 4, 120, &out));
    ASSERT(out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST a_failed_address_that_works_again_clears_the_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t on_a = flow_to(50001, 41), on_b = flow_to(50002, 215), b_again = flow_to(50003, 215),
                         later = flow_to(50004, 41);
    ASSERT(hello_times(a, &on_a, "x.example", 4, 100, &out));
    ASSERT(hello_times(a, &on_b, "x.example", 4, 105, &out));
    ASSERT_EQ(2u, out.fails);
    ASSERT_FALSE(hello_times(a, &b_again, "x.example", 1, 110, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &b_again, false, 111, &out));
    ASSERT(hello_times(a, &later, "x.example", 4, 112, &out));
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST a_reply_to_a_connection_never_seen_is_ignored(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(firc_autolist_reply(a, &f, true, 100, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_hello_without_sni_takes_its_name_from_the_dns_answer(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "named.example", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(hello_times(a, &f, NULL, 4, 100, &out));
    ASSERT_STR_EQ("named.example", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST another_device_s_answer_names_nothing(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_flow_t other = flow(11, 50000);
    firc_autolist_hint(a, &other.client, "named.example", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERTm("a connection with no name is never a failure of anyone's", !hello_times(a, &f, NULL, 4, 100, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_stale_answer_names_nothing(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "named.example", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, NULL, 4, 90 + FIRC_AUTOLIST_HINT_SECS + 1, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_new_handshake_on_a_reused_port_starts_its_own_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, "x.example", 100, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, "x.example", 101, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, "x.example", 102, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, "x.example", 103, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, "x.example", 104, &out));
    ASSERT(firc_autolist_hello(a, &f, 2000, "x.example", 105, &out));
    firc_autolist_free(a);
    PASS();
}

TEST the_thresholds_can_be_set(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_params_t p = {1, 0, 1};
    firc_autolist_set_params(a, &p);
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT(hello_times(a, &f, "fast.example", 2, 100, &out));
    ASSERT(out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST more_connections_than_slots_do_not_break_it(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint32_t i = 0; i < FIRC_AUTOLIST_FLOWS * 2; i++) {
        firc_autolist_flow_t f = flow((uint8_t)(i % 200), (uint16_t)(10000 + i));
        char name[32];
        snprintf(name, sizeof(name), "h%u.example", (unsigned)(i % (FIRC_AUTOLIST_HOSTS * 2)));
        (void)firc_autolist_hello(a, &f, i, name, 100, &out);
    }
    firc_autolist_flow_t f = flow(250, 60000);
    ASSERT(hello_times(a, &f, "late.example", 4, 100, &out));
    ASSERT_STR_EQ("late.example", out.host);
    firc_autolist_free(a);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_hello_sent_once_is_no_failure);
    RUN_TEST(three_sendings_again_make_a_failure_once);
    RUN_TEST(three_failed_connections_list_the_host);
    RUN_TEST(failures_too_far_apart_start_over);
    RUN_TEST(an_early_reset_is_a_failure);
    RUN_TEST(a_working_connection_clears_the_count);
    RUN_TEST(a_working_address_does_not_clear_another_s_failures);
    RUN_TEST(a_failed_address_that_works_again_clears_the_count);
    RUN_TEST(a_reply_to_a_connection_never_seen_is_ignored);
    RUN_TEST(a_hello_without_sni_takes_its_name_from_the_dns_answer);
    RUN_TEST(another_device_s_answer_names_nothing);
    RUN_TEST(a_stale_answer_names_nothing);
    RUN_TEST(a_new_handshake_on_a_reused_port_starts_its_own_count);
    RUN_TEST(the_thresholds_can_be_set);
    RUN_TEST(more_connections_than_slots_do_not_break_it);
    GREATEST_MAIN_END();
}

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
    if (sni != NULL && sni[0] != '\0') { firc_autolist_hint(a, &f->client, sni, &f->server, 1, now); }
    bool failed = false;
    for (int i = 0; i < times; i++) { failed = firc_autolist_hello(a, f, 1000, 0, sni, now + i, out) || failed; }
    return failed;
}

static bool bare_hello_times(firc_autolist_t *a, const firc_autolist_flow_t *f, const char *sni, int times,
                             int64_t now, firc_autolist_failure_t *out) {
    bool failed = false;
    for (int i = 0; i < times; i++) { failed = firc_autolist_hello(a, f, 1000, 0, sni, now + i, out) || failed; }
    return failed;
}

TEST a_hello_sent_once_is_no_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    ASSERT(a != NULL);
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, "blocked.example", 1, 100, &out));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 100));
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
    firc_autolist_flow_t next = flow(10, 50003);
    ASSERT(hello_times(a, &next, "blocked.example", 4, 130, &out));
    ASSERTm("the count starts over once listed", out.fails == 1 && !out.listed);
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
    firc_autolist_hint(a, &f.client, "x.example", &f.server, 1, 100);
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "x.example", 100, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "x.example", 101, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, 0, "x.example", 102, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, 0, "x.example", 103, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, 0, "x.example", 104, &out));
    ASSERT(firc_autolist_hello(a, &f, 2000, 0, "x.example", 105, &out));
    ASSERT_FALSE(out.bypass);
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
        (void)firc_autolist_hello(a, &f, i, 0, name, 100, &out);
    }
    firc_autolist_flow_t f = flow(250, 60000);
    ASSERT(hello_times(a, &f, "late.example", 4, 100, &out));
    ASSERT_STR_EQ("late.example", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST no_hint_is_bypass_not_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "a.test", 4, 100, &out));
    ASSERT(out.bypass);
    ASSERT_FALSE(out.listed);
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    firc_ip_t clients[4];
    uint32_t fails[4];
    ASSERT_EQ(1u, (unsigned)firc_autolist_bypassed(a, 104, clients, fails, 4));
    ASSERT_EQ(4, clients[0].len);
    ASSERT_EQ(0, memcmp(clients[0].b, f.client.b, 4));
    ASSERT_EQ(1u, fails[0]);
    firc_autolist_free(a);
    PASS();
}

TEST hint_with_other_name_is_bypass(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "b.test", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "a.test", 4, 100, &out));
    ASSERT(out.bypass);
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    firc_autolist_free(a);
    PASS();
}

TEST two_names_on_one_address_both_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, 90);
    firc_autolist_hint(a, &f.client, "b.test", &f.server, 1, 91);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "a.test", 4, 100, &out));
    ASSERT_FALSE(out.bypass);
    ASSERT_STR_EQ("a.test", out.host);
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST failures_day_counts_and_expires(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    const int64_t t = 3600 * 1000;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow(10, (uint16_t)(50000 + i));
        firc_autolist_hint(a, &f.client, "day.test", &f.server, 1, t);
        ASSERT(bare_hello_times(a, &f, "day.test", 4, t, &out));
    }
    ASSERT_EQ(3u, firc_autolist_failures_day(a, t + 86399));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, t + 86400));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, t + 86400 + 3600));
    firc_autolist_free(a);
    PASS();
}

TEST hint_same_name_counts(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow(10, (uint16_t)(50000 + i));
        firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, 100);
        ASSERT(bare_hello_times(a, &f, "a.test", 4, 100 + i * 20, &out));
        ASSERT_FALSE(out.bypass);
    }
    ASSERT(out.listed);
    ASSERT_STR_EQ("a.test", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST no_sni_uses_hint(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "", 4, 100, &out));
    ASSERT_FALSE(out.bypass);
    ASSERT_STR_EQ("a.test", out.host);
    firc_autolist_free(a);
    PASS();
}

static bool stalled(firc_autolist_t *a, uint16_t port, uint32_t ack0, uint32_t fin_ack, int64_t at, int64_t held,
                    firc_autolist_nomination_t *nom) {
    firc_autolist_flow_t f = flow(10, port);
    firc_autolist_hint(a, &f.client, "freeze.test", &f.server, 1, at);
    firc_autolist_failure_t out;
    (void)firc_autolist_hello(a, &f, 7, ack0, "freeze.test", at, &out);
    (void)firc_autolist_reply(a, &f, false, at + 1, &out);
    return firc_autolist_fin(a, &f, fin_ack, at + held, nom);
}

TEST fin_in_window_after_ten_seconds_notes(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT(stalled(a, 50002, 1000, 1000 + 16384, 150, 11, &nom));
    ASSERT_STR_EQ("freeze.test", nom.host);
    ASSERT_EQ(16384u, nom.received);
    ASSERT_EQ(10, nom.client.b[3]);
    ASSERTm("the notes are cleared", !stalled(a, 50003, 1000, 1000 + 16384, 170, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST fin_too_soon_is_no_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 9, &nom));
    ASSERT_FALSE(stalled(a, 50002, 1000, 1000 + 16384, 150, 9, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST fin_outside_window_is_no_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 4096, 100, 11, &nom));
    ASSERT_FALSE(stalled(a, 50002, 1000, 1000 + 4096, 150, 11, &nom));
    ASSERT_FALSE(stalled(a, 50003, 1000, 1000 + 40000, 160, 11, &nom));
    ASSERT_FALSE(stalled(a, 50004, 1000, 1000 + 40000, 170, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST fin_window_edges_are_in(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 8192, 100, 10, &nom));
    ASSERT(stalled(a, 50002, 1000, 1000 + 32768, 150, 10, &nom));
    ASSERT_EQ(32768u, nom.received);
    firc_autolist_free(a);
    PASS();
}

TEST fin_wraps_mod_2_32(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 0xfffff000u, 0x00003000u, 100, 11, &nom));
    ASSERT(stalled(a, 50002, 0xfffff000u, 0x00003000u, 150, 11, &nom));
    ASSERT_EQ(0x4000u, nom.received);
    firc_autolist_free(a);
    PASS();
}

TEST notes_older_than_two_minutes_do_not_pair(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT_FALSE(stalled(a, 50002, 1000, 1000 + 16384, 100 + 121, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST notes_two_minutes_apart_pair(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT(stalled(a, 50002, 1000, 1000 + 16384, 100 + 120, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST a_bypass_flow_s_fin_is_no_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    firc_autolist_failure_t out;
    for (uint16_t port = 50001; port <= 50002; port++) {
        firc_autolist_flow_t f = flow(10, port);
        (void)firc_autolist_hello(a, &f, 7, 1000, "freeze.test", 100 + port - 50001, &out);
        ASSERT_FALSE(firc_autolist_fin(a, &f, 1000 + 16384, 120 + port - 50001, &nom));
    }
    firc_autolist_free(a);
    PASS();
}

TEST a_fin_sent_again_is_one_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    firc_autolist_flow_t f = flow(10, 50001);
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT_FALSE(firc_autolist_fin(a, &f, 1000 + 16384, 112, &nom));
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
    RUN_TEST(no_hint_is_bypass_not_failure);
    RUN_TEST(hint_with_other_name_is_bypass);
    RUN_TEST(two_names_on_one_address_both_count);
    RUN_TEST(failures_day_counts_and_expires);
    RUN_TEST(hint_same_name_counts);
    RUN_TEST(no_sni_uses_hint);
    RUN_TEST(fin_in_window_after_ten_seconds_notes);
    RUN_TEST(fin_too_soon_is_no_note);
    RUN_TEST(fin_outside_window_is_no_note);
    RUN_TEST(fin_window_edges_are_in);
    RUN_TEST(fin_wraps_mod_2_32);
    RUN_TEST(notes_older_than_two_minutes_do_not_pair);
    RUN_TEST(notes_two_minutes_apart_pair);
    RUN_TEST(a_bypass_flow_s_fin_is_no_note);
    RUN_TEST(a_fin_sent_again_is_one_note);
    GREATEST_MAIN_END();
}

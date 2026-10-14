#include "greatest.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "firc/events.h"
#include "firc/log.h"
#include "firc/logrep.h"

static uint64_t g_now;

static uint64_t fake_mono(void) { return g_now; }

static int g_devnull = -1;

static void quiet_begin(void) {
    firc_event_reset_for_test();
    g_now = 5000;
    firc_logrep_set_clock_for_test(fake_mono);
    g_devnull = open("/dev/null", O_WRONLY);
    firc_log_set_fd(g_devnull);
}

static void quiet_end(void) {
    firc_log_set_fd(STDOUT_FILENO);
    if (g_devnull >= 0) { close(g_devnull); }
    g_devnull = -1;
    firc_logrep_set_clock_for_test(NULL);
}

static size_t journal(firc_event_t *out, size_t cap) {
    uint64_t next = 0, dropped = 0;
    return firc_event_read(0, out, cap, &next, &dropped);
}

/* Catches: a repeat said at its level, a reminder before ten minutes, a reminder without its count or how long it has lasted, or no reminder at all. */
TEST a_repeat_is_debug_until_ten_minutes_pass(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "x_tables ipv4 nat refused");
    g_now += 1000;
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "x_tables ipv4 nat refused");
    g_now = 5000 + FIRC_LOGREP_REMIND_MS - 1;
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "x_tables ipv4 nat refused");
    g_now = 5000 + FIRC_LOGREP_REMIND_MS;
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "x_tables ipv4 nat refused");
    g_now += 1000;
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "x_tables ipv4 nat refused");
    firc_event_t out[8];
    size_t n = journal(out, 8);
    quiet_end();
    ASSERT_EQ_FMT((size_t)5, n, "%zu");
    ASSERT_EQ(FIRC_LOG_WARN, out[0].u.log.level);
    ASSERT_STR_EQ("x_tables ipv4 nat refused", out[0].u.log.text);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[1].u.log.level);
    ASSERT_STR_EQ("x_tables ipv4 nat refused", out[1].u.log.text);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[2].u.log.level);
    ASSERT_EQ(FIRC_LOG_WARN, out[3].u.log.level);
    ASSERT_STR_EQ("x_tables ipv4 nat refused (still failing, 4 times for 10 min)", out[3].u.log.text);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[4].u.log.level);
    PASS();
}

/* Catches: a reminder timed from the first failure instead of the last reminder, so it repeats every call. */
TEST the_next_reminder_waits_another_ten_minutes(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    firc_logrep_fail(&r, FIRC_LOG_ERROR, "tunvless0", "down");
    g_now += FIRC_LOGREP_REMIND_MS;
    firc_logrep_fail(&r, FIRC_LOG_ERROR, "tunvless0", "down");
    g_now += FIRC_LOGREP_REMIND_MS - 1;
    firc_logrep_fail(&r, FIRC_LOG_ERROR, "tunvless0", "down");
    g_now += 1;
    firc_logrep_fail(&r, FIRC_LOG_ERROR, "tunvless0", "down");
    firc_event_t out[8];
    size_t n = journal(out, 8);
    quiet_end();
    ASSERT_EQ_FMT((size_t)4, n, "%zu");
    ASSERT_EQ(FIRC_LOG_ERROR, out[1].u.log.level);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[2].u.log.level);
    ASSERT_EQ(FIRC_LOG_ERROR, out[3].u.log.level);
    ASSERT_STR_EQ("down (still failing, 4 times for 20 min)", out[3].u.log.text);
    ASSERT_STR_EQ("tunvless0", out[3].u.log.source);
    PASS();
}

/* Catches: a recovery not said, said without failures, said at the wrong level, count or duration (seconds under a minute, whole minutes past it), or a failure after it taken as a repeat instead of a first. */
TEST recovery_is_said_once_and_starts_over(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    ASSERT_FALSE(firc_logrep_ok(&r, NULL, "group \"%s\"", "vpn"));
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "group \"vpn\": link: no such device");
    g_now += 90000;
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "group \"vpn\": link: no such device");
    g_now += 90000;
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "group \"vpn\": link: no such device");
    g_now += 59999;
    ASSERT(firc_logrep_ok(&r, NULL, "group \"%s\"", "vpn"));
    ASSERT_FALSE(firc_logrep_ok(&r, NULL, "group \"%s\"", "vpn"));
    g_now += 1000;
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "group \"vpn\": link: no such device");
    g_now += 59999;
    firc_logrep_ok(&r, NULL, "group \"vpn\"");
    firc_event_t out[8];
    size_t n = journal(out, 8);
    quiet_end();
    ASSERT_EQ_FMT((size_t)6, n, "%zu");
    ASSERT_EQ(FIRC_LOG_INFO, out[3].u.log.level);
    ASSERT_STR_EQ("group \"vpn\": recovered after 3 failures over 3 min", out[3].u.log.text);
    ASSERT_EQ(FIRC_LOG_WARN, out[4].u.log.level);
    ASSERT_STR_EQ("group \"vpn\": recovered after 1 failure over 59 s", out[5].u.log.text);
    PASS();
}

/* Catches: a limiter that holds the first line, lets a held one through early, loses the count, or keeps the count after it was said. */
TEST a_rated_line_is_said_once_per_interval_with_the_count(void) {
    quiet_begin();
    firc_lograte_t r = {0};
    for (int i = 0; i < 5; i++) {
        firc_lograte_say(&r, 60000, FIRC_LOG_WARN, NULL, "login refused for \"u%d\"", i);
        g_now += 1000;
    }
    g_now = 5000 + 60000;
    firc_lograte_say(&r, 60000, FIRC_LOG_WARN, NULL, "login refused for \"%s\"", "late");
    g_now += 60000;
    firc_lograte_say(&r, 60000, FIRC_LOG_WARN, NULL, "login refused for \"%s\"", "alone");
    firc_event_t out[8];
    size_t n = journal(out, 8);
    quiet_end();
    ASSERT_EQ_FMT((size_t)3, n, "%zu");
    ASSERT_STR_EQ("login refused for \"u0\"", out[0].u.log.text);
    ASSERT_STR_EQ("login refused for \"late\" (4 more since the last)", out[1].u.log.text);
    ASSERT_EQ(FIRC_LOG_WARN, out[1].u.log.level);
    ASSERT_STR_EQ("login refused for \"alone\"", out[2].u.log.text);
    PASS();
}

/* Catches: a lasting failure never raised to ERROR, raised before its duration, raised more than once, or its reminders said below ERROR once raised. */
TEST a_failure_that_lasts_is_raised_to_error_once(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    firc_logrep_fail_for(&r, 60000, NULL, "upstream dead");
    g_now += 59999;
    firc_logrep_fail_for(&r, 60000, NULL, "upstream dead");
    g_now += 1;
    firc_logrep_fail_for(&r, 60000, NULL, "upstream dead");
    g_now += 1000;
    firc_logrep_fail_for(&r, 60000, NULL, "upstream dead");
    g_now += FIRC_LOGREP_REMIND_MS - 1001;
    firc_logrep_fail_for(&r, 60000, NULL, "upstream dead");
    g_now += 1001;
    firc_logrep_fail_for(&r, 60000, NULL, "upstream dead");
    firc_logrep_ok(&r, NULL, "upstream");
    firc_event_t out[8];
    size_t n = journal(out, 8);
    quiet_end();
    ASSERT_EQ_FMT((size_t)7, n, "%zu");
    ASSERT_EQ(FIRC_LOG_WARN, out[0].u.log.level);
    ASSERT_STR_EQ("upstream dead", out[0].u.log.text);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[1].u.log.level);
    ASSERT_EQ(FIRC_LOG_ERROR, out[2].u.log.level);
    ASSERT_STR_EQ("upstream dead (still failing, 3 times for 1 min)", out[2].u.log.text);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[3].u.log.level);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[4].u.log.level);
    ASSERT_EQ(FIRC_LOG_ERROR, out[5].u.log.level);
    ASSERT_STR_EQ("upstream dead (still failing, 6 times for 11 min)", out[5].u.log.text);
    ASSERT_EQ(FIRC_LOG_INFO, out[6].u.log.level);
    ASSERT_STR_EQ("upstream: recovered after 6 failures over 11 min", out[6].u.log.text);
    PASS();
}

/* Catches: a zero duration said at WARN first, a reset that says something, or a reset run taken as still going. */
TEST a_zero_duration_is_an_error_at_once_and_a_reset_is_silent(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    firc_logrep_fail_for(&r, 0, NULL, "pool not saved");
    firc_logrep_fail_for(&r, 0, NULL, "pool not saved");
    firc_logrep_reset(&r);
    ASSERT_FALSE(firc_logrep_ok(&r, NULL, "pool"));
    firc_logrep_fail_for(&r, 0, NULL, "pool not saved");
    firc_event_t out[8];
    size_t n = journal(out, 8);
    quiet_end();
    ASSERT_EQ_FMT((size_t)3, n, "%zu");
    ASSERT_EQ(FIRC_LOG_ERROR, out[0].u.log.level);
    ASSERT_EQ(FIRC_LOG_DEBUG, out[1].u.log.level);
    ASSERT_EQ(FIRC_LOG_ERROR, out[2].u.log.level);
    ASSERT_STR_EQ("pool not saved", out[2].u.log.text);
    PASS();
}

/* Catches: the duration counted from the last WARN reminder instead of the first failure. */
TEST a_long_duration_is_counted_from_the_first_failure(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    uint64_t d = FIRC_LOGREP_REMIND_MS + FIRC_LOGREP_REMIND_MS / 2;
    firc_logrep_fail_for(&r, d, NULL, "x");
    g_now += FIRC_LOGREP_REMIND_MS;
    firc_logrep_fail_for(&r, d, NULL, "x");
    g_now += FIRC_LOGREP_REMIND_MS / 2;
    firc_logrep_fail_for(&r, d, NULL, "x");
    firc_event_t out[4];
    size_t n = journal(out, 4);
    quiet_end();
    ASSERT_EQ_FMT((size_t)3, n, "%zu");
    ASSERT_EQ(FIRC_LOG_WARN, out[1].u.log.level);
    ASSERT_EQ(FIRC_LOG_ERROR, out[2].u.log.level);
    PASS();
}

/* Catches: a run said due between reminders (a line at every check), not due at its reminder or at its raise to ERROR, or a fresh tracker not due. */
TEST due_follows_the_reminder_and_the_raise(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    bool fresh = firc_logrep_due(&r, UINT64_MAX);
    firc_logrep_fail(&r, FIRC_LOG_WARN, NULL, "x");
    g_now += 60000;
    bool between = firc_logrep_due(&r, UINT64_MAX);
    bool raise = firc_logrep_due(&r, 60000);
    g_now += FIRC_LOGREP_REMIND_MS - 60000;
    bool remind = firc_logrep_due(&r, UINT64_MAX);
    quiet_end();
    ASSERT(fresh);
    ASSERT_FALSE(between);
    ASSERT(raise);
    ASSERT(remind);
    PASS();
}

/* Catches: a quiet run that writes a DEBUG line per repeat, or that stops counting the repeats it does not say. */
TEST a_quiet_run_says_no_repeat_but_counts_it(void) {
    quiet_begin();
    firc_logrep_t r = {0};
    firc_logrep_fail_for_quiet(&r, UINT64_MAX, NULL, "x");
    firc_logrep_fail_for_quiet(&r, UINT64_MAX, NULL, "x");
    firc_logrep_fail_for_quiet(&r, UINT64_MAX, NULL, "x");
    g_now += FIRC_LOGREP_REMIND_MS;
    firc_logrep_fail_for_quiet(&r, UINT64_MAX, NULL, "x");
    firc_event_t out[8];
    size_t n = journal(out, 8);
    quiet_end();
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT_EQ(FIRC_LOG_WARN, out[1].u.log.level);
    ASSERT_STR_EQ("x (still failing, 4 times for 10 min)", out[1].u.log.text);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_repeat_is_debug_until_ten_minutes_pass);
    RUN_TEST(the_next_reminder_waits_another_ten_minutes);
    RUN_TEST(recovery_is_said_once_and_starts_over);
    RUN_TEST(a_rated_line_is_said_once_per_interval_with_the_count);
    RUN_TEST(a_failure_that_lasts_is_raised_to_error_once);
    RUN_TEST(a_zero_duration_is_an_error_at_once_and_a_reset_is_silent);
    RUN_TEST(a_long_duration_is_counted_from_the_first_failure);
    RUN_TEST(due_follows_the_reminder_and_the_raise);
    RUN_TEST(a_quiet_run_says_no_repeat_but_counts_it);
    GREATEST_MAIN_END();
}

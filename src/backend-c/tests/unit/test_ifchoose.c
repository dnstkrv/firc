#include "greatest.h"

#include <string.h>

#include "firc/ifchoose.h"

static firc_if_track_t A, B, C;
static const firc_if_track_t *const L2[] = {&A, &B};
static const firc_if_track_t *const L3[] = {&A, &B, &C};

static void all_alive_at(int64_t t) {
    firc_if_track_init(&A, 0);
    firc_if_track_init(&B, 0);
    firc_if_track_init(&C, 0);
    firc_if_track_check(&A, true, false, NULL, t);
    firc_if_track_check(&B, true, false, NULL, t);
    firc_if_track_check(&C, true, false, NULL, t);
}

TEST a_single_failure_asks_for_a_confirm_and_moves_nothing(void) {
    all_alive_at(0);
    ASSERT_EQ(FIRC_IF_CONFIRM, firc_if_track_check(&A, false, false, "timed out", 1000));
    ASSERT_EQ(FIRC_IF_ALIVE, A.state);
    ASSERT_EQ_FMT((size_t)0, firc_ifchoose(L2, 2, 0, 1000).active, "%zu");
    ASSERT_EQ(FIRC_IF_CHANGED, firc_if_track_check(&A, false, false, "timed out", 4000));
    ASSERT_EQ(FIRC_IF_DEAD, A.state);
    ASSERT_STR_EQ("timed out", A.error);
    firc_ifchoice_t c = firc_ifchoose(L2, 2, 0, 4000);
    ASSERT_EQ_FMT((size_t)1, c.active, "%zu");
    ASSERT_FALSE(c.all_dead);
    PASS();
}

TEST the_move_up_waits_120_s_of_unbroken_passes(void) {
    all_alive_at(0);
    firc_if_track_check(&A, false, false, "x", 1000);
    firc_if_track_check(&A, false, false, "x", 4000);
    ASSERT_EQ(FIRC_IF_CHANGED, firc_if_track_check(&A, true, false, NULL, 10000));
    ASSERT_EQ_FMT((size_t)1, firc_ifchoose(L2, 2, 1, 129999).active, "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_ifchoose(L2, 2, 1, 130000).active, "%zu");
    PASS();
}

TEST one_failed_check_inside_the_hold_restarts_it(void) {
    all_alive_at(0);
    firc_if_track_check(&A, false, false, "x", 1000);
    firc_if_track_check(&A, false, false, "x", 4000);
    firc_if_track_check(&A, true, false, NULL, 10000);
    ASSERT_EQ(FIRC_IF_CONFIRM, firc_if_track_check(&A, false, false, "x", 60000));
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_check(&A, true, false, NULL, 63000));
    ASSERT_EQ_FMT((size_t)1, firc_ifchoose(L2, 2, 1, 130000).active, "%zu");
    ASSERT_EQ_FMT((size_t)1, firc_ifchoose(L2, 2, 1, 182999).active, "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_ifchoose(L2, 2, 1, 183000).active, "%zu");
    PASS();
}

TEST a_move_down_takes_the_first_alive_entry_in_list_order(void) {
    all_alive_at(0);
    firc_if_track_link(&A, false, 500);
    ASSERT_EQ_FMT((size_t)1, firc_ifchoose(L3, 3, 0, 500).active, "%zu");
    firc_if_track_link(&B, false, 600);
    firc_if_track_check(&A, true, false, NULL, 700);
    firc_if_track_link(&C, false, 800);
    ASSERT_EQ_FMTm("a dead active entry takes an alive one above it without the hold", (size_t)0,
                   firc_ifchoose(L3, 3, 2, 800).active, "%zu");
    PASS();
}

TEST every_entry_dead_keeps_the_last_choice_and_says_so(void) {
    all_alive_at(0);
    firc_if_track_link(&A, false, 100);
    firc_if_track_link(&B, false, 100);
    firc_ifchoice_t c = firc_ifchoose(L2, 2, 1, 100);
    ASSERT(c.all_dead);
    ASSERT_EQ_FMT((size_t)1, c.active, "%zu");
    PASS();
}

TEST every_entry_unknown_keeps_the_first_and_an_unknown_above_moves_nothing(void) {
    firc_if_track_init(&A, 0);
    firc_if_track_init(&B, 0);
    firc_ifchoice_t c = firc_ifchoose(L2, 2, 0, 0);
    ASSERT_EQ_FMT((size_t)0, c.active, "%zu");
    ASSERT_FALSE(c.all_dead);
    firc_if_track_check(&B, true, false, NULL, 10);
    ASSERT_EQ_FMT((size_t)0, firc_ifchoose(L2, 2, 0, 500000).active, "%zu");
    firc_if_track_init(&A, 0);
    ASSERT_EQ_FMT((size_t)1, firc_ifchoose(L2, 2, 1, 500000).active, "%zu");
    PASS();
}

TEST a_dead_active_entry_falls_to_an_unknown_one_before_blocking(void) {
    firc_if_track_init(&A, 0);
    firc_if_track_init(&B, 0);
    firc_if_track_link(&A, false, 5);
    firc_ifchoice_t c = firc_ifchoose(L2, 2, 0, 5);
    ASSERT_EQ_FMT((size_t)1, c.active, "%zu");
    ASSERT_FALSE(c.all_dead);
    PASS();
}

TEST a_failed_control_changes_no_state(void) {
    all_alive_at(0);
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_check(&A, false, true, "no route to host", 1000));
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_check(&A, false, true, "no route to host", 4000));
    ASSERT_EQ(FIRC_IF_ALIVE, A.state);
    ASSERT_FALSE(A.suspect);
    firc_if_track_link(&B, false, 5000);
    ASSERT_EQm("a pass counts in a guarded round", FIRC_IF_CHANGED, firc_if_track_check(&B, true, true, NULL, 5100));
    PASS();
}

TEST link_down_and_tunnel_status_count_without_a_check(void) {
    all_alive_at(0);
    ASSERT_EQ(FIRC_IF_CHANGED, firc_if_track_link(&A, false, 10));
    ASSERT_EQ(FIRC_IF_DEAD, A.state);
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_link(&A, true, 20));
    ASSERT_EQ_FMTm("a link up alone is not alive", FIRC_IF_DEAD, A.state, "%d");
    ASSERT_EQ(FIRC_IF_CHANGED, firc_if_track_tunnel(&B, false, 30));
    ASSERT_EQ(FIRC_IF_DEAD, B.state);
    ASSERT_EQ(FIRC_IF_CHANGED, firc_if_track_tunnel(&B, true, 40));
    ASSERT_EQ(FIRC_IF_ALIVE, B.state);
    ASSERT_EQ_FMT(40LL, (long long)B.clean_since_ms, "%lld");
    PASS();
}

TEST the_button_needs_the_first_entry_alive(void) {
    all_alive_at(0);
    ASSERT(firc_ifchoose_first_alive(L2, 2));
    firc_if_track_link(&A, false, 1);
    ASSERT_FALSE(firc_ifchoose_first_alive(L2, 2));
    firc_if_track_init(&A, 2);
    ASSERT_FALSE(firc_ifchoose_first_alive(L2, 2));
    PASS();
}

TEST later_passes_do_not_restart_the_hold(void) {
    all_alive_at(0);
    firc_if_track_check(&A, true, false, NULL, 50000);
    firc_if_track_check(&A, true, false, NULL, 100000);
    ASSERT_EQ_FMT((size_t)0, firc_ifchoose(L2, 2, 1, 120000).active, "%zu");
    PASS();
}

TEST a_failure_on_a_dead_entry_asks_for_nothing(void) {
    all_alive_at(0);
    firc_if_track_link(&A, false, 10);
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_check(&A, false, false, "x", 20));
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_check(&A, false, false, "x", 30));
    PASS();
}

TEST a_dead_active_entry_prefers_an_alive_entry_over_an_unknown_one(void) {
    firc_if_track_init(&A, 0);
    firc_if_track_init(&B, 0);
    firc_if_track_init(&C, 0);
    firc_if_track_link(&A, false, 5);
    firc_if_track_check(&C, true, false, NULL, 6);
    ASSERT_EQ_FMT((size_t)2, firc_ifchoose(L3, 3, 0, 6).active, "%zu");
    PASS();
}

TEST a_pass_between_two_failures_clears_the_suspicion(void) {
    all_alive_at(0);
    ASSERT_EQ(FIRC_IF_CONFIRM, firc_if_track_check(&A, false, false, "x", 1000));
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_check(&A, true, false, NULL, 4000));
    ASSERT_EQ(FIRC_IF_CONFIRM, firc_if_track_check(&A, false, false, "x", 8000));
    ASSERT_EQ(FIRC_IF_ALIVE, A.state);
    PASS();
}

TEST a_repeated_tunnel_up_keeps_the_hold_running(void) {
    all_alive_at(0);
    firc_if_track_tunnel(&A, false, 1000);
    firc_if_track_tunnel(&A, true, 2000);
    ASSERT_EQ(FIRC_IF_KEEP, firc_if_track_tunnel(&A, true, 60000));
    ASSERT_EQ_FMT((size_t)1, firc_ifchoose(L2, 2, 1, 121999).active, "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_ifchoose(L2, 2, 1, 122000).active, "%zu");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_single_failure_asks_for_a_confirm_and_moves_nothing);
    RUN_TEST(the_move_up_waits_120_s_of_unbroken_passes);
    RUN_TEST(one_failed_check_inside_the_hold_restarts_it);
    RUN_TEST(a_move_down_takes_the_first_alive_entry_in_list_order);
    RUN_TEST(every_entry_dead_keeps_the_last_choice_and_says_so);
    RUN_TEST(every_entry_unknown_keeps_the_first_and_an_unknown_above_moves_nothing);
    RUN_TEST(a_dead_active_entry_falls_to_an_unknown_one_before_blocking);
    RUN_TEST(a_failed_control_changes_no_state);
    RUN_TEST(link_down_and_tunnel_status_count_without_a_check);
    RUN_TEST(the_button_needs_the_first_entry_alive);
    RUN_TEST(later_passes_do_not_restart_the_hold);
    RUN_TEST(a_failure_on_a_dead_entry_asks_for_nothing);
    RUN_TEST(a_dead_active_entry_prefers_an_alive_entry_over_an_unknown_one);
    RUN_TEST(a_pass_between_two_failures_clears_the_suspicion);
    RUN_TEST(a_repeated_tunnel_up_keeps_the_hold_running);
    GREATEST_MAIN_END();
}

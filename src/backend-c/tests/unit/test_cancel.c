#include "greatest.h"

#include "firc/cancel.h"

TEST starts_lowered(void) {
    firc_cancel_t *c = firc_cancel_new();
    ASSERT(c != NULL);
    ASSERT(!firc_cancel_raised(c));
    firc_cancel_free(c);
    PASS();
}

TEST raise_is_visible(void) {
    firc_cancel_t *c = firc_cancel_new();
    firc_cancel_raise(c);
    ASSERT(firc_cancel_raised(c));
    firc_cancel_free(c);
    PASS();
}

TEST clear_lowers(void) {
    firc_cancel_t *c = firc_cancel_new();
    firc_cancel_raise(c);
    firc_cancel_clear(c);
    ASSERT(!firc_cancel_raised(c));
    firc_cancel_free(c);
    PASS();
}

TEST reraise_after_clear(void) {
    firc_cancel_t *c = firc_cancel_new();
    firc_cancel_raise(c);
    firc_cancel_clear(c);
    firc_cancel_raise(c);
    ASSERT(firc_cancel_raised(c));
    firc_cancel_free(c);
    PASS();
}

TEST null_is_never_raised(void) {
    ASSERT(!firc_cancel_raised(NULL));
    firc_cancel_raise(NULL);
    firc_cancel_clear(NULL);
    firc_cancel_free(NULL);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(starts_lowered);
    RUN_TEST(raise_is_visible);
    RUN_TEST(clear_lowers);
    RUN_TEST(reraise_after_clear);
    RUN_TEST(null_is_never_raised);
    GREATEST_MAIN_END();
}

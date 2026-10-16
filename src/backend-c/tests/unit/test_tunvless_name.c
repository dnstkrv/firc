#include "greatest.h"

#include <stddef.h>

#include "firc/tunvless_name.h"

/* Catches: a non-canonical or out-of-range device given a port, or a canonical one refused. */
TEST only_a_canonical_tunvless_device_has_a_number(void) {
    ASSERT_EQ(0, firc_tunvless_index("tunvless0"));
    ASSERT_EQ(3, firc_tunvless_index("tunvless3"));
    ASSERT_EQ(42, firc_tunvless_index("tunvless42"));
    ASSERT_EQ(99, firc_tunvless_index("tunvless99"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless100"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless03"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless00"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless3a"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless-1"));
    ASSERT_EQ(-1, firc_tunvless_index("Tunvless3"));
    ASSERT_EQ(-1, firc_tunvless_index("eth0"));
    ASSERT_EQ(9, firc_tunvless_index("tunvless9"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless01"));
    ASSERT_EQ(-1, firc_tunvless_index(""));
    ASSERT_EQ(-1, firc_tunvless_index("tunvlessx"));
    ASSERT_EQ(-1, firc_tunvless_index(NULL));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(only_a_canonical_tunvless_device_has_a_number);
    GREATEST_MAIN_END();
}

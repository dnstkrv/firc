#include "greatest.h"

#include "firc/utf8.h"

/* Catches: a well-formed sequence of any length refused, or the edges of the code space cut short. */
TEST every_length_of_well_formed_utf8_is_valid(void) {
    ASSERT(firc_utf8_valid(""));
    ASSERT(firc_utf8_valid("plain ascii"));
    ASSERT(firc_utf8_valid("\xd1\x8f"));
    ASSERT(firc_utf8_valid("\xe2\x82\xac"));
    ASSERT(firc_utf8_valid("\xf0\x90\x8d\x88"));
    ASSERTm("U+0080, the first two-byte code point", firc_utf8_valid("\xc2\x80"));
    ASSERTm("U+0800, the first three-byte code point", firc_utf8_valid("\xe0\xa0\x80"));
    ASSERTm("U+D7FF, just below the surrogates", firc_utf8_valid("\xed\x9f\xbf"));
    ASSERTm("U+E000, just above them", firc_utf8_valid("\xee\x80\x80"));
    ASSERTm("U+10000, the first four-byte code point", firc_utf8_valid("\xf0\x90\x80\x80"));
    ASSERTm("U+10FFFF, the last code point", firc_utf8_valid("\xf4\x8f\xbf\xbf"));
    PASS();
}

/* Catches: a stray, truncated, overlong, surrogate or out-of-range sequence taken as UTF-8. */
TEST every_malformed_sequence_is_refused(void) {
    ASSERT_FALSEm("a continuation byte on its own", firc_utf8_valid("a\x80"));
    ASSERT_FALSEm("a lead byte cut off at the end", firc_utf8_valid("a\xd1"));
    ASSERT_FALSEm("a three-byte sequence cut short", firc_utf8_valid("\xe2\x82"));
    ASSERT_FALSEm("a lead byte followed by ASCII", firc_utf8_valid("\xd1z"));
    ASSERT_FALSEm("an overlong NUL", firc_utf8_valid("\xc0\x80"));
    ASSERT_FALSEm("an overlong two-byte form", firc_utf8_valid("\xc1\xbf"));
    ASSERT_FALSEm("U+07FF in three bytes", firc_utf8_valid("\xe0\x9f\xbf"));
    ASSERT_FALSEm("U+D800, a surrogate", firc_utf8_valid("\xed\xa0\x80"));
    ASSERT_FALSEm("U+DFFF, the last surrogate", firc_utf8_valid("\xed\xbf\xbf"));
    ASSERT_FALSEm("U+FFFF in four bytes", firc_utf8_valid("\xf0\x8f\xbf\xbf"));
    ASSERT_FALSEm("U+110000, past the code space", firc_utf8_valid("\xf4\x90\x80\x80"));
    ASSERT_FALSEm("a lead byte no code point has", firc_utf8_valid("\xf5\x80\x80\x80"));
    ASSERT_FALSE(firc_utf8_valid("\xff"));
    PASS();
}

/* Catches: a C0, DEL or C1 control character missed, or a printable byte taken for one. */
TEST control_characters_are_c0_del_and_c1(void) {
    ASSERT(firc_text_has_control("a\tb"));
    ASSERT(firc_text_has_control("a\nb"));
    ASSERT(firc_text_has_control("\x01"));
    ASSERT(firc_text_has_control("\x1f"));
    ASSERT(firc_text_has_control("a\x7f"));
    ASSERTm("U+0080", firc_text_has_control("\xc2\x80"));
    ASSERTm("U+009F", firc_text_has_control("a\xc2\x9f"));
    ASSERT_FALSE(firc_text_has_control(""));
    ASSERT_FALSE(firc_text_has_control(" ~"));
    ASSERT_FALSEm("U+00A0 is a space, not a control", firc_text_has_control("\xc2\xa0"));
    ASSERT_FALSEm("U+0440 ends in a byte in the C1 range", firc_text_has_control("\xd1\x80"));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(every_length_of_well_formed_utf8_is_valid);
    RUN_TEST(every_malformed_sequence_is_refused);
    RUN_TEST(control_characters_are_c0_del_and_c1);
    GREATEST_MAIN_END();
}

#include "unit.h"
#include "ratelog.h"

int main(void) {
    struct ratelog r = {0};
    unsigned held = 99;
    char buf[48];
    /* catches: the first line held back, or a held count that is not zero on the first */
    check("the first line is said", 1, ratelog_take(&r, 100, 10, &held));
    check("with nothing held", 0, (long)held);
    /* catches: a line said again before its interval */
    check("one second later: held", 0, ratelog_take(&r, 101, 10, &held));
    check("nine seconds later: held", 0, ratelog_take(&r, 109, 10, &held));
    /* catches: a line held past its interval, or the held ones not counted */
    check("ten seconds later: said", 1, ratelog_take(&r, 110, 10, &held));
    check("with the two held back", 2, (long)held);
    check_str("and says so", " (2 more since the last)", ratelog_more(buf, sizeof buf, held));
    /* catches: the count kept after it was said */
    check("a quiet interval later: said", 1, ratelog_take(&r, 200, 10, &held));
    check("with none held", 0, (long)held);
    check_str("and nothing added", "", ratelog_more(buf, sizeof buf, held));
    return unit_done("ratelogmatch");
}

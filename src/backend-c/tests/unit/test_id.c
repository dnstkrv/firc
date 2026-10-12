#include "greatest.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

#include "firc/id.h"
#include "firc/subparse.h"

static struct rlimit g_saved;

static bool no_more_fds(void) {
    if (getrlimit(RLIMIT_NOFILE, &g_saved) != 0) { return false; }
    int probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (probe < 0) { return false; }
    close(probe);
    struct rlimit low = {(rlim_t)probe, g_saved.rlim_max};
    if (setrlimit(RLIMIT_NOFILE, &low) != 0) { return false; }
    int again = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (again >= 0) {
        close(again);
        setrlimit(RLIMIT_NOFILE, &g_saved);
        return false;
    }
    return errno == EMFILE;
}

static void fds_again(void) { setrlimit(RLIMIT_NOFILE, &g_saved); }

/* Catches: an unreadable /dev/urandom handed out as the zero id instead of an error. */
TEST a_random_id_that_cannot_be_read_is_an_error(void) {
    firc_id_t id = {{1, 2, 3, 4}};
    ASSERT(no_more_fds());
    firc_err_t err = firc_id_random(&id);
    fds_again();
    ASSERT_EQ(FIRC_ERR_SYS, err);
    ASSERT_EQ(FIRC_OK, firc_id_random(&id));
    ASSERT_FALSE(firc_id_is_zero(id));
    PASS();
}

/* Catches: a pool that reads /dev/urandom per id, or one that hands out ids it never read. */
TEST a_pool_serves_256_ids_from_one_read(void) {
    firc_id_pool_t pool = {0};
    firc_id_t id;
    ASSERT_EQ(FIRC_OK, firc_id_pool_next(&pool, &id));
    ASSERT_FALSE(firc_id_is_zero(id));
    ASSERT(no_more_fds());
    int served = 1;
    firc_err_t err = FIRC_OK;
    while (served < 1000 && (err = firc_id_pool_next(&pool, &id)) == FIRC_OK) {
        served++;
        if (firc_id_is_zero(id)) { break; }
    }
    fds_again();
    ASSERT_FALSE(firc_id_is_zero(id));
    ASSERT_EQ(FIRC_ERR_SYS, err);
    ASSERT_EQ(256, served);
    PASS();
}

/* Catches: a list parsed with no randomness at hand coming back as rules that all share the zero id. */
TEST a_list_parsed_without_randomness_fails(void) {
    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT(no_more_fds());
    firc_err_t err = firc_sub_parse_rules("a.example\nb.example\n", &rules);
    fds_again();
    firc_sub_rules_free(&rules);
    ASSERT_EQ(FIRC_ERR_SYS, err);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_random_id_that_cannot_be_read_is_an_error);
    RUN_TEST(a_pool_serves_256_ids_from_one_read);
    RUN_TEST(a_list_parsed_without_randomness_fails);
    GREATEST_MAIN_END();
}

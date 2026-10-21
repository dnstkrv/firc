#include "greatest.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "firc/update_handoff.h"

#define FAKE "tests/unit/fixtures/fake_opkg.sh"
#define FAKE_BIN "tests/unit/fixtures/bin"
#define RECORDING_SH "tests/unit/fixtures/recording_sh.sh"
#define IPK "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk"
#define EPOCH ((int64_t)1791831000)
#define OPKG_SAID "Installing firc (0.3.0-1) to root...\nopkg: an error on stderr\n"

static char g_path[4096];

typedef struct {
    char base[64];
    char dir[96];
    char ipk[192];
    char marker[128];
    char result[128];
    char log[96];
    char hold[96];
    char daemon[96];
    char logger_log[96];
    char date_hold[96];
    char date_reached[128];
    char bin[96];
    char opkg[PATH_MAX];
    char fake_bin[PATH_MAX];
    char path[4096];
} env_t;

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool exists(const char *path) { return access(path, F_OK) == 0; }

static bool wait_for(const char *path, bool present, int ms) {
    for (int i = 0; i < ms / 10; i++) {
        if (exists(path) == present) { return true; }
        sleep_ms(10);
    }
    return exists(path) == present;
}

static bool read_text(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "r");
    if (f == NULL) { return false; }
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return true;
}

static void write_text(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (f == NULL) { return; }
    fputs(text, f);
    fclose(f);
}

static bool env_setup(env_t *e) {
    memset(e, 0, sizeof(*e));
    snprintf(e->base, sizeof(e->base), "/tmp/firc_handoff_XXXXXX");
    if (mkdtemp(e->base) == NULL) { return false; }
    snprintf(e->dir, sizeof(e->dir), "%s/update", e->base);
    snprintf(e->ipk, sizeof(e->ipk), "%s/%s", e->dir, IPK);
    snprintf(e->marker, sizeof(e->marker), "%s/installing", e->dir);
    snprintf(e->result, sizeof(e->result), "%s/result", e->dir);
    snprintf(e->log, sizeof(e->log), "%s/log", e->base);
    snprintf(e->hold, sizeof(e->hold), "%s/hold", e->base);
    snprintf(e->daemon, sizeof(e->daemon), "%s/daemon", e->base);
    snprintf(e->logger_log, sizeof(e->logger_log), "%s/logger", e->base);
    snprintf(e->date_hold, sizeof(e->date_hold), "%s/datehold", e->base);
    snprintf(e->date_reached, sizeof(e->date_reached), "%s.reached", e->date_hold);
    snprintf(e->bin, sizeof(e->bin), "%s/bin", e->base);
    char cwd[PATH_MAX - sizeof(FAKE) - 1];
    if (getcwd(cwd, sizeof(cwd)) == NULL) { return false; }
    snprintf(e->opkg, sizeof(e->opkg), "%s/%s", cwd, FAKE);
    snprintf(e->fake_bin, sizeof(e->fake_bin), "%s/%s", cwd, FAKE_BIN);
    snprintf(e->path, sizeof(e->path), "%s", g_path);
    if (setenv("PATH", e->path, 1) != 0) { return false; }
    if (mkdir(e->dir, 0700) != 0) { return false; }
    char body[1000];
    memset(body, 'x', sizeof(body));
    FILE *f = fopen(e->ipk, "w");
    if (f == NULL) { return false; }
    size_t n = fwrite(body, 1, sizeof(body), f);
    fclose(f);
    if (n != sizeof(body)) { return false; }
    unsetenv("FAKE_OPKG_HOLD");
    unsetenv("FAKE_OPKG_RC");
    unsetenv("FAKE_OPKG_DAEMON");
    unsetenv("FAKE_OPKG_KILL_PARENT");
    unsetenv("FAKE_DATE_HOLD");
    unsetenv("FAKE_OPKG_SAY");
    return setenv("FAKE_OPKG_LOG", e->log, 1) == 0 && setenv("FAKE_LOGGER_LOG", e->logger_log, 1) == 0;
}

static void env_teardown(const env_t *e) {
    char path[160];
    const char *names[] = {"result", "result.part", "installing", "opkg.log", IPK};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", e->dir, names[i]);
        unlink(path);
    }
    rmdir(e->dir);
    unlink(e->log);
    unlink(e->hold);
    unlink(e->daemon);
    unlink(e->logger_log);
    unlink(e->date_hold);
    unlink(e->date_reached);
    const char *tools[] = {"sed", "cut", "date", "mv", "rm", "cat", "wc", "sleep"};
    for (size_t i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", e->bin, tools[i]);
        unlink(path);
    }
    rmdir(e->bin);
    rmdir(e->base);
    setenv("PATH", e->path, 1);
    unsetenv("FAKE_LOGGER_LOG");
    unsetenv("FAKE_OPKG_KILL_PARENT");
    unsetenv("FAKE_DATE_HOLD");
    unsetenv("FAKE_OPKG_LOG");
    unsetenv("FAKE_OPKG_HOLD");
    unsetenv("FAKE_OPKG_RC");
    unsetenv("FAKE_OPKG_DAEMON");
}

static bool fake_bin_first(const env_t *e) {
    char path[sizeof(e->fake_bin) + sizeof(e->path) + 2];
    snprintf(path, sizeof(path), "%s:%s", e->fake_bin, e->path);
    return setenv("PATH", path, 1) == 0;
}

static bool bin_without_logger(const env_t *e) {
    if (mkdir(e->bin, 0700) != 0) { return false; }
    const char *tools[] = {"sed", "cut", "date", "mv", "rm", "cat", "wc", "sleep"};
    for (size_t i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) {
        char from[64], to[160];
        snprintf(from, sizeof(from), "/usr/bin/%s", tools[i]);
        if (access(from, X_OK) != 0) { snprintf(from, sizeof(from), "/bin/%s", tools[i]); }
        snprintf(to, sizeof(to), "%s/%s", e->bin, tools[i]);
        if (symlink(from, to) != 0) { return false; }
    }
    return setenv("PATH", e->bin, 1) == 0;
}

static bool field22(pid_t pid, uint64_t *out) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (!read_text(path, buf, sizeof(buf))) { return false; }
    const char *p = strrchr(buf, ')');
    if (p == NULL) { return false; }
    unsigned long long v = 0;
    if (sscanf(p + 1, " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu", &v) != 1) {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}

typedef struct {
    pid_t pid;
    int gate;
} child_t;

static bool child_start(child_t *c, const char *name) {
    int gate[2], ready[2];
    if (pipe(gate) != 0) { return false; }
    if (pipe(ready) != 0) { return false; }
    c->pid = fork();
    if (c->pid < 0) { return false; }
    if (c->pid == 0) {
        close(gate[1]);
        close(ready[0]);
        if (name != NULL) { prctl(PR_SET_NAME, name, 0, 0, 0); }
        if (write(ready[1], "r", 1) != 1) { _exit(1); }
        char ch;
        if (read(gate[0], &ch, 1) < 0) { _exit(1); }
        _exit(0);
    }
    close(gate[0]);
    close(ready[1]);
    char ch;
    bool ok = read(ready[0], &ch, 1) == 1;
    close(ready[0]);
    c->gate = gate[1];
    return ok;
}

static void child_end(const child_t *c) {
    close(c->gate);
    waitpid(c->pid, NULL, 0);
}

TEST the_installer_runs_under_the_given_shell(void) {
    /* Catches a fixed /bin/sh: on Keenetic it is a wrapper that drops every argument after the script. */
    env_t e;
    ASSERT(env_setup(&e));
    char cwd[PATH_MAX - sizeof(RECORDING_SH) - 1];
    ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
    char sh[PATH_MAX], log[128];
    snprintf(sh, sizeof(sh), "%s/%s", cwd, RECORDING_SH);
    snprintf(log, sizeof(log), "%s/sh", e.base);
    ASSERT_EQ(0, setenv("FAKE_SH_LOG", log, 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, sh, e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char text[128];
    ASSERT(read_text(log, text, sizeof(text)));
    ASSERT_STR_EQ("-c\n", text);
    ASSERT(read_text(e.result, text, sizeof(text)));
    ASSERT_EQ(0, strncmp(text, "0.3.0 0 ", 8));
    unsetenv("FAKE_SH_LOG");
    unlink(log);
    env_teardown(&e);
    PASS();
}

TEST the_result_carries_opkgs_exit_not_the_loggers(void) {
    /* Catches rc taken after the logger pipeline, which records 0 for every failed install. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT_EQ(0, setenv("FAKE_OPKG_RC", "7", 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char text[128];
    ASSERT(read_text(e.result, text, sizeof(text)));
    char version[64];
    int code = -1;
    long long finished = 0;
    char nl = 0;
    ASSERT_EQ(4, sscanf(text, "%63s %d %lld%c", version, &code, &finished, &nl));
    ASSERT_STR_EQ("0.3.0", version);
    ASSERT_EQ(7, code);
    ASSERT_EQ('\n', nl);
    ASSERT(llabs(finished - (long long)time(NULL)) <= 60);
    env_teardown(&e);
    PASS();
}

TEST opkg_gets_install_and_the_package_only(void) {
    /* Catches an added flag (--force-reinstall purges the pool) or a wrong package path. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char got[512], want[512];
    ASSERT(read_text(e.log, got, sizeof(got)));
    snprintf(want, sizeof(want), "install %s/%s 1000\n", e.dir, IPK);
    ASSERT_STR_EQ(want, got);
    env_teardown(&e);
    PASS();
}

TEST the_package_and_the_marker_are_gone_when_opkg_ends(void) {
    /* Catches a package left behind per update, or a marker that locks restarts forever. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    ASSERT(wait_for(e.ipk, false, 2000));
    ASSERT(wait_for(e.marker, false, 2000));
    env_teardown(&e);
    PASS();
}

TEST the_marker_names_the_live_installer_while_opkg_runs(void) {
    /* Catches the lock not holding across the hand-off: no pid line, a wrong field, or the marker gone early. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    char tag[64] = "";
    int64_t epoch = 0;
    firc_update_marker_t m = FIRC_UPDATE_MARKER_NONE;
    for (int i = 0; i < 500 && m != FIRC_UPDATE_MARKER_ALIVE; i++) {
        m = firc_update_marker_read(e.dir, tag, sizeof(tag), &epoch);
        if (m != FIRC_UPDATE_MARKER_ALIVE) { sleep_ms(10); }
    }
    ASSERT_EQ(FIRC_UPDATE_MARKER_ALIVE, m);
    ASSERT_STR_EQ("0.3.0", tag);
    ASSERT_EQ(EPOCH, epoch);
    ASSERT_FALSE(exists(e.result));
    write_text(e.hold, "go");
    ASSERT(wait_for(e.result, true, 5000));
    ASSERT(wait_for(e.marker, false, 2000));
    ASSERT_EQ(FIRC_UPDATE_MARKER_NONE, firc_update_marker_read(e.dir, NULL, 0, NULL));
    env_teardown(&e);
    PASS();
}

TEST a_marker_whose_installer_is_gone_is_stale(void) {
    /* Catches a dead or reused pid read as a live installer, or a marker still awaiting its pid line read as dead. */
    env_t e;
    ASSERT(env_setup(&e));
    char text[160], tag[64];
    int64_t epoch = 0;

    ASSERT_EQ(FIRC_UPDATE_MARKER_NONE, firc_update_marker_read(e.dir, tag, sizeof(tag), &epoch));

    child_t c;
    ASSERT(child_start(&c, NULL));
    uint64_t st = 0;
    ASSERT(field22(c.pid, &st));
    snprintf(text, sizeof(text), "0.3.0 1791831000\n%ld %" PRIu64 "\n", (long)c.pid, st);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_ALIVE, firc_update_marker_read(e.dir, NULL, 0, NULL));
    child_end(&c);
    ASSERT_EQ(FIRC_UPDATE_MARKER_STALE, firc_update_marker_read(e.dir, tag, sizeof(tag), &epoch));
    ASSERT_STR_EQ("0.3.0", tag);
    ASSERT_EQ(EPOCH, epoch);

    ASSERT(field22(getpid(), &st));
    snprintf(text, sizeof(text), "0.3.0 1791831000\n%ld %" PRIu64 "\n", (long)getpid(), st);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_ALIVE, firc_update_marker_read(e.dir, NULL, 0, NULL));
    snprintf(text, sizeof(text), "0.3.0 1791831000\n%ld %" PRIu64 "\n", (long)getpid(), st + 1);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_STALE, firc_update_marker_read(e.dir, NULL, 0, NULL));

    write_text(e.marker, "0.3.0 1791831000\n");
    ASSERT_EQ(FIRC_UPDATE_MARKER_NO_PID, firc_update_marker_read(e.dir, tag, sizeof(tag), &epoch));
    ASSERT_STR_EQ("0.3.0", tag);
    ASSERT_EQ(EPOCH, epoch);

    snprintf(text, sizeof(text), "0.3.0 1791831000\n%ld %" PRIu64, (long)getpid(), st);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_NO_PID, firc_update_marker_read(e.dir, NULL, 0, NULL));

    uint64_t init_st = 0;
    ASSERT(field22(1, &init_st));
    snprintf(text, sizeof(text), "0.3.0 1791831000\n1 %" PRIu64 "\n", init_st);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_ALIVE, firc_update_marker_read(e.dir, NULL, 0, NULL));
    snprintf(text, sizeof(text), "0.3.0 1791831000\n4294967297 %" PRIu64 "\n", init_st);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_STALE, firc_update_marker_read(e.dir, NULL, 0, NULL));

    snprintf(text, sizeof(text), "0.3.0 10000000000000000000\n%ld %" PRIu64 "\n", (long)getpid(), st);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_STALE, firc_update_marker_read(e.dir, NULL, 0, NULL));

    snprintf(text, sizeof(text), "0.3.0 1791831000\n%ld\n", (long)getpid());
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_STALE, firc_update_marker_read(e.dir, NULL, 0, NULL));

    snprintf(text, sizeof(text), "0.3.0\n%ld %" PRIu64 "\n", (long)getpid(), st);
    write_text(e.marker, text);
    ASSERT_EQ(FIRC_UPDATE_MARKER_STALE, firc_update_marker_read(e.dir, NULL, 0, NULL));

    unlink(e.marker);
    ASSERT_EQ(FIRC_UPDATE_MARKER_NONE, firc_update_marker_read(e.dir, NULL, 0, NULL));
    env_teardown(&e);
    PASS();
}

TEST a_new_hand_off_clears_the_last_result(void) {
    /* Catches the last install's result served as this one's while opkg still runs. */
    env_t e;
    ASSERT(env_setup(&e));
    write_text(e.result, "0.2.0 0 1700000000\n");
    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT_FALSE(exists(e.result));
    write_text(e.hold, "go");
    ASSERT(wait_for(e.result, true, 5000));
    firc_update_result_t r;
    ASSERT(firc_update_result_read(e.dir, &r));
    ASSERT_STR_EQ("0.3.0", r.version);
    env_teardown(&e);
    PASS();
}

TEST a_hand_off_into_a_missing_directory_is_an_io_error(void) {
    /* Catches success reported without a marker to lock the install. */
    env_t e;
    ASSERT(env_setup(&e));
    char missing[128];
    snprintf(missing, sizeof(missing), "%s/missing", e.base);
    ASSERT_EQ(FIRC_ERR_IO, firc_update_handoff(missing, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    env_teardown(&e);
    PASS();
}

TEST a_result_that_cannot_be_removed_starts_nothing(void) {
    /* Catches a hand-off that ignores a result it could not clear and leaves it to be read as this install's. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT_EQ(0, mkdir(e.result, 0700));
    ASSERT_EQ(FIRC_ERR_IO, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    sleep_ms(300);
    ASSERT_FALSE(exists(e.marker));
    ASSERT_FALSE(exists(e.log));
    rmdir(e.result);
    env_teardown(&e);
    PASS();
}

TEST a_shell_that_cannot_start_leaves_no_marker(void) {
    /* Catches a marker left behind by a failed spawn, which would hold the lock with no installer. */
    env_t e;
    ASSERT(env_setup(&e));
    pid_t pid = fork();
    ASSERT(pid >= 0);
    if (pid == 0) {
        struct rlimit rl = {0, 0};
        if (setrlimit(RLIMIT_NPROC, &rl) != 0) { _exit(2); }
        pid_t probe = fork();
        if (probe == 0) { _exit(0); }
        if (probe > 0) {
            waitpid(probe, NULL, 0);
            _exit(2);
        }
        _exit(firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH) == FIRC_OK ? 1 : 0);
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT(WIFEXITED(status));
    if (WEXITSTATUS(status) == 2) {
        env_teardown(&e);
        SKIPm("fork is not limited for this user");
    }
    ASSERT_EQ(0, WEXITSTATUS(status));
    ASSERT_FALSE(exists(e.marker));
    ASSERT(exists(e.ipk));
    env_teardown(&e);
    PASS();
}

TEST a_daemon_the_package_starts_does_not_hold_the_result(void) {
    /* Catches opkg inheriting the status descriptor: the daemon postinst starts keeps it, and no result ever lands. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT_EQ(0, setenv("FAKE_OPKG_DAEMON", e.daemon, 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    bool landed = wait_for(e.result, true, 5000);
    char text[32] = "";
    if (wait_for(e.daemon, true, 2000) && read_text(e.daemon, text, sizeof(text))) {
        long d = strtol(text, NULL, 10);
        if (d > 0) { kill((pid_t)d, SIGKILL); }
    }
    ASSERT(landed);
    ASSERT(wait_for(e.marker, false, 2000));
    env_teardown(&e);
    PASS();
}

TEST opkgs_output_reaches_logger_under_its_tag(void) {
    /* Catches opkg's output or errors kept out of the system log: logger dropped, stderr not joined, or another tag. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(fake_bin_first(&e));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char got[256];
    ASSERT(read_text(e.logger_log, got, sizeof(got)));
    ASSERT_STR_EQ("-t firc-update\nInstalling firc (0.3.0-1) to root...\nopkg: an error on stderr\n", got);
    env_teardown(&e);
    PASS();
}

TEST what_logger_prints_stays_out_of_the_result(void) {
    /* Catches logger's stdout captured with opkg's exit, which makes a finished install's result unreadable. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(fake_bin_first(&e));
    ASSERT_EQ(0, setenv("FAKE_OPKG_RC", "7", 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    firc_update_result_t r;
    ASSERT(firc_update_result_read(e.dir, &r));
    ASSERT_EQ(7, r.opkg_exit);
    env_teardown(&e);
    PASS();
}

TEST without_logger_opkg_still_runs_to_its_exit(void) {
    /* Catches a missing logger closing the pipe, so opkg dies of SIGPIPE mid-install. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(bin_without_logger(&e));
    ASSERT_EQ(0, setenv("FAKE_OPKG_RC", "7", 1));
    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    sleep_ms(300);
    write_text(e.hold, "go");
    ASSERT(wait_for(e.result, true, 5000));
    firc_update_result_t r;
    ASSERT(firc_update_result_read(e.dir, &r));
    ASSERT_EQ(7, r.opkg_exit);
    env_teardown(&e);
    PASS();
}

TEST an_installer_cut_off_before_its_status_records_255(void) {
    /* Catches an empty status read as success when the side running opkg dies before reporting. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT_EQ(0, setenv("FAKE_OPKG_KILL_PARENT", "1", 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    firc_update_result_t r;
    ASSERT(firc_update_result_read(e.dir, &r));
    ASSERT_EQ(255, r.opkg_exit);
    env_teardown(&e);
    PASS();
}

TEST the_marker_stays_until_the_result_is_written(void) {
    /* Catches the marker removed before the result, a gap a reader settles as a failed install. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(fake_bin_first(&e));
    ASSERT_EQ(0, setenv("FAKE_DATE_HOLD", e.date_hold, 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.date_reached, true, 5000));
    ASSERT(exists(e.marker));
    ASSERT_FALSE(exists(e.result));
    write_text(e.date_hold, "go");
    ASSERT(wait_for(e.result, true, 5000));
    ASSERT(wait_for(e.marker, false, 2000));
    env_teardown(&e);
    PASS();
}

TEST result_lines_are_read_strictly(void) {
    /* Catches a half-written or foreign result taken for opkg's verdict. */
    env_t e;
    ASSERT(env_setup(&e));
    firc_update_result_t r;
    ASSERT_FALSE(firc_update_result_read(e.dir, &r));
    write_text(e.result, "0.3.0 0 1791831000\n");
    ASSERT(firc_update_result_read(e.dir, &r));
    ASSERT_STR_EQ("0.3.0", r.version);
    ASSERT_EQ(0, r.opkg_exit);
    ASSERT_EQ(EPOCH, r.finished_at);
    write_text(e.result, "0.3.0 255 1791831000\n");
    ASSERT(firc_update_result_read(e.dir, &r));
    ASSERT_EQ(255, r.opkg_exit);
    const char *bad[] = {"0.3.0 x 1\n", "", "0.3.0 0", "0.3.0 0\n", "0.3.0 0 1791831000", "0.3.0 0 1791831000\nx",
                         "0.3.0 256 1791831000\n", "0.3.0  0 1791831000\n", " 0 1791831000\n",
                         "0.3.0 0 99999999999999999999\n", "0.3.0 0 \n",
                         "0.3.0 0 10000000000000000000\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        write_text(e.result, bad[i]);
        ASSERT_FALSEm(bad[i], firc_update_result_read(e.dir, &r));
    }
    env_teardown(&e);
    PASS();
}

TEST opkgs_output_is_kept_beside_the_result(void) {
    /* Catches opkg's output not kept, or stderr left out of it. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(fake_bin_first(&e));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char got[256];
    ASSERT_EQ(strlen(OPKG_SAID), firc_update_log_read(e.dir, got, sizeof(got)));
    ASSERT_STR_EQ(OPKG_SAID, got);
    env_teardown(&e);
    PASS();
}

TEST without_logger_opkgs_output_is_still_kept(void) {
    /* Catches the kept output lost when logger is missing. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(bin_without_logger(&e));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char got[256];
    firc_update_log_read(e.dir, got, sizeof(got));
    ASSERT_STR_EQ(OPKG_SAID, got);
    env_teardown(&e);
    PASS();
}

TEST opkgs_output_is_kept_byte_for_byte(void) {
    /* Catches read without -r, printf with the line as its format, or a last line without a newline dropped. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(fake_bin_first(&e));
    ASSERT_EQ(0, setenv("FAKE_OPKG_SAY", "-n 100%s \\x\n  indented\nlast", 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char got[256];
    firc_update_log_read(e.dir, got, sizeof(got));
    ASSERT_STR_EQ("-n 100%s \\x\n  indented\nlast\n", got);
    env_teardown(&e);
    PASS();
}

TEST a_new_hand_off_starts_a_new_log(void) {
    /* Catches the last install's output shown as this one's. */
    env_t e;
    ASSERT(env_setup(&e));
    ASSERT(fake_bin_first(&e));
    char path[160];
    snprintf(path, sizeof(path), "%s/opkg.log", e.dir);
    write_text(path, "the last install said this\n");
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", EPOCH));
    ASSERT(wait_for(e.result, true, 5000));
    char got[256];
    firc_update_log_read(e.dir, got, sizeof(got));
    ASSERT_STR_EQ(OPKG_SAID, got);
    env_teardown(&e);
    PASS();
}

TEST the_log_is_read_from_its_tail_at_a_line_start(void) {
    /* Catches the head kept instead of the tail, a line served cut in half, or a whole first line dropped. */
    env_t e;
    ASSERT(env_setup(&e));
    char got[16];
    ASSERT_EQ(0, firc_update_log_read(e.dir, got, sizeof(got)));
    ASSERT_STR_EQ("", got);
    char path[160];
    snprintf(path, sizeof(path), "%s/opkg.log", e.dir);
    write_text(path, "first line\nsecond\nthird\n");
    ASSERT_EQ(13, firc_update_log_read(e.dir, got, sizeof(got)));
    ASSERT_STR_EQ("second\nthird\n", got);
    write_text(path, "short\nlast");
    ASSERT_EQ(10, firc_update_log_read(e.dir, got, sizeof(got)));
    ASSERT_STR_EQ("short\nlast", got);
    write_text(path, "0123456789\nabcdefghijklmn\n");
    ASSERT_EQ(15, firc_update_log_read(e.dir, got, sizeof(got)));
    ASSERT_STR_EQ("abcdefghijklmn\n", got);
    write_text(path, "one line much longer than the buffer");
    ASSERT_EQ(0, firc_update_log_read(e.dir, got, sizeof(got)));
    ASSERT_STR_EQ("", got);
    env_teardown(&e);
    PASS();
}

TEST proc_starttime_reads_field_22(void) {
    /* Catches a wrong field, or a split at the first ")" of a name that holds one. */
    uint64_t want = 0, got = 0;
    ASSERT(field22(getpid(), &want));
    ASSERT(firc_proc_starttime(getpid(), &got));
    ASSERT_EQ(want, got);

    child_t c;
    ASSERT(child_start(&c, "a) 1 2 3 4 5 6"));
    ASSERT(field22(c.pid, &want));
    ASSERT(firc_proc_starttime(c.pid, &got));
    ASSERT_EQ(want, got);
    pid_t gone = c.pid;
    child_end(&c);
    ASSERT_FALSE(firc_proc_starttime(gone, &got));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    const char *path = getenv("PATH");
    snprintf(g_path, sizeof(g_path), "%s", path != NULL ? path : "/usr/bin:/bin");
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_installer_runs_under_the_given_shell);
    RUN_TEST(the_result_carries_opkgs_exit_not_the_loggers);
    RUN_TEST(opkg_gets_install_and_the_package_only);
    RUN_TEST(the_package_and_the_marker_are_gone_when_opkg_ends);
    RUN_TEST(the_marker_names_the_live_installer_while_opkg_runs);
    RUN_TEST(a_marker_whose_installer_is_gone_is_stale);
    RUN_TEST(a_new_hand_off_clears_the_last_result);
    RUN_TEST(a_hand_off_into_a_missing_directory_is_an_io_error);
    RUN_TEST(a_result_that_cannot_be_removed_starts_nothing);
    RUN_TEST(a_shell_that_cannot_start_leaves_no_marker);
    RUN_TEST(a_daemon_the_package_starts_does_not_hold_the_result);
    RUN_TEST(opkgs_output_reaches_logger_under_its_tag);
    RUN_TEST(what_logger_prints_stays_out_of_the_result);
    RUN_TEST(without_logger_opkg_still_runs_to_its_exit);
    RUN_TEST(an_installer_cut_off_before_its_status_records_255);
    RUN_TEST(the_marker_stays_until_the_result_is_written);
    RUN_TEST(result_lines_are_read_strictly);
    RUN_TEST(opkgs_output_is_kept_beside_the_result);
    RUN_TEST(without_logger_opkgs_output_is_still_kept);
    RUN_TEST(opkgs_output_is_kept_byte_for_byte);
    RUN_TEST(a_new_hand_off_starts_a_new_log);
    RUN_TEST(the_log_is_read_from_its_tail_at_a_line_start);
    RUN_TEST(proc_starttime_reads_field_22);
    GREATEST_MAIN_END();
}

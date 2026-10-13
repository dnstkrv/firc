#include "greatest.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "firc/httpd.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/release.h"
#include "firc/sub_fetch.h"
#include "firc/update.h"
#include "firc/update_handoff.h"

#define HOUR_MS ((int64_t)3600 * 1000)

enum mode { M_FIXTURE, M_LIMITED, M_FORBIDDEN, M_RETRY, M_NONE, M_BIG, M_BAD_GATEWAY, M_HOLD, M_NEVER, M_INSTALL,
            M_NO_DIGEST, M_HUGE_ERROR };

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_hits;
static enum mode g_mode;
static char g_accept[128];
static char g_agent[128];
static char *g_fixture;
static size_t g_fixture_len;
static char *g_big;
static size_t g_big_len;
static firc_http_deferred_t *g_held;
static char g_install_json[2048];
static char g_no_digest_json[2048];

typedef struct {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
    uint16_t port;
} server_t;

static server_t *g_srv;
static char g_api[64];

static void on_held_close(void *ud) {
    (void)ud;
    firc_http_deferred_drop(g_held);
    g_held = NULL;
}

static void h_latest(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_mu);
    g_hits++;
    enum mode m = g_mode;
    const char *a = firc_http_req_header(req, "Accept");
    const char *ua = firc_http_req_header(req, "User-Agent");
    snprintf(g_accept, sizeof g_accept, "%s", a != NULL ? a : "");
    snprintf(g_agent, sizeof g_agent, "%s", ua != NULL ? ua : "");
    pthread_mutex_unlock(&g_mu);
    switch (m) {
    case M_FIXTURE:
        firc_http_res_write(res, 200, "application/json", (const uint8_t *)g_fixture, g_fixture_len);
        break;
    case M_LIMITED:
        firc_http_res_set_header(res, "X-RateLimit-Remaining", "0");
        firc_http_res_set_header(res, "X-RateLimit-Reset", "1791831689");
        firc_http_res_write(res, 403, "application/json", (const uint8_t *)"{}", 2);
        break;
    case M_FORBIDDEN:
        firc_http_res_write(res, 403, "application/json", (const uint8_t *)"{}", 2);
        break;
    case M_RETRY:
        firc_http_res_set_header(res, "Retry-After", "60");
        firc_http_res_write(res, 429, "application/json", (const uint8_t *)"{}", 2);
        break;
    case M_NONE:
        firc_http_res_write(res, 404, "application/json", (const uint8_t *)"{}", 2);
        break;
    case M_BIG:
        firc_http_res_write(res, 200, "application/json", (const uint8_t *)g_big, g_big_len);
        break;
    case M_BAD_GATEWAY:
        firc_http_res_write(res, 502, "text/plain", (const uint8_t *)"bad", 3);
        break;
    case M_HUGE_ERROR: {
        size_t n = FIRC_SUB_FETCH_MAX_BODY_BYTES + 1;
        uint8_t *body = calloc(1, n);
        if (body != NULL) { memset(body, 'x', n); }
        firc_http_res_write(res, 502, "text/plain", body, body != NULL ? n : 0);
        free(body);
        break;
    }
    case M_INSTALL:
        firc_http_res_write(res, 200, "application/json", (const uint8_t *)g_install_json, strlen(g_install_json));
        break;
    case M_NO_DIGEST:
        firc_http_res_write(res, 200, "application/json", (const uint8_t *)g_no_digest_json,
                            strlen(g_no_digest_json));
        break;
    case M_HOLD:
    case M_NEVER:
        g_held = firc_http_res_defer(res, on_held_close, NULL);
        break;
    }
}

static void release_held(firc_loop_t *loop, void *ud) {
    (void)loop;
    (void)ud;
    if (g_held == NULL) { return; }
    char *body = malloc(g_fixture_len);
    if (body != NULL) { memcpy(body, g_fixture, g_fixture_len); }
    firc_http_deferred_finish(g_held, 200, "application/json", (uint8_t *)body, body != NULL ? g_fixture_len : 0);
    g_held = NULL;
}

static void *server_thread(void *ud) {
    firc_loop_run(((server_t *)ud)->loop);
    return NULL;
}

static uint16_t free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return 0; }
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof sa;
    uint16_t port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0 && getsockname(fd, (struct sockaddr *)&sa, &sl) == 0) {
        port = ntohs(sa.sin_port);
    }
    close(fd);
    return port;
}

static bool server_start(void) {
    server_t *s = calloc(1, sizeof *s);
    if (s == NULL || firc_loop_create(&s->loop) != FIRC_OK || firc_httpd_create(s->loop, &s->srv) != FIRC_OK) {
        return false;
    }
    firc_httpd_route(s->srv, "GET", "/repos/hoaxisr/firc/releases/latest", h_latest, NULL);
    bool up = false;
    for (int i = 0; i < 16 && !up; i++) {
        s->port = free_port();
        up = s->port != 0 && firc_httpd_listen_tcp(s->srv, "127.0.0.1", s->port) == FIRC_OK;
    }
    if (!up) { return false; }
    snprintf(g_api, sizeof g_api, "http://127.0.0.1:%u/repos/hoaxisr/firc/releases/latest", (unsigned)s->port);
    pthread_create(&s->thread, NULL, server_thread, s);
    g_srv = s;
    return true;
}

static void server_stop(void) {
    if (g_srv == NULL) { return; }
    firc_loop_stop(g_srv->loop);
    pthread_join(g_srv->thread, NULL);
    firc_httpd_destroy(g_srv->srv);
    firc_loop_destroy(g_srv->loop);
    free(g_srv);
    g_srv = NULL;
    g_held = NULL;
}

static int hits(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_hits;
    pthread_mutex_unlock(&g_mu);
    return n;
}

static void set_mode(enum mode m) {
    pthread_mutex_lock(&g_mu);
    g_mode = m;
    pthread_mutex_unlock(&g_mu);
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool loopback_ok(void *ud, const char *url) {
    (void)ud;
    return strncmp(url, "http://127.0.0.1:", 17) == 0;
}

typedef struct {
    firc_loop_t *loop;
    firc_update_t *u;
    int checked;
    firc_update_outcome_t last;
} fx_t;

static fx_t *g_fx;

static void on_checked(void *ud, const firc_update_outcome_t *o) {
    fx_t *f = ud;
    f->checked++;
    f->last = *o;
}

static bool fx_up_as(fx_t *f, const char *version, const char *target) {
    memset(f, 0, sizeof *f);
    g_fx = f;
    if (firc_loop_create(&f->loop) != FIRC_OK) { return false; }
    firc_update_deps_t d = {
        .loop = f->loop,
        .dir = "/nonexistent/update",
        .api_url = g_api,
        .download_prefix = FIRC_UPDATE_DOWNLOAD_PREFIX,
        .version = version,
        .target = target,
        .revision = 1,
        .url_ok = loopback_ok,
        .checked = on_checked,
        .ud = f,
    };
    f->u = firc_update_new(&d);
    return f->u != NULL && firc_update_start(f->u) == FIRC_OK;
}

static bool fx_up(fx_t *f) { return fx_up_as(f, "0.1.3", "mipsel-3.4_kn"); }

static void fx_down(fx_t *f) {
    firc_update_free(f->u);
    f->u = NULL;
    if (f->loop != NULL) {
        firc_loop_destroy(f->loop);
        f->loop = NULL;
    }
    g_fx = NULL;
}

typedef struct {
    fx_t *f;
    int want;
    int64_t deadline;
    bool ok;
} wait_t;

static void wait_cb(firc_loop_t *loop, void *ud) {
    wait_t *w = ud;
    w->ok = w->want >= 0 && w->f->checked >= w->want;
    if (w->ok || mono_ms() >= w->deadline) { firc_loop_stop(loop); }
}

static bool run_until_checked(fx_t *f, int want, int ms) {
    wait_t w = {f, want, mono_ms() + ms, false};
    int timer = 0;
    firc_loop_add_timer(f->loop, 10, 10, wait_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return w.ok;
}

static void idle(fx_t *f, int ms) { (void)run_until_checked(f, -1, ms); }

static bool hits_reach(int n, int ms) {
    int64_t end = mono_ms() + ms;
    while (hits() < n && mono_ms() < end) {
        struct timespec ts = {0, 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return hits() >= n;
}

static void reset(void) {
    pthread_mutex_lock(&g_mu);
    g_hits = 0;
    g_mode = M_FIXTURE;
    g_accept[0] = 0;
    g_agent[0] = 0;
    pthread_mutex_unlock(&g_mu);
}

static void setup(void *ud) {
    (void)ud;
    reset();
    if (g_srv == NULL) { (void)server_start(); }
}

typedef struct ienv ienv_t;
static ienv_t *g_env;
static void env_down(ienv_t *e);

static void teardown(void *ud) {
    (void)ud;
    if (g_fx != NULL) { fx_down(g_fx); }
    if (g_env != NULL) { env_down(g_env); }
    server_stop();
}

static bool check_once(fx_t *f) {
    int before = f->checked;
    return firc_update_check(f->u) == FIRC_OK && run_until_checked(f, before + 1, 5000);
}

static bool newer_for(const char *version, bool *newer) {
    static fx_t f;
    bool ok = fx_up_as(&f, version, "mipsel-3.4_kn") && check_once(&f);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    *newer = v.newer;
    ok = ok && v.latest != NULL;
    fx_down(&f);
    return ok;
}

static const char *reason_for(const char *version, const char *target) {
    static fx_t f;
    const char *r = "unbuilt";
    if (fx_up_as(&f, version, target)) {
        firc_update_view_t v;
        firc_update_view(f.u, &v);
        r = v.cannot_install;
    }
    fx_down(&f);
    return r;
}

/* Catches a check that never reports newer, never returns to idle, or calls back twice. */
TEST a_check_finds_the_newer_release(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT_EQ(FIRC_OK, firc_update_check(f.u));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("checking", firc_update_state_name(v.state));
    ASSERT(run_until_checked(&f, 1, 5000));
    idle(&f, 200);
    ASSERT_EQ(1, f.checked);
    ASSERT_EQ(FIRC_OK, f.last.err);
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("idle", firc_update_state_name(v.state));
    ASSERT(v.attempted);
    ASSERT(v.check_error == NULL);
    ASSERT(v.latest != NULL);
    ASSERT_STR_EQ("0.2.0", v.latest->version_text);
    ASSERT(v.latest->installable);
    ASSERT(v.newer);
    ASSERT(v.cannot_install == NULL);
    ASSERT(v.age_s >= 0 && v.age_s <= 1);
    int64_t now = (int64_t)time(NULL);
    ASSERT(v.checked_at >= now - 5 && v.checked_at <= now);
    PASS();
}

/* Catches a check sent without GitHub's media type or with the compiled-in version instead of the running one. */
TEST the_check_asks_as_firc_for_github_json(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT(check_once(&f));
    pthread_mutex_lock(&g_mu);
    char accept[128];
    char agent[128];
    snprintf(accept, sizeof accept, "%s", g_accept);
    snprintf(agent, sizeof agent, "%s", g_agent);
    pthread_mutex_unlock(&g_mu);
    ASSERT_STR_EQ("application/vnd.github+json", accept);
    ASSERT_STR_EQ("firc/0.1.3", agent);
    PASS();
}

/* Catches a dev build ranked wrong, which would offer 0.2.0 to a newer branch build. */
TEST an_equal_or_older_release_is_not_newer(void) {
    bool newer = true;
    ASSERT(newer_for("0.2.0", &newer));
    ASSERT_FALSE(newer);
    newer = true;
    ASSERT(newer_for("0.2.1~git20261012.ad18642", &newer));
    ASSERT_FALSE(newer);
    newer = false;
    ASSERT(newer_for("0.2.0~git20261012.ad18642", &newer));
    ASSERT(newer);
    newer = true;
    ASSERT(newer_for("unattached", &newer));
    ASSERT_FALSE(newer);
    PASS();
}

/* Catches the reasons checked in the wrong order, or a dev build allowed to install. */
TEST why_this_build_cannot_install(void) {
    const char *r = reason_for("0.2.1~git20261012.ad18642", "");
    ASSERT(r != NULL);
    ASSERT_STR_EQ("no-target", r);
    r = reason_for("unattached", "mipsel-3.4_kn");
    ASSERT(r != NULL);
    ASSERT_STR_EQ("unknown-version", r);
    r = reason_for("0.2.1~git20261012.ad18642", "mipsel-3.4_kn");
    ASSERT(r != NULL);
    ASSERT_STR_EQ("dev-build", r);
    ASSERT(reason_for("0.1.3", "mipsel-3.4_kn") == NULL);
    PASS();
}

/* Catches the header dot vanishing after a neighbour used up the limit, or a rate limit reported as 502. */
TEST a_403_with_no_requests_left_is_a_rate_limit_and_keeps_the_last_release(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT(check_once(&f));
    set_mode(M_LIMITED);
    ASSERT(check_once(&f));
    ASSERT_EQ(FIRC_ERR_AGAIN, f.last.err);
    ASSERT_EQ(403, f.last.http_status);
    ASSERT_EQ(1791831689, f.last.reset_at);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.check_error != NULL);
    ASSERT_STR_EQ("GitHub refuses more checks from this address until 2026-10-12T19:01:29Z", v.check_error);
    ASSERT(v.latest != NULL);
    ASSERT_STR_EQ("0.2.0", v.latest->version_text);
    ASSERT(v.newer);
    PASS();
}

/* Catches an oversized error answer described as too many redirects. */
TEST an_oversized_error_answer_says_githubs_status(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    set_mode(M_HUGE_ERROR);
    ASSERT(check_once(&f));
    ASSERT_EQ(FIRC_ERR_UPSTREAM, f.last.err);
    ASSERT_STR_EQ("GitHub answered 502", f.last.message);
    PASS();
}

/* Catches every 403 called a rate limit. */
TEST a_403_without_rate_limit_headers_is_upstream(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    set_mode(M_FORBIDDEN);
    ASSERT(check_once(&f));
    ASSERT_EQ(FIRC_ERR_UPSTREAM, f.last.err);
    ASSERT_EQ(403, f.last.http_status);
    ASSERT_EQ(0, f.last.reset_at);
    ASSERT_STR_EQ("GitHub answered 403", f.last.message);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.check_error != NULL);
    ASSERT_STR_EQ("GitHub answered 403", v.check_error);
    ASSERT(v.latest == NULL);
    PASS();
}

/* Catches a 429 taken for an ordinary failure, or Retry-After ignored. */
TEST a_429_with_retry_after_is_a_rate_limit(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    set_mode(M_RETRY);
    int64_t before = (int64_t)time(NULL);
    ASSERT(check_once(&f));
    int64_t after = (int64_t)time(NULL);
    ASSERT_EQ(FIRC_ERR_AGAIN, f.last.err);
    ASSERT_EQ(429, f.last.http_status);
    ASSERT(f.last.reset_at >= before + 60 && f.last.reset_at <= after + 60);
    PASS();
}

/* Catches a repository without releases shown as a failed check. */
TEST no_release_at_all_is_not_an_error(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    set_mode(M_NONE);
    ASSERT(check_once(&f));
    ASSERT_EQ(FIRC_OK, f.last.err);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.attempted);
    ASSERT(v.latest == NULL);
    ASSERT(v.check_error == NULL);
    ASSERT_FALSE(v.newer);
    PASS();
}

/* Catches an unbounded answer in RAM. */
TEST a_body_over_256_kib_is_refused_and_keeps_the_last_release(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT(check_once(&f));
    set_mode(M_BIG);
    ASSERT(check_once(&f));
    ASSERT_EQ(FIRC_ERR_UPSTREAM, f.last.err);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.check_error != NULL);
    ASSERT(v.latest != NULL);
    ASSERT_STR_EQ("0.2.0", v.latest->version_text);
    ASSERT(v.newer);
    PASS();
}

/* Catches double fetches against the 60/h limit. */
TEST two_checks_at_once_cost_one_request(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    set_mode(M_HOLD);
    ASSERT_EQ(FIRC_OK, firc_update_check(f.u));
    ASSERT(hits_reach(1, 5000));
    ASSERT_EQ(FIRC_OK, firc_update_check(f.u));
    ASSERT_EQ(FIRC_OK, firc_loop_post(g_srv->loop, release_held, NULL));
    ASSERT(run_until_checked(&f, 1, 5000));
    idle(&f, 300);
    ASSERT_EQ(1, hits());
    ASSERT_EQ(1, f.checked);
    PASS();
}

/* Catches the setting ignored, or a strict 24 h on an hourly tick that lands at 25 h and drifts an hour a day. */
TEST the_daily_check_runs_only_when_on_and_a_day_has_passed(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    ASSERT(check_once(&f));
    int64_t now = mono_ms();
    firc_update_auto_check(f.u, false, now + 25 * HOUR_MS);
    idle(&f, 200);
    ASSERT_EQ(1, hits());
    firc_update_auto_check(f.u, true, now + 23 * HOUR_MS);
    idle(&f, 200);
    ASSERT_EQ(1, hits());
    firc_update_auto_check(f.u, true, now + 23 * HOUR_MS + HOUR_MS / 2);
    ASSERT(run_until_checked(&f, 2, 5000));
    ASSERT_EQ(2, hits());
    fx_down(&f);

    ASSERT(fx_up(&f));
    firc_update_auto_check(f.u, true, mono_ms());
    ASSERT(run_until_checked(&f, 1, 5000));
    ASSERT_EQ(3, hits());
    PASS();
}

/* Catches a failed attempt at boot + 10 min counted as the day's check, leaving the router blind for 24 h. */
TEST a_failed_daily_check_is_retried_at_the_next_tick(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    set_mode(M_BAD_GATEWAY);
    int64_t now = 10 * 60 * 1000;
    firc_update_auto_check(f.u, true, now);
    ASSERT(run_until_checked(&f, 1, 5000));
    ASSERT_EQ(1, hits());
    ASSERT_EQ(FIRC_ERR_UPSTREAM, f.last.err);
    set_mode(M_FIXTURE);
    firc_update_auto_check(f.u, true, now + HOUR_MS);
    ASSERT(run_until_checked(&f, 2, 5000));
    ASSERT_EQ(2, hits());
    ASSERT_EQ(FIRC_OK, f.last.err);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.check_error == NULL);
    ASSERT(v.latest != NULL);
    PASS();
}

/* Catches libcurl's reason replaced by a generic error, which would hide a wrong clock or a dead WAN. */
TEST an_unreachable_github_says_why_in_libcurls_words(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    firc_update_free(f.u);
    char closed[64];
    snprintf(closed, sizeof closed, "http://127.0.0.1:%u/repos/hoaxisr/firc/releases/latest", (unsigned)free_port());
    firc_update_deps_t d = {
        .loop = f.loop, .api_url = closed, .version = "0.1.3", .target = "mipsel-3.4_kn",
        .revision = 1, .url_ok = loopback_ok, .checked = on_checked, .ud = &f,
    };
    f.u = firc_update_new(&d);
    ASSERT(f.u != NULL);
    ASSERT_EQ(FIRC_OK, firc_update_start(f.u));
    ASSERT(check_once(&f));
    ASSERT_EQ(FIRC_ERR_UPSTREAM, f.last.err);
    ASSERT(strstr(f.last.message, "onnect") != NULL);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.check_error != NULL);
    ASSERT_STR_EQ(f.last.message, v.check_error);
    PASS();
}

/* Catches a join that waits out the 15 s transfer timeout during a daemon stop. */
TEST stopping_mid_check_returns_promptly(void) {
    static fx_t f;
    ASSERT(fx_up(&f));
    set_mode(M_NEVER);
    ASSERT_EQ(FIRC_OK, firc_update_check(f.u));
    ASSERT(hits_reach(1, 5000));
    int64_t t0 = mono_ms();
    firc_update_free(f.u);
    f.u = NULL;
    ASSERT(mono_ms() - t0 < 3000);
    PASS();
}

static char *read_file(const char *path, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) { return NULL; }
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = n >= 0 ? malloc((size_t)n + 1) : NULL;
    if (buf != NULL && fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(fp);
    if (buf != NULL) {
        buf[n] = 0;
        *len = (size_t)n;
    }
    return buf;
}

static bool build_big(void) {
    size_t pad = FIRC_RELEASE_JSON_MAX;
    g_big_len = g_fixture_len + pad + 16;
    g_big = malloc(g_big_len);
    if (g_big == NULL || g_fixture[0] != '{') { return false; }
    size_t k = 0;
    memcpy(g_big + k, "{\"pad\":\"", 8);
    k += 8;
    memset(g_big + k, 'x', pad);
    k += pad;
    memcpy(g_big + k, "\",", 2);
    k += 2;
    memcpy(g_big + k, g_fixture + 1, g_fixture_len - 1);
    k += g_fixture_len - 1;
    g_big_len = k;
    return true;
}

#define PAYLOAD_LEN 1000000
#define IPK_NAME "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk"
#define PAYLOAD_SHA "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
#define INTERRUPTED                                                                                                    \
    "the last install did not finish: its installer is gone and left no result; see logread and opkg status firc"
#define FAKE "tests/unit/fixtures/fake_opkg.sh"
#define FAKE_BIN "tests/unit/fixtures/bin"

enum dl_mode { DL_FULL, DL_SHORT, DL_FLIPPED, DL_LONGER, DL_TRICKLE, DL_HOLD, DL_MISSING };

static struct {
    pthread_mutex_t mu;
    pthread_t thread;
    int fd;
    bool stop;
    enum dl_mode mode;
    int hits;
    int phase;
    bool go;
    char accept[128];
} g_dl = {.mu = PTHREAD_MUTEX_INITIALIZER, .fd = -1};

static uint8_t *g_payload;
static uint8_t *g_flipped;
static char g_dl_prefix[96];
static char g_path[4096];

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool dl_stopping(void) {
    pthread_mutex_lock(&g_dl.mu);
    bool s = g_dl.stop;
    pthread_mutex_unlock(&g_dl.mu);
    return s;
}

static bool peer_gone(int c, int ms) {
    struct pollfd p = {.fd = c, .events = POLLIN};
    if (poll(&p, 1, ms) <= 0) { return false; }
    char ch;
    ssize_t n = recv(c, &ch, 1, MSG_PEEK | MSG_DONTWAIT);
    return n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
}

static bool hold_until_go(int c) {
    for (;;) {
        if (dl_stopping()) { return false; }
        pthread_mutex_lock(&g_dl.mu);
        bool go = g_dl.go;
        pthread_mutex_unlock(&g_dl.mu);
        if (go) { return true; }
        if (peer_gone(c, 20)) { return false; }
    }
}

static void hold_until_gone(int c) {
    while (!dl_stopping() && !peer_gone(c, 20)) {}
}

static bool send_all(int c, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = send(c, p, n, MSG_NOSIGNAL);
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            if (dl_stopping()) { return false; }
            continue;
        }
        if (w <= 0) { return false; }
        p += w;
        n -= (size_t)w;
    }
    return true;
}

static bool send_head(int c, int status, size_t len) {
    char h[160];
    int k = snprintf(h, sizeof h, "HTTP/1.1 %d %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", status,
                     status == 200 ? "OK" : "Not Found", len);
    return send_all(c, h, (size_t)k);
}

static bool read_request(int c) {
    char buf[2048];
    size_t n = 0;
    int64_t end = mono_ms() + 3000;
    while (n + 1 < sizeof buf && mono_ms() < end && !dl_stopping()) {
        struct pollfd p = {.fd = c, .events = POLLIN};
        if (poll(&p, 1, 20) <= 0) { continue; }
        ssize_t r = recv(c, buf + n, sizeof buf - 1 - n, 0);
        if (r <= 0) { return false; }
        n += (size_t)r;
        buf[n] = 0;
        if (strstr(buf, "\r\n\r\n") == NULL) { continue; }
        const char *a = strstr(buf, "\r\nAccept: ");
        pthread_mutex_lock(&g_dl.mu);
        g_dl.accept[0] = 0;
        if (a != NULL) {
            a += 10;
            size_t k = strcspn(a, "\r");
            snprintf(g_dl.accept, sizeof g_dl.accept, "%.*s", (int)k, a);
        }
        g_dl.hits++;
        pthread_mutex_unlock(&g_dl.mu);
        return true;
    }
    return false;
}

static void set_phase(int phase) {
    pthread_mutex_lock(&g_dl.mu);
    g_dl.phase = phase;
    pthread_mutex_unlock(&g_dl.mu);
}

static void dl_serve(int c) {
    if (!read_request(c)) { return; }
    pthread_mutex_lock(&g_dl.mu);
    enum dl_mode mode = g_dl.mode;
    pthread_mutex_unlock(&g_dl.mu);
    switch (mode) {
    case DL_FULL:
        if (send_head(c, 200, PAYLOAD_LEN)) { (void)send_all(c, g_payload, PAYLOAD_LEN); }
        break;
    case DL_SHORT:
        if (send_head(c, 200, PAYLOAD_LEN - 1)) { (void)send_all(c, g_payload, PAYLOAD_LEN - 1); }
        break;
    case DL_FLIPPED:
        if (send_head(c, 200, PAYLOAD_LEN)) { (void)send_all(c, g_flipped, PAYLOAD_LEN); }
        break;
    case DL_LONGER:
        if (!send_head(c, 200, 3 * (size_t)PAYLOAD_LEN) || !send_all(c, g_payload, PAYLOAD_LEN)) { break; }
        set_phase(1);
        if (!hold_until_go(c)) { break; }
        (void)send_all(c, g_payload + PAYLOAD_LEN, PAYLOAD_LEN);
        set_phase(2);
        hold_until_gone(c);
        break;
    case DL_TRICKLE:
        if (!send_head(c, 200, PAYLOAD_LEN)) { break; }
        for (size_t k = 0; k < PAYLOAD_LEN; k += 1024) {
            if (!send_all(c, g_payload, 1024)) { return; }
            int64_t t = mono_ms() + 1000;
            while (mono_ms() < t) {
                if (dl_stopping() || peer_gone(c, 20)) { return; }
            }
        }
        break;
    case DL_HOLD:
        if (send_head(c, 200, PAYLOAD_LEN)) { hold_until_gone(c); }
        break;
    case DL_MISSING:
        (void)send_head(c, 404, 0);
        break;
    }
}

static void *dl_thread(void *ud) {
    (void)ud;
    while (!dl_stopping()) {
        struct pollfd p = {.fd = g_dl.fd, .events = POLLIN};
        if (poll(&p, 1, 20) <= 0) { continue; }
        int c = accept(g_dl.fd, NULL, NULL);
        if (c < 0) { continue; }
        (void)fcntl(c, F_SETFD, FD_CLOEXEC);
        struct timeval tv = {0, 50000};
        (void)setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        dl_serve(c);
        close(c);
    }
    return NULL;
}

static bool dl_start(void) {
    g_dl.fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (g_dl.fd < 0) { return false; }
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof sa;
    if (bind(g_dl.fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_dl.fd, 8) != 0 ||
        getsockname(g_dl.fd, (struct sockaddr *)&sa, &sl) != 0) {
        return false;
    }
    snprintf(g_dl_prefix, sizeof g_dl_prefix, "http://127.0.0.1:%u/hoaxisr/firc/releases/download/",
             (unsigned)ntohs(sa.sin_port));
    return pthread_create(&g_dl.thread, NULL, dl_thread, NULL) == 0;
}

static void dl_stop(void) {
    pthread_mutex_lock(&g_dl.mu);
    g_dl.stop = true;
    pthread_mutex_unlock(&g_dl.mu);
    pthread_join(g_dl.thread, NULL);
    close(g_dl.fd);
}

static void dl_set(enum dl_mode m) {
    pthread_mutex_lock(&g_dl.mu);
    g_dl.mode = m;
    g_dl.hits = 0;
    g_dl.phase = 0;
    g_dl.go = false;
    g_dl.accept[0] = 0;
    pthread_mutex_unlock(&g_dl.mu);
}

static void dl_go(void) {
    pthread_mutex_lock(&g_dl.mu);
    g_dl.go = true;
    pthread_mutex_unlock(&g_dl.mu);
}

static bool dl_reaches(int hits, int phase, int ms) {
    int64_t end = mono_ms() + ms;
    for (;;) {
        pthread_mutex_lock(&g_dl.mu);
        bool ok = g_dl.hits >= hits && g_dl.phase >= phase;
        pthread_mutex_unlock(&g_dl.mu);
        if (ok) { return true; }
        if (mono_ms() >= end) { return false; }
        sleep_ms(5);
    }
}

static void build_release_json(char *buf, size_t cap, bool digest) {
    snprintf(buf, cap,
             "{\"tag_name\":\"0.3.0\",\"published_at\":\"2026-10-13T08:00:00Z\",\"body\":\"- notes\","
             "\"draft\":false,\"prerelease\":false,\"assets\":[{\"name\":\"%s\",\"state\":\"uploaded\","
             "\"size\":%d,%s\"browser_download_url\":\"%s0.3.0/%s\"}]}",
             IPK_NAME, PAYLOAD_LEN, digest ? "\"digest\":\"sha256:" PAYLOAD_SHA "\"," : "", g_dl_prefix, IPK_NAME);
}

struct ienv {
    char base[64];
    char dir[96];
    char part[256];
    char ipk[256];
    char marker[128];
    char result[128];
    char result_part[128];
    char log[96];
    char hold[96];
    char file[96];
    char old_ipk[256];
    char old_part[256];
    char opkg[PATH_MAX];
    char fake_bin[PATH_MAX];
};

static bool exists(const char *path) { return access(path, F_OK) == 0; }

static long long file_size(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? (long long)st.st_size : -1;
}

static bool read_text(const char *path, char *buf, size_t cap) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) { return false; }
    size_t n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    buf[n] = 0;
    return true;
}

static void write_text(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) { return; }
    fputs(text, fp);
    fclose(fp);
}

static void unset_fakes(void) {
    unsetenv("FAKE_OPKG_HOLD");
    unsetenv("FAKE_OPKG_RC");
    unsetenv("FAKE_OPKG_DAEMON");
    unsetenv("FAKE_OPKG_KILL_PARENT");
    unsetenv("FAKE_DATE_NOW");
}

static bool env_up(ienv_t *e) {
    memset(e, 0, sizeof *e);
    snprintf(e->base, sizeof e->base, "/tmp/firc_update_XXXXXX");
    if (mkdtemp(e->base) == NULL) { return false; }
    g_env = e;
    snprintf(e->dir, sizeof e->dir, "%s/update", e->base);
    snprintf(e->part, sizeof e->part, "%s/%s.part", e->dir, IPK_NAME);
    snprintf(e->ipk, sizeof e->ipk, "%s/%s", e->dir, IPK_NAME);
    snprintf(e->marker, sizeof e->marker, "%s/installing", e->dir);
    snprintf(e->result, sizeof e->result, "%s/result", e->dir);
    snprintf(e->result_part, sizeof e->result_part, "%s/result.part", e->dir);
    snprintf(e->log, sizeof e->log, "%s/log", e->base);
    snprintf(e->hold, sizeof e->hold, "%s/hold", e->base);
    snprintf(e->file, sizeof e->file, "%s/file", e->base);
    snprintf(e->old_ipk, sizeof e->old_ipk, "%s/firc_0.2.9-1_entware_mipsel-3.4_kn.ipk", e->dir);
    snprintf(e->old_part, sizeof e->old_part, "%s/firc_0.2.9-1_entware_mipsel-3.4_kn.ipk.part", e->dir);
    char cwd[PATH_MAX - sizeof(FAKE) - 1];
    if (getcwd(cwd, sizeof cwd) == NULL) { return false; }
    snprintf(e->opkg, sizeof e->opkg, "%s/%s", cwd, FAKE);
    snprintf(e->fake_bin, sizeof e->fake_bin, "%s/%s", cwd, FAKE_BIN);
    char path[sizeof e->fake_bin + sizeof g_path + 2];
    snprintf(path, sizeof path, "%s:%s", e->fake_bin, g_path);
    unset_fakes();
    return setenv("PATH", path, 1) == 0 && setenv("FAKE_OPKG_LOG", e->log, 1) == 0;
}

static void env_down(ienv_t *e) {
    write_text(e->hold, "");
    int64_t start = mono_ms();
    for (;;) {
        firc_update_marker_t m = firc_update_marker_read(e->dir, NULL, 0, NULL);
        int64_t spent = mono_ms() - start;
        if (m == FIRC_UPDATE_MARKER_NONE || m == FIRC_UPDATE_MARKER_STALE || spent > 10000 ||
            (m == FIRC_UPDATE_MARKER_NO_PID && spent > 1000)) {
            break;
        }
        sleep_ms(10);
    }
    const char *paths[] = {e->part,  e->ipk, e->marker, e->result,  e->result_part,
                           e->log,   e->hold, e->file,  e->old_ipk, e->old_part};
    for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) { unlink(paths[i]); }
    rmdir(e->dir);
    rmdir(e->base);
    setenv("PATH", g_path, 1);
    unsetenv("FAKE_OPKG_LOG");
    unset_fakes();
    g_env = NULL;
}

typedef struct {
    const char *version, *target, *opkg, *dir;
    int64_t grace;
    uint64_t (*free_bytes)(const char *dir);
    void (*verified)(void *ud);
} iopts_t;

static bool fx_install_up(fx_t *f, const ienv_t *e, const iopts_t *o) {
    memset(f, 0, sizeof *f);
    g_fx = f;
    if (firc_loop_create(&f->loop) != FIRC_OK) { return false; }
    firc_update_deps_t d = {
        .loop = f->loop,
        .dir = o->dir != NULL ? o->dir : e->dir,
        .api_url = g_api,
        .download_prefix = g_dl_prefix,
        .version = o->version != NULL ? o->version : "0.1.3",
        .target = o->target != NULL ? o->target : "mipsel-3.4_kn",
        .sh = "/bin/sh",
        .opkg = o->opkg != NULL ? o->opkg : e->opkg,
        .revision = 1,
        .url_ok = loopback_ok,
        .checked = on_checked,
        .ud = f,
        .free_bytes = o->free_bytes,
        .handoff_grace_ms = o->grace,
        .verified = o->verified,
    };
    f->u = firc_update_new(&d);
    return f->u != NULL && firc_update_start(f->u) == FIRC_OK;
}

static bool checked_as(fx_t *f, enum mode m) {
    set_mode(m);
    if (!check_once(f)) { return false; }
    firc_update_view_t v;
    firc_update_view(f->u, &v);
    return v.latest != NULL && strcmp(v.latest->tag, "0.3.0") == 0;
}

typedef bool (*view_pred)(const firc_update_view_t *v, const void *ud);

typedef struct {
    fx_t *f;
    view_pred pred;
    const void *ud;
    int64_t deadline;
    bool ok;
} vwait_t;

static void vwait_cb(firc_loop_t *loop, void *ud) {
    vwait_t *w = ud;
    firc_update_view_t v;
    firc_update_view(w->f->u, &v);
    w->ok = w->pred(&v, w->ud);
    if (w->ok || mono_ms() >= w->deadline) { firc_loop_stop(loop); }
}

static bool run_until_view(fx_t *f, view_pred pred, const void *ud, int ms) {
    vwait_t w = {f, pred, ud, mono_ms() + ms, false};
    int timer = 0;
    firc_loop_add_timer(f->loop, 5, 5, vwait_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return w.ok;
}

static bool state_is(const firc_update_view_t *v, const void *ud) {
    return v->state == *(const firc_update_state_t *)ud;
}

static bool idle_with_result(const firc_update_view_t *v, const void *ud) {
    (void)ud;
    return v->state == FIRC_UPDATE_IDLE && v->has_result;
}

static const firc_update_state_t ST_INSTALLING = FIRC_UPDATE_INSTALLING;
static const firc_update_state_t ST_FAILED = FIRC_UPDATE_FAILED;

static int g_log_pipe[2] = {-1, -1};
static char g_log[65536];

static void log_capture_begin(void) {
    if (pipe(g_log_pipe) != 0) { abort(); }
    fcntl(g_log_pipe[0], F_SETFL, fcntl(g_log_pipe[0], F_GETFL) | O_NONBLOCK);
    fcntl(g_log_pipe[1], F_SETFL, fcntl(g_log_pipe[1], F_GETFL) | O_NONBLOCK);
    firc_log_set_fd(g_log_pipe[1]);
}

static const char *log_capture_end(void) {
    firc_log_set_fd(STDOUT_FILENO);
    size_t len = 0;
    for (;;) {
        ssize_t n = read(g_log_pipe[0], g_log + len, sizeof g_log - 1 - len);
        if (n <= 0) { break; }
        len += (size_t)n;
    }
    g_log[len] = 0;
    close(g_log_pipe[0]);
    close(g_log_pipe[1]);
    return g_log;
}

static bool failed_install(fx_t *f, enum dl_mode m, char *error, size_t cap) {
    dl_set(m);
    firc_update_install_ans_t ans;
    if (firc_update_install(f->u, "0.3.0", &ans) != FIRC_UPDATE_OK) { return false; }
    if (!run_until_view(f, state_is, &ST_FAILED, 10000)) { return false; }
    firc_update_view_t v;
    firc_update_view(f->u, &v);
    snprintf(error, cap, "%s", v.error != NULL ? v.error : "(null)");
    return true;
}

static bool any_part(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL) { return false; }
    bool found = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t n = strlen(de->d_name);
        if (n > 5 && strcmp(de->d_name + n - 5, ".part") == 0) { found = true; }
    }
    closedir(d);
    return found;
}

static uint64_t one_byte_free(const char *dir) {
    (void)dir;
    return 1;
}

static void kill_session(pid_t sid) {
    DIR *d = opendir("/proc");
    if (d == NULL) { return; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        char *end = NULL;
        long pid = strtol(de->d_name, &end, 10);
        if (end == de->d_name || *end != 0) { continue; }
        char path[64], buf[1024];
        snprintf(path, sizeof path, "/proc/%ld/stat", pid);
        if (!read_text(path, buf, sizeof buf)) { continue; }
        const char *p = strrchr(buf, ')');
        long s = 0;
        if (p != NULL && sscanf(p + 1, " %*c %*d %*d %ld", &s) == 1 && s == (long)sid) { kill((pid_t)pid, SIGKILL); }
    }
    closedir(d);
}

/* Catches a package handed to opkg without its download and check, a wrong path or size given to opkg, or a .part left. */
TEST an_install_downloads_verifies_and_hands_off(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_FULL);
    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    log_capture_begin();
    firc_update_install_ans_t ans;
    firc_update_refusal_t r = firc_update_install(f.u, "0.3.0", &ans);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    firc_update_state_t first = v.state;
    bool installing = r == FIRC_UPDATE_OK && run_until_view(&f, state_is, &ST_INSTALLING, 10000);
    bool marker = exists(e.marker);
    struct stat st;
    int ipk_mode = stat(e.ipk, &st) == 0 ? (int)(st.st_mode & 0777) : -1;
    write_text(e.hold, "");
    bool idle = installing && run_until_view(&f, idle_with_result, NULL, 10000);
    firc_update_view(f.u, &v);
    const char *log = log_capture_end();
    ASSERT_EQ(FIRC_UPDATE_OK, r);
    ASSERT_STR_EQ("0.3.0", ans.tag);
    ASSERT_STR_EQ(IPK_NAME, ans.asset);
    ASSERT_EQ(PAYLOAD_LEN, ans.size);
    ASSERT_STR_EQ("downloading", firc_update_state_name(first));
    ASSERT(installing);
    ASSERT(marker);
    ASSERT_EQ(0600, ipk_mode);
    ASSERT(idle);
    const char *d = strstr(log, "update: downloading " IPK_NAME);
    const char *ver = d != NULL ? strstr(d, "update: verifying " IPK_NAME) : NULL;
    const char *ins = ver != NULL ? strstr(ver, "update: installing " IPK_NAME) : NULL;
    ASSERT(ins != NULL);
    ASSERT_STR_EQ("0.3.0", v.result.version);
    ASSERT_EQ(0, v.result.opkg_exit);
    char text[512], want[512];
    ASSERT(read_text(e.log, text, sizeof text));
    snprintf(want, sizeof want, "install %s 1000000\n", e.ipk);
    ASSERT_STR_EQ(want, text);
    ASSERT_FALSE(exists(e.part));
    pthread_mutex_lock(&g_dl.mu);
    snprintf(text, sizeof text, "%s", g_dl.accept);
    pthread_mutex_unlock(&g_dl.mu);
    ASSERT_STR_EQ("application/octet-stream", text);
    PASS();
}

/* Catches a truncated package reaching opkg. */
TEST a_download_one_byte_short_is_refused_and_removed(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    ASSERT_EQ(0, mkdir(e.dir, 0700));
    write_text(e.old_ipk, "old");
    write_text(e.old_part, "old");
    write_text(e.result, "0.2.9 0 1791830000\n");
    char error[256];
    ASSERT(failed_install(&f, DL_SHORT, error, sizeof error));
    ASSERT_STR_EQ("the download is 999999 bytes; the release says 1000000", error);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_FALSE(v.has_result);
    ASSERT_FALSE(exists(e.old_ipk));
    ASSERT_FALSE(exists(e.old_part));
    ASSERT_FALSE(exists(e.result));
    ASSERT_FALSE(exists(e.log));
    ASSERT_FALSE(exists(e.part));
    ASSERT_FALSE(exists(e.ipk));
    ASSERT_FALSE(exists(e.marker));
    PASS();
}

/* Catches the digest compared on the wrong bytes or not at all. */
TEST a_download_with_one_byte_changed_is_refused(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    char error[256];
    ASSERT(failed_install(&f, DL_FLIPPED, error, sizeof error));
    ASSERT_STR_EQ("checksum: the download does not match the release's digest", error);
    ASSERT_FALSE(exists(e.log));
    ASSERT_FALSE(exists(e.part));
    ASSERT_FALSE(exists(e.ipk));
    ASSERT_FALSE(exists(e.marker));
    PASS();
}

/* Catches an unbounded write filling /opt while a server keeps sending. */
TEST a_download_longer_than_the_release_stops_at_its_size(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_LONGER);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(dl_reaches(1, 1, 10000));
    int64_t end = mono_ms() + 5000;
    while (file_size(e.part) < PAYLOAD_LEN && mono_ms() < end) { sleep_ms(5); }
    sleep_ms(100);
    long long held = file_size(e.part);
    struct stat st;
    int part_mode = stat(e.part, &st) == 0 ? (int)(st.st_mode & 0777) : -1;
    firc_update_view_t during;
    firc_update_view(f.u, &during);
    dl_go();
    ASSERT(dl_reaches(1, 2, 10000));
    sleep_ms(300);
    long long after = file_size(e.part);
    ASSERT(run_until_view(&f, state_is, &ST_FAILED, 10000));
    ASSERT_EQ(PAYLOAD_LEN, held);
    ASSERT(after <= PAYLOAD_LEN);
    ASSERT_EQ(0600, part_mode);
    ASSERT_STR_EQ("downloading", firc_update_state_name(during.state));
    ASSERT_EQ(PAYLOAD_LEN, during.bytes);
    ASSERT_EQ(PAYLOAD_LEN, during.total);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.error != NULL);
    unsigned long long got = 0;
    char tail[64] = "";
    ASSERT_EQ(2, sscanf(v.error, "the download is %llu bytes; the release says %63[0-9]", &got, tail));
    ASSERT(got > PAYLOAD_LEN);
    ASSERT_STR_EQ("1000000", tail);
    ASSERT_FALSE(exists(e.log));
    ASSERT_FALSE(exists(e.part));
    ASSERT_FALSE(exists(e.ipk));
    ASSERT_FALSE(exists(e.marker));
    PASS();
}

/* Catches a full disk ignored until the digest fails a minute later. */
TEST a_write_error_stops_the_sink(void) {
    int fd = open("/dev/full", O_WRONLY | O_CLOEXEC);
    ASSERT(fd >= 0);
    _Atomic uint64_t progress = 0;
    firc_update_file_sink_t s = {.fd = fd, .want = 100, .progress = &progress};
    firc_sha256_init(&s.sha);
    uint8_t buf[10] = {0};
    bool ok = firc_update_file_sink_write(&s, buf, sizeof buf);
    close(fd);
    ASSERT_FALSE(ok);
    ASSERT_EQ(ENOSPC, s.err);
    ASSERT_EQ(0, s.got);
    PASS();
}

/* Catches a sink that writes the chunk crossing the release's size before refusing, putting it past size on disk. */
TEST the_chunk_crossing_the_size_is_not_written(void) {
    char path[] = "/tmp/firc_sink_XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    unlink(path);
    _Atomic uint64_t progress = 0;
    firc_update_file_sink_t s = {.fd = fd, .want = 10, .progress = &progress};
    firc_sha256_init(&s.sha);
    const uint8_t six[6] = {1, 2, 3, 4, 5, 6}, five[5] = {7, 8, 9, 10, 11};
    bool first = firc_update_file_sink_write(&s, six, sizeof six);
    uint64_t after_first = atomic_load(&progress);
    bool second = firc_update_file_sink_write(&s, five, sizeof five);
    struct stat st;
    int rc = fstat(fd, &st);
    close(fd);
    ASSERT(first);
    ASSERT_EQ(6, after_first);
    ASSERT_FALSE(second);
    ASSERT_EQ(0, rc);
    ASSERT_EQ(6, st.st_size);
    ASSERT(s.got > s.want);
    ASSERT_EQ(0, s.err);
    ASSERT_EQ(6, atomic_load(&progress));
    PASS();
}

/* Catches the job ignoring the sink's error: no space text, or a .part left on a full disk. */
TEST a_full_disk_stops_the_download_and_removes_the_part(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    struct rlimit old;
    ASSERT_EQ(0, getrlimit(RLIMIT_FSIZE, &old));
    struct rlimit lim = {500000, old.rlim_max};
    void (*prev)(int) = signal(SIGXFSZ, SIG_IGN);
    bool limited = setrlimit(RLIMIT_FSIZE, &lim) == 0;
    char error[256] = "";
    bool failed = limited && failed_install(&f, DL_FULL, error, sizeof error);
    setrlimit(RLIMIT_FSIZE, &old);
    signal(SIGXFSZ, prev);
    ASSERT(limited);
    ASSERT(failed);
    ASSERT_STR_EQ("no space left: 500000 of 1000000 bytes written (File too large)", error);
    ASSERT_FALSE(exists(e.part));
    ASSERT_FALSE(exists(e.log));
    ASSERT_FALSE(exists(e.marker));
    PASS();
}

/* Catches GitHub's refusal reported as a size or checksum failure. */
TEST a_refused_download_says_githubs_status(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    char error[256];
    ASSERT(failed_install(&f, DL_MISSING, error, sizeof error));
    ASSERT_STR_EQ("GitHub answered 404", error);
    ASSERT_FALSE(exists(e.part));
    ASSERT_FALSE(exists(e.log));
    PASS();
}

/* Catches the rule off by a size, without the 8 MiB, or wrapping to a small need. */
TEST the_space_rule_is_three_sizes_and_eight_mib(void) {
    ASSERT_EQ(10875920ULL, firc_update_space_need(829104));
    ASSERT_EQ(8388608ULL, firc_update_space_need(0));
    ASSERT_EQ(UINT64_MAX, firc_update_space_need(UINT64_MAX / 2));
    ASSERT_EQ(UINT64_MAX - 1, firc_update_space_need(6148914691233721002ULL));
    ASSERT_EQ(UINT64_MAX, firc_update_space_need(6148914691233721003ULL));
    PASS();
}

static firc_update_refusal_t install_as(const ienv_t *e, const iopts_t *o, enum mode m, const char *tag,
                                        firc_update_install_ans_t *ans) {
    static fx_t f;
    firc_update_refusal_t r = (firc_update_refusal_t)-1;
    if (fx_install_up(&f, e, o) && (m == M_NONE || checked_as(&f, m))) { r = firc_update_install(f.u, tag, ans); }
    fx_down(&f);
    return r;
}

/* Catches a refusal skipped or reordered, or a running check reported as an install. */
TEST the_install_refusals_in_order(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    firc_update_install_ans_t ans;

    ASSERT_EQ(FIRC_UPDATE_CANNOT, install_as(&e, &(iopts_t){.target = ""}, M_NONE, "0.3.0", &ans));
    ASSERT(ans.reason != NULL);
    ASSERT_STR_EQ("no-target", ans.reason);
    ASSERT_EQ(FIRC_UPDATE_STALE_CHECK, install_as(&e, &(iopts_t){0}, M_NONE, "0.3.0", &ans));
    ASSERT_EQ(FIRC_UPDATE_STALE_CHECK, install_as(&e, &(iopts_t){0}, M_INSTALL, "0.3.1", &ans));
    ASSERT_EQ(FIRC_UPDATE_NOT_NEWER, install_as(&e, &(iopts_t){.version = "0.3.0"}, M_INSTALL, "0.3.0", &ans));
    ASSERT_EQ(FIRC_UPDATE_NOT_NEWER, install_as(&e, &(iopts_t){.version = "0.3.0"}, M_NO_DIGEST, "0.3.0", &ans));
    ASSERT_EQ(FIRC_UPDATE_NOT_INSTALLABLE, install_as(&e, &(iopts_t){0}, M_NO_DIGEST, "0.3.0", &ans));
    ASSERT(ans.reason != NULL);
    ASSERT_STR_EQ("no-digest", ans.reason);
    ASSERT_EQ(FIRC_UPDATE_NOT_INSTALLABLE,
              install_as(&e, &(iopts_t){.free_bytes = one_byte_free}, M_NO_DIGEST, "0.3.0", &ans));
    ASSERT_FALSE(exists(e.dir));
    ASSERT_EQ(FIRC_UPDATE_NO_SPACE, install_as(&e, &(iopts_t){.free_bytes = one_byte_free}, M_INSTALL, "0.3.0", &ans));
    ASSERT_EQ(1, ans.free_bytes);
    ASSERT_EQ(11388608ULL, ans.need_bytes);
    struct stat st;
    ASSERT_EQ(0, stat(e.dir, &st));
    ASSERT(S_ISDIR(st.st_mode));
    ASSERT_EQ(0700, st.st_mode & 0777);
    write_text(e.file, "");
    char under_file[160];
    snprintf(under_file, sizeof under_file, "%s/update", e.file);
    ASSERT_EQ(FIRC_UPDATE_IO,
              install_as(&e, &(iopts_t){.dir = under_file, .free_bytes = one_byte_free}, M_INSTALL, "0.3.0", &ans));

    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_HOLD);
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(dl_reaches(1, 0, 5000));
    ASSERT_EQ(FIRC_UPDATE_BUSY, firc_update_install(f.u, "0.3.0", &ans));
    fx_down(&f);

    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    reset();
    set_mode(M_HOLD);
    ASSERT_EQ(FIRC_OK, firc_update_check(f.u));
    ASSERT(hits_reach(1, 5000));
    ASSERT_EQ(FIRC_UPDATE_CHECK_RUNNING, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT_EQ(FIRC_OK, firc_loop_post(g_srv->loop, release_held, NULL));
    ASSERT(run_until_checked(&f, 1, 5000));
    fx_down(&f);

    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    ASSERT_EQ(FIRC_OK, firc_update_handoff(e.dir, "/bin/sh", e.opkg, e.ipk, "0.3.0", (int64_t)time(NULL)));
    int64_t end = mono_ms() + 5000;
    while (firc_update_marker_read(e.dir, NULL, 0, NULL) != FIRC_UPDATE_MARKER_ALIVE && mono_ms() < end) {
        sleep_ms(5);
    }
    ASSERT_EQ(FIRC_UPDATE_MARKER_ALIVE, firc_update_marker_read(e.dir, NULL, 0, NULL));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(firc_update_installing(f.u));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("installing", firc_update_state_name(v.state));
    ASSERT_EQ(FIRC_UPDATE_BUSY, firc_update_install(f.u, "0.3.0", &ans));
    PASS();
}

/* Catches in-memory installing held forever, a dead shell read as installing, or an old result taken for this install. */
TEST the_settle_rule(void) {
    const int64_t G = 10000, E = 1791831000;
    ASSERT_EQ(FIRC_UPDATE_SETTLED_INSTALLING,
              firc_update_settle(true, 2000, G, FIRC_UPDATE_MARKER_NO_PID, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED, firc_update_settle(true, 11000, G, FIRC_UPDATE_MARKER_NO_PID, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED, firc_update_settle(true, 10000, G, FIRC_UPDATE_MARKER_NO_PID, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED, firc_update_settle(false, 2000, G, FIRC_UPDATE_MARKER_NO_PID, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED, firc_update_settle(true, 2000, G, FIRC_UPDATE_MARKER_STALE, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_INSTALLING,
              firc_update_settle(true, 60000, G, FIRC_UPDATE_MARKER_ALIVE, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_INSTALLING,
              firc_update_settle(false, 0, G, FIRC_UPDATE_MARKER_ALIVE, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_IDLE, firc_update_settle(true, 2000, G, FIRC_UPDATE_MARKER_NONE, true, E, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED,
              firc_update_settle(true, 11000, G, FIRC_UPDATE_MARKER_NONE, true, E - 1, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED, firc_update_settle(true, 11000, G, FIRC_UPDATE_MARKER_NONE, false, E, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED, firc_update_settle(false, 0, G, FIRC_UPDATE_MARKER_STALE, false, 0, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_FAILED, firc_update_settle(false, 0, G, FIRC_UPDATE_MARKER_STALE, true, E, E));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_IDLE, firc_update_settle(false, 0, G, FIRC_UPDATE_MARKER_NONE, false, 0, 0));
    ASSERT_EQ(FIRC_UPDATE_SETTLED_IDLE, firc_update_settle(false, 0, G, FIRC_UPDATE_MARKER_NONE, true, 5, 0));
    PASS();
}

/* Catches the daemon opkg refused answering 409 to every install and restart until someone restarts it over ssh. */
TEST opkg_refusing_leaves_the_daemon_idle_with_the_exit(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    ASSERT_EQ(0, setenv("FAKE_OPKG_RC", "255", 1));
    dl_set(DL_FULL);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(run_until_view(&f, idle_with_result, NULL, 5000));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("0.3.0", v.result.version);
    ASSERT_EQ(255, v.result.opkg_exit);
    ASSERT_FALSE(firc_update_installing(f.u));
    char error[256];
    ASSERT(failed_install(&f, DL_SHORT, error, sizeof error));
    ASSERT(check_once(&f));
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("idle", firc_update_state_name(v.state));
    char text[1024], want[1024];
    ASSERT(read_text(e.log, text, sizeof text));
    snprintf(want, sizeof want, "install %s 1000000\n", e.ipk);
    ASSERT_STR_EQ(want, text);
    PASS();
}

/* Catches a shell failure ahead of opkg leaving the lock held. */
TEST a_missing_opkg_frees_the_lock_with_127(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    char missing[160];
    snprintf(missing, sizeof missing, "%s/no-opkg", e.base);
    ASSERT(fx_install_up(&f, &e, &(iopts_t){.opkg = missing}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_FULL);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(run_until_view(&f, idle_with_result, NULL, 5000));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("0.3.0", v.result.version);
    ASSERT_EQ(127, v.result.opkg_exit);
    ASSERT_FALSE(firc_update_installing(f.u));
    PASS();
}

static bool shell_killed_before_its_append(const ienv_t *e) {
    char text[256] = "";
    int64_t end = mono_ms() + 5000;
    while (mono_ms() < end) {
        if (read_text(e->marker, text, sizeof text) && strchr(text, '\n') != NULL &&
            strchr(strchr(text, '\n') + 1, '\n') != NULL) {
            break;
        }
        sleep_ms(5);
    }
    char *nl = strchr(text, '\n');
    if (nl == NULL) { return false; }
    long pid = strtol(nl + 1, NULL, 10);
    if (pid <= 1) { return false; }
    kill_session((pid_t)pid);
    nl[1] = 0;
    write_text(e->marker, text);
    return true;
}

/* Catches a marker without a pid line trusted forever by the daemon that wrote it. */
TEST a_dead_shell_frees_the_lock_after_the_grace(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){.grace = 200}));
    ASSERT(checked_as(&f, M_INSTALL));
    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    dl_set(DL_FULL);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(run_until_view(&f, state_is, &ST_INSTALLING, 10000));
    ASSERT(shell_killed_before_its_append(&e));
    ASSERT(run_until_view(&f, state_is, &ST_FAILED, 5000));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.error != NULL);
    ASSERT_STR_EQ(INTERRUPTED, v.error);
    ASSERT_FALSE(firc_update_installing(f.u));
    PASS();
}

/* Catches this daemon's hand-off forgotten, which reads a marker gone without a result as a clean finish. */
TEST a_marker_gone_without_a_result_is_failed(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){.grace = 200}));
    ASSERT(checked_as(&f, M_INSTALL));
    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    dl_set(DL_FULL);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(run_until_view(&f, state_is, &ST_INSTALLING, 10000));
    ASSERT(shell_killed_before_its_append(&e));
    ASSERT_EQ(0, unlink(e.marker));
    ASSERT(run_until_view(&f, state_is, &ST_FAILED, 5000));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT(v.error != NULL);
    ASSERT_STR_EQ(INTERRUPTED, v.error);
    PASS();
}

/* Catches the grace ignored, which fails an install whose shell has not appended its pid yet. */
TEST the_grace_holds_installing_while_the_shell_appends(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){.grace = 5000}));
    ASSERT(checked_as(&f, M_INSTALL));
    ASSERT_EQ(0, setenv("FAKE_OPKG_HOLD", e.hold, 1));
    dl_set(DL_FULL);
    firc_update_install_ans_t ans;
    int64_t t0 = mono_ms();
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(run_until_view(&f, state_is, &ST_INSTALLING, 10000));
    ASSERT(shell_killed_before_its_append(&e));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    bool held = firc_update_installing(f.u);
    ASSERT(mono_ms() - t0 < 5000);
    ASSERT_STR_EQ("installing", firc_update_state_name(v.state));
    ASSERT(held);
    ASSERT(run_until_view(&f, state_is, &ST_FAILED, 10000));
    ASSERT(mono_ms() - t0 >= 5000);
    PASS();
}

/* Catches a marker whose shell died under another daemon reported as idle, hiding an interrupted install. */
TEST a_stale_marker_from_another_daemon_reads_as_failed(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT_EQ(0, mkdir(e.dir, 0700));
    write_text(e.marker, "0.3.0 1791831000\n2147483646 1\n");
    ASSERT_EQ(FIRC_UPDATE_MARKER_STALE, firc_update_marker_read(e.dir, NULL, 0, NULL));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("failed", firc_update_state_name(v.state));
    ASSERT(v.error != NULL);
    ASSERT_STR_EQ(INTERRUPTED, v.error);
    ASSERT_FALSE(firc_update_installing(f.u));
    ASSERT(checked_as(&f, M_INSTALL));
    firc_update_install_ans_t ans;
    dl_set(DL_HOLD);
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    PASS();
}

static pthread_mutex_t g_stop_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_stop_cv = PTHREAD_COND_INITIALIZER;
static int g_stop_stage;

static void stop_at_verified(void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_stop_mu);
    g_stop_stage = 1;
    pthread_cond_broadcast(&g_stop_cv);
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 5;
    while (g_stop_stage < 2) {
        if (pthread_cond_timedwait(&g_stop_cv, &g_stop_mu, &until) != 0) { break; }
    }
    pthread_mutex_unlock(&g_stop_mu);
    sleep_ms(200);
}

typedef struct {
    firc_update_t *u;
} stopper_t;

static void *stopper(void *ud) {
    stopper_t *s = ud;
    pthread_mutex_lock(&g_stop_mu);
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 10;
    while (g_stop_stage < 1) {
        if (pthread_cond_timedwait(&g_stop_cv, &g_stop_mu, &until) != 0) { break; }
    }
    g_stop_stage = 2;
    pthread_cond_broadcast(&g_stop_cv);
    pthread_mutex_unlock(&g_stop_mu);
    firc_update_free(s->u);
    return NULL;
}

/* Catches a stop between the last byte and the hand-off still running opkg on a daemon the operator stopped. */
TEST a_stop_after_the_download_never_hands_off(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){.verified = stop_at_verified}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_FULL);
    g_stop_stage = 0;
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    stopper_t st = {f.u};
    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, NULL, stopper, &st));
    pthread_join(t, NULL);
    f.u = NULL;
    int stage = g_stop_stage;
    sleep_ms(300);
    ASSERT_EQ(2, stage);
    ASSERT_FALSE(exists(e.marker));
    ASSERT_FALSE(exists(e.log));
    ASSERT_FALSE(exists(e.ipk));
    ASSERT_FALSE(exists(e.part));
    PASS();
}

static void *canceller(void *ud) {
    stopper_t *s = ud;
    pthread_mutex_lock(&g_stop_mu);
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 10;
    while (g_stop_stage < 1) {
        if (pthread_cond_timedwait(&g_stop_cv, &g_stop_mu, &until) != 0) { break; }
    }
    firc_update_cancel(s->u);
    g_stop_stage = 2;
    pthread_cond_broadcast(&g_stop_cv);
    pthread_mutex_unlock(&g_stop_mu);
    return NULL;
}

/* Catches a cancel raised at the top of the stop not reaching the job, so a download ending mid-stop hands off. */
TEST a_cancel_after_the_download_never_hands_off(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){.verified = stop_at_verified}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_FULL);
    g_stop_stage = 0;
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    stopper_t st = {f.u};
    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, NULL, canceller, &st));
    bool failed = run_until_view(&f, state_is, &ST_FAILED, 10000);
    pthread_join(t, NULL);
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_EQ(2, g_stop_stage);
    ASSERT(failed);
    ASSERT_STR_EQ("the download was stopped", v.error);
    ASSERT_FALSE(exists(e.marker));
    ASSERT_FALSE(exists(e.log));
    ASSERT_FALSE(exists(e.ipk));
    ASSERT_FALSE(exists(e.part));
    PASS();
}

static _Thread_local bool t_calloc_fails;

extern void *__real_calloc(size_t n, size_t size);
void *__wrap_calloc(size_t n, size_t size);
void *__wrap_calloc(size_t n, size_t size) { return t_calloc_fails ? NULL : __real_calloc(n, size); }

static void cancel_without_calloc(void *ud) {
    fx_t *f = ud;
    t_calloc_fails = true;
    firc_update_cancel(f->u);
}

/* Catches the job's last step lost to a failed allocation, holding the install lock until the process ends. */
TEST a_failed_allocation_at_the_end_still_frees_the_lock(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){.verified = cancel_without_calloc}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_FULL);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(run_until_view(&f, state_is, &ST_FAILED, 5000));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_STR_EQ("the download was stopped", v.error);
    ASSERT_FALSE(firc_update_busy(f.u));
    PASS();
}

/* Catches a wall clock stepped back during opkg turning a refusal into an interrupted install. */
TEST a_clock_stepped_back_still_reads_opkgs_exit(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    ASSERT_EQ(0, setenv("FAKE_OPKG_RC", "255", 1));
    ASSERT_EQ(0, setenv("FAKE_DATE_NOW", "1000000000", 1));
    dl_set(DL_FULL);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(run_until_view(&f, idle_with_result, NULL, 5000));
    firc_update_view_t v;
    firc_update_view(f.u, &v);
    ASSERT_EQ(255, v.result.opkg_exit);
    ASSERT_EQ(1000000000, v.result.finished_at);
    ASSERT(v.error == NULL);
    PASS();
}

/* Catches 1 MB left behind per kill, or a stop waiting out the 300 s transfer. */
TEST stopping_mid_download_removes_the_part_file(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_TRICKLE);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(dl_reaches(1, 0, 5000));
    int64_t end = mono_ms() + 5000;
    while (file_size(e.part) <= 0 && mono_ms() < end) { sleep_ms(5); }
    ASSERT(file_size(e.part) > 0);
    int64_t t0 = mono_ms();
    firc_update_free(f.u);
    f.u = NULL;
    ASSERT(mono_ms() - t0 < 3000);
    ASSERT_FALSE(any_part(e.dir));
    PASS();
}

/* Catches a check let through mid-download, which would replace the release being installed. */
TEST a_check_is_refused_while_installing(void) {
    static ienv_t e;
    static fx_t f;
    ASSERT(env_up(&e));
    ASSERT(fx_install_up(&f, &e, &(iopts_t){0}));
    ASSERT(checked_as(&f, M_INSTALL));
    dl_set(DL_HOLD);
    firc_update_install_ans_t ans;
    ASSERT_EQ(FIRC_UPDATE_OK, firc_update_install(f.u, "0.3.0", &ans));
    ASSERT(dl_reaches(1, 0, 5000));
    ASSERT_EQ(FIRC_ERR_STATE, firc_update_check(f.u));
    PASS();
}

SUITE(update) {
    GREATEST_SET_SETUP_CB(setup, NULL);
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(a_check_finds_the_newer_release);
    RUN_TEST(the_check_asks_as_firc_for_github_json);
    RUN_TEST(an_equal_or_older_release_is_not_newer);
    RUN_TEST(why_this_build_cannot_install);
    RUN_TEST(a_403_with_no_requests_left_is_a_rate_limit_and_keeps_the_last_release);
    RUN_TEST(an_oversized_error_answer_says_githubs_status);
    RUN_TEST(a_403_without_rate_limit_headers_is_upstream);
    RUN_TEST(a_429_with_retry_after_is_a_rate_limit);
    RUN_TEST(no_release_at_all_is_not_an_error);
    RUN_TEST(a_body_over_256_kib_is_refused_and_keeps_the_last_release);
    RUN_TEST(two_checks_at_once_cost_one_request);
    RUN_TEST(the_daily_check_runs_only_when_on_and_a_day_has_passed);
    RUN_TEST(a_failed_daily_check_is_retried_at_the_next_tick);
    RUN_TEST(an_unreachable_github_says_why_in_libcurls_words);
    RUN_TEST(stopping_mid_check_returns_promptly);
    RUN_TEST(an_install_downloads_verifies_and_hands_off);
    RUN_TEST(a_download_one_byte_short_is_refused_and_removed);
    RUN_TEST(a_download_with_one_byte_changed_is_refused);
    RUN_TEST(a_download_longer_than_the_release_stops_at_its_size);
    RUN_TEST(a_write_error_stops_the_sink);
    RUN_TEST(the_chunk_crossing_the_size_is_not_written);
    RUN_TEST(a_full_disk_stops_the_download_and_removes_the_part);
    RUN_TEST(a_refused_download_says_githubs_status);
    RUN_TEST(the_space_rule_is_three_sizes_and_eight_mib);
    RUN_TEST(the_install_refusals_in_order);
    RUN_TEST(the_settle_rule);
    RUN_TEST(opkg_refusing_leaves_the_daemon_idle_with_the_exit);
    RUN_TEST(a_missing_opkg_frees_the_lock_with_127);
    RUN_TEST(a_dead_shell_frees_the_lock_after_the_grace);
    RUN_TEST(the_grace_holds_installing_while_the_shell_appends);
    RUN_TEST(a_marker_gone_without_a_result_is_failed);
    RUN_TEST(a_stale_marker_from_another_daemon_reads_as_failed);
    RUN_TEST(stopping_mid_download_removes_the_part_file);
    RUN_TEST(a_stop_after_the_download_never_hands_off);
    RUN_TEST(a_cancel_after_the_download_never_hands_off);
    RUN_TEST(a_failed_allocation_at_the_end_still_frees_the_lock);
    RUN_TEST(a_clock_stepped_back_still_reads_opkgs_exit);
    RUN_TEST(a_check_is_refused_while_installing);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    g_fixture = read_file("tests/unit/fixtures/release-0.2.0.json", &g_fixture_len);
    if (g_fixture == NULL || !build_big()) {
        fprintf(stderr, "fixture not read\n");
        return 1;
    }
    const char *path = getenv("PATH");
    snprintf(g_path, sizeof g_path, "%s", path != NULL ? path : "/usr/bin:/bin");
    g_payload = malloc(2 * (size_t)PAYLOAD_LEN);
    g_flipped = malloc(PAYLOAD_LEN);
    if (g_payload == NULL || g_flipped == NULL || !dl_start()) {
        fprintf(stderr, "download stub not started\n");
        return 1;
    }
    memset(g_payload, 'a', 2 * (size_t)PAYLOAD_LEN);
    memset(g_flipped, 'a', PAYLOAD_LEN);
    g_flipped[PAYLOAD_LEN / 2] = 'b';
    build_release_json(g_install_json, sizeof g_install_json, true);
    build_release_json(g_no_digest_json, sizeof g_no_digest_json, false);
    firc_sub_fetch_global_init();
    RUN_SUITE(update);
    firc_sub_fetch_global_cleanup();
    dl_stop();
    free(g_payload);
    free(g_flipped);
    free(g_fixture);
    free(g_big);
    GREATEST_MAIN_END();
}

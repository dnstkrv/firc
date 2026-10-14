#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include "greatest.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "firc/httpd.h"
#include "firc/ifcheck.h"
#include "firc/loop.h"
#include "firc/settings.h"
#include "firc/sub_fetch.h"

#define PORT 18110

static _Atomic int g_hits_204;
static void h_204(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    g_hits_204++;
    firc_http_res_write(res, 204, NULL, NULL, 0);
}
static void h_200(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)"ok", 2);
}
static void h_moved(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    (void)ud;
    firc_http_res_set_header(res, "Location", "/204");
    firc_http_res_write(res, 302, NULL, NULL, 0);
}

typedef struct {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
    int silent;
} harness_t;

static void *loop_thread(void *ud) {
    firc_loop_run(((harness_t *)ud)->loop);
    return NULL;
}

static bool start(harness_t *h) {
    memset(h, 0, sizeof(*h));
    g_hits_204 = 0;
    if (firc_loop_create(&h->loop) != FIRC_OK || firc_httpd_create(h->loop, &h->srv) != FIRC_OK) { return false; }
    firc_httpd_route(h->srv, "GET", "/204", h_204, NULL);
    firc_httpd_route(h->srv, "GET", "/200", h_200, NULL);
    firc_httpd_route(h->srv, "GET", "/moved", h_moved, NULL);
    if (firc_httpd_listen_tcp(h->srv, "127.0.0.1", PORT) != FIRC_OK) { return false; }
    h->silent = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(18111)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(h->silent, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(h->silent, 4) != 0) { return false; }
    return pthread_create(&h->thread, NULL, loop_thread, h) == 0;
}

static void stop(harness_t *h) {
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->srv);
    firc_loop_destroy(h->loop);
    close(h->silent);
}

static _Atomic uint32_t g_mark_seen;
static _Atomic int g_marks;
static bool g_refuse_marks;
static int record_mark(int fd, int level, int name, const void *val, socklen_t len) {
    if (level == SOL_SOCKET && name == SO_MARK) {
        uint32_t m = 0;
        memcpy(&m, val, sizeof(m));
        g_mark_seen = m;
        g_marks++;
        return g_refuse_marks ? -1 : 0;
    }
    return setsockopt(fd, level, name, val, len);
}

static char g_url[96];
static const char *url_at(int port, const char *path) {
    snprintf(g_url, sizeof(g_url), "http://127.0.0.1:%d%s", port, path);
    return g_url;
}

static long ms_since(const struct timespec *a) {
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return (long)(b.tv_sec - a->tv_sec) * 1000 + (b.tv_nsec - a->tv_nsec) / 1000000;
}

TEST only_a_204_passes(void) {
    harness_t h;
    ASSERT(start(&h));
    long st = 0;
    char e[FIRC_IF_ERROR_MAX];
    ASSERT(firc_ifcheck_once(url_at(PORT, "/204"), NULL, 0, 2, NULL, &st, e, sizeof(e)));
    ASSERT_EQ(204, st);
    ASSERT_FALSE(firc_ifcheck_once(url_at(PORT, "/200"), NULL, 0, 2, NULL, &st, e, sizeof(e)));
    ASSERT_STR_EQ("answered 200, not 204", e);
    g_hits_204 = 0;
    ASSERT_FALSE(firc_ifcheck_once(url_at(PORT, "/moved"), NULL, 0, 2, NULL, &st, e, sizeof(e)));
    ASSERT_STR_EQm("a redirect is not followed", "answered 302, not 204", e);
    ASSERT_EQ_FMTm("the redirect's target was never asked", 0, g_hits_204, "%d");
    stop(&h);
    PASS();
}

TEST a_timeout_and_a_refusal_fail_with_libcurls_words(void) {
    harness_t h;
    ASSERT(start(&h));
    long st = 0;
    char e[FIRC_IF_ERROR_MAX];
    ASSERT_FALSE(firc_ifcheck_once(url_at(18111, "/204"), NULL, 0, 1, NULL, &st, e, sizeof(e)));
    ASSERT(strstr(e, "imed out") != NULL);
    ASSERT_FALSE(firc_ifcheck_once(url_at(18112, "/204"), NULL, 0, 1, NULL, &st, e, sizeof(e)));
    ASSERT(e[0] != '\0' && strstr(e, "204") == NULL);
    stop(&h);
    PASS();
}

typedef struct {
    _Atomic bool *flag;
    long after_ms;
} raiser_t;

static void *raise_later(void *ud) {
    raiser_t *r = ud;
    struct timespec ts = {r->after_ms / 1000, (r->after_ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
    atomic_store(r->flag, true);
    return NULL;
}

TEST a_raised_stop_ends_a_check_inside_curl(void) {
    harness_t h;
    ASSERT(start(&h));
    _Atomic bool flag;
    atomic_init(&flag, false);
    raiser_t r = {&flag, 300};
    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, NULL, raise_later, &r));
    long st = 0;
    char e[FIRC_IF_ERROR_MAX];
    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    ASSERT_FALSE(firc_ifcheck_once(url_at(18111, "/204"), NULL, 0, 10, &flag, &st, e, sizeof(e)));
    long ms = ms_since(&a);
    pthread_join(t, NULL);
    ASSERT_LTm("a stop waits out no 10 s timeout", ms, 2500);
    stop(&h);
    PASS();
}

TEST the_mark_is_on_the_socket(void) {
    harness_t h;
    ASSERT(start(&h));
    firc_sub_fetch_set_setsockopt_for_test(record_mark);
    g_marks = 0;
    long st = 0;
    char e[FIRC_IF_ERROR_MAX];
    ASSERT(firc_ifcheck_once(url_at(PORT, "/204"), NULL, 0x30000, 2, NULL, &st, e, sizeof(e)));
    ASSERT_EQ_FMT(0x30000u, g_mark_seen, "%x");
    ASSERT_EQ(1, g_marks);
    ASSERT(firc_ifcheck_once(url_at(PORT, "/204"), NULL, 0, 2, NULL, &st, e, sizeof(e)));
    ASSERT_EQ_FMTm("the control is unmarked", 1, g_marks, "%d");
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    stop(&h);
    PASS();
}

static int break_marked(int fd, int level, int name, const void *val, socklen_t len) {
    if (level == SOL_SOCKET && name == SO_MARK) {
        int u = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        dup2(u, fd);
        close(u);
        return 0;
    }
    return setsockopt(fd, level, name, val, len);
}

TEST a_round_tries_the_control_once_and_only_for_failures(void) {
    harness_t h;
    ASSERT(start(&h));
    firc_sub_fetch_set_setsockopt_for_test(break_marked);
    firc_ifcheck_settings_t s = {.timeout_s = 2};
    snprintf(s.url, sizeof(s.url), "%s", url_at(PORT, "/204"));
    firc_ifcheck_job_t jobs[3] = {{"up0", 0x10000, 4}, {"up1", 0x20000, 5}, {"up2", 0, 6}};
    firc_ifcheck_result_t out[3];
    firc_ifcheck_round(&s, jobs, 3, NULL, out);
    ASSERT_FALSE(out[0].passed);
    ASSERT_FALSE(out[1].passed);
    ASSERT(out[2].passed);
    ASSERT_FALSE(out[0].control_failed);
    ASSERT_FALSE(out[1].control_failed);
    ASSERT(out[0].control_ran && out[1].control_ran);
    ASSERT_FALSEm("a pass needs no control", out[2].control_ran);
    ASSERT_EQ_FMT(4u, out[0].gen, "%u");
    ASSERT_EQ_FMT(5u, out[1].gen, "%u");
    ASSERT_EQ_FMT(6u, out[2].gen, "%u");
    ASSERT_STR_EQ("up1", out[1].iface);
    ASSERT_EQ_FMTm("the unmarked job and one control reached the server", 2, g_hits_204, "%d");
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    stop(&h);
    PASS();
}

TEST a_refused_mark_guards_the_round(void) {
    harness_t h;
    ASSERT(start(&h));
    firc_sub_fetch_set_setsockopt_for_test(record_mark);
    g_refuse_marks = true;
    firc_ifcheck_settings_t s = {.timeout_s = 2};
    snprintf(s.url, sizeof(s.url), "%s", url_at(PORT, "/204"));
    firc_ifcheck_job_t jobs[2] = {{"up0", 0x10000, 1}, {"up1", 0x20000, 2}};
    firc_ifcheck_result_t out[2];
    firc_ifcheck_round(&s, jobs, 2, NULL, out);
    ASSERT(out[0].control_failed && out[1].control_failed);
    ASSERT_FALSE(out[0].control_ran || out[1].control_ran);
    ASSERT_STR_EQ("the socket refused the check's mark", out[0].error);
    ASSERT_EQ_FMTm("a refused mark needs no control", 0, g_hits_204, "%d");
    g_refuse_marks = false;
    firc_sub_fetch_set_setsockopt_for_test(NULL);
    stop(&h);
    PASS();
}

TEST a_slow_entry_does_not_delay_the_others(void) {
    harness_t h;
    ASSERT(start(&h));
    firc_ifcheck_settings_t s = {.timeout_s = 2};
    snprintf(s.url, sizeof(s.url), "%s", url_at(18111, "/204"));
    firc_ifcheck_job_t jobs[4] = {{"up0", 0, 1}, {"up1", 0, 2}, {"up2", 0, 3}, {"up3", 0, 4}};
    firc_ifcheck_result_t out[4];
    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    firc_ifcheck_round(&s, jobs, 4, NULL, out);
    long ms = ms_since(&a);
    ASSERTm("four timeouts and a control run as two timeouts, not five", ms < 7000);
    stop(&h);
    PASS();
}

TEST a_round_whose_control_fails_marks_every_failure_guarded(void) {
    firc_ifcheck_settings_t s = {.timeout_s = 1};
    snprintf(s.url, sizeof(s.url), "%s", url_at(18112, "/204"));
    firc_ifcheck_job_t jobs[2] = {{"up0", 0, 1}, {"up1", 0, 2}};
    firc_ifcheck_result_t out[2];
    firc_ifcheck_round(&s, jobs, 2, NULL, out);
    ASSERT(out[0].control_failed && out[1].control_failed);
    ASSERT(out[0].control_ran && out[1].control_ran);
    ASSERT(out[0].error[0] != '\0');
    PASS();
}

TEST a_round_whose_host_does_not_resolve_is_guarded(void) {
    firc_ifcheck_settings_t s = {.timeout_s = 1, .upstream = "127.0.0.1", .upstream_port = 15398};
    snprintf(s.url, sizeof(s.url), "http://nowhere.test:%d/204", PORT);
    firc_ifcheck_job_t jobs[1] = {{"up0", 0x10000, 1}};
    firc_ifcheck_result_t out[1];
    firc_ifcheck_round(&s, jobs, 1, NULL, out);
    ASSERT(out[0].control_failed);
    ASSERT_FALSE(out[0].control_ran);
    ASSERT(strncmp(out[0].error, "the check's host does not resolve", 33) == 0);
    PASS();
}

typedef struct {
    int fd;
    _Atomic bool quit;
    _Atomic int queries;
    bool answer;
    pthread_t thread;
} stub_t;

static void *stub_run(void *ud) {
    stub_t *s = ud;
    static const uint8_t rr[16] = {0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                                   0x00, 0x3c, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01};
    while (!atomic_load(&s->quit)) {
        struct pollfd p = {.fd = s->fd, .events = POLLIN};
        if (poll(&p, 1, 50) <= 0) { continue; }
        uint8_t b[600];
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(s->fd, b, 512, 0, (struct sockaddr *)&from, &fl);
        if (n < 12) { continue; }
        atomic_fetch_add(&s->queries, 1);
        if (!s->answer || b[n - 4] != 0 || b[n - 3] != 1) { continue; }
        b[2] = 0x81;
        b[3] = 0x80;
        b[6] = 0;
        b[7] = 1;
        memcpy(b + n, rr, sizeof(rr));
        (void)sendto(s->fd, b, (size_t)n + sizeof(rr), 0, (struct sockaddr *)&from, fl);
    }
    return NULL;
}

static bool stub_start(stub_t *s, uint16_t port, bool answer) {
    memset(s, 0, sizeof(*s));
    atomic_init(&s->quit, false);
    atomic_init(&s->queries, 0);
    s->answer = answer;
    s->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (s->fd < 0 || bind(s->fd, (struct sockaddr *)&a, sizeof(a)) != 0) { return false; }
    return pthread_create(&s->thread, NULL, stub_run, s) == 0;
}

static void stub_stop(stub_t *s) {
    atomic_store(&s->quit, true);
    pthread_join(s->thread, NULL);
    close(s->fd);
}

TEST resolve_asks_the_upstream_for_an_a_record(void) {
    stub_t s;
    ASSERT(stub_start(&s, 15399, true));
    char a[64] = "";
    ASSERT_EQ(FIRC_OK, firc_ifcheck_resolve("127.0.0.1", 15399, "http://check.test/204", 1, a, sizeof a, NULL));
    ASSERT_STR_EQ("127.0.0.1", a);
    ASSERT_EQ(FIRC_OK, firc_ifcheck_resolve("127.0.0.1", 15399, "http://10.9.8.7:81/204", 1, a, sizeof a, NULL));
    ASSERT_STR_EQ("10.9.8.7", a);
    ASSERT_EQ_FMTm("a literal host asks nobody", 1, atomic_load(&s.queries), "%d");
    stub_stop(&s);

    stub_t mute;
    ASSERT(stub_start(&mute, 15399, false));
    _Atomic bool flag;
    atomic_init(&flag, false);
    raiser_t r = {&flag, 300};
    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, NULL, raise_later, &r));
    struct timespec at;
    clock_gettime(CLOCK_MONOTONIC, &at);
    firc_err_t err = firc_ifcheck_resolve("127.0.0.1", 15399, "http://check.test/204", 5, a, sizeof a, &flag);
    long ms = ms_since(&at);
    pthread_join(t, NULL);
    stub_stop(&mute);
    ASSERT(err != FIRC_OK);
    ASSERT_LTm("the teardown does not wait out the timeout", ms, 2500);
    PASS();
}

TEST the_settings_check_and_the_fetch_agree_on_every_url(void) {
    static const char *const urls[] = {"http://a/",        "https://a.b:8443/x?y", "HTTP://A/",  "ftp://a/",
                                       "http:///x",        "http://",              "http://a b/", "https://1.2.3.4/204",
                                       "http://a/#f",      "mailto:a@b",           "http:/x"};
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
        ASSERT_EQm(urls[i], firc_check_url_ok(urls[i]), firc_sub_url_is_supported(urls[i]));
    }
    ASSERT_FALSEm("the check route is IPv4 only", firc_check_url_ok("https://[::1]/204"));
    ASSERTm("a list may still name an IPv6 host", firc_sub_url_is_supported("https://[::1]/204"));
    PASS();
}

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int count;
    firc_ifcheck_result_t first;
} got_t;

static void done(void *ud, const firc_ifcheck_result_t *r, size_t n) {
    got_t *g = ud;
    pthread_mutex_lock(&g->mu);
    if (g->count == 0 && n > 0) { g->first = r[0]; }
    g->count++;
    pthread_cond_signal(&g->cv);
    pthread_mutex_unlock(&g->mu);
}

static int got_count(got_t *g) {
    pthread_mutex_lock(&g->mu);
    int c = g->count;
    pthread_mutex_unlock(&g->mu);
    return c;
}

typedef struct {
    got_t *got;
    firc_ifcheck_t *c;
    bool ready, freed;
    firc_err_t err;
} owner_t;

static void owner_signal(owner_t *o, bool *flag) {
    pthread_mutex_lock(&o->got->mu);
    *flag = true;
    pthread_cond_broadcast(&o->got->cv);
    pthread_mutex_unlock(&o->got->mu);
}

static void owner_wait(owner_t *o, const bool *flag) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 5;
    pthread_mutex_lock(&o->got->mu);
    while (!*flag) {
        if (pthread_cond_timedwait(&o->got->cv, &o->got->mu, &until) != 0) { break; }
    }
    pthread_mutex_unlock(&o->got->mu);
}

static void owner_setup(firc_loop_t *loop, void *ud) {
    owner_t *o = ud;
    o->c = firc_ifcheck_new(loop, done, o->got);
    o->err = o->c == NULL ? FIRC_ERR_NOMEM : firc_ifcheck_start(o->c);
    if (o->err == FIRC_OK) {
        firc_ifcheck_settings_t s = {.timeout_s = 2};
        snprintf(s.url, sizeof(s.url), "http://127.0.0.1:%d/204", PORT);
        firc_ifcheck_configure(o->c, &s);
        o->err = firc_ifcheck_queue(o->c, "up0", 0, 7);
    }
    owner_signal(o, &o->ready);
}

static void owner_teardown(firc_loop_t *loop, void *ud) {
    (void)loop;
    owner_t *o = ud;
    (void)firc_ifcheck_queue(o->c, "up1", 0, 8);
    firc_ifcheck_free(o->c);
    owner_signal(o, &o->freed);
}

TEST the_thread_posts_a_round_to_the_loop(void) {
    harness_t h;
    ASSERT(start(&h));
    got_t got = {.mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER};
    owner_t o = {.got = &got};
    ASSERT_EQ(FIRC_OK, firc_loop_post(h.loop, owner_setup, &o));
    owner_wait(&o, &o.ready);
    ASSERT_EQ(FIRC_OK, o.err);
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += 5;
    pthread_mutex_lock(&got.mu);
    while (got.count == 0) {
        if (pthread_cond_timedwait(&got.cv, &got.mu, &until) != 0) { break; }
    }
    int count = got.count;
    firc_ifcheck_result_t first = got.first;
    pthread_mutex_unlock(&got.mu);
    ASSERT_EQ(1, count);
    ASSERT_STR_EQ("up0", first.iface);
    ASSERT_EQ_FMTm("the job's generation comes back with it", 7u, first.gen, "%u");
    ASSERT(first.passed);
    ASSERT_EQ(204, first.status);
    ASSERT_EQ(FIRC_OK, firc_loop_post(h.loop, owner_teardown, &o));
    owner_wait(&o, &o.freed);
    ASSERT(o.freed);
    struct timespec ts = {0, 100 * 1000000L};
    nanosleep(&ts, NULL);
    ASSERT_EQ_FMTm("no done runs after free", 1, got_count(&got), "%d");
    stop(&h);
    PASS();
}

TEST a_full_queue_refuses_the_seventeenth_job(void) {
    got_t got = {.mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER};
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_ifcheck_t *c = firc_ifcheck_new(loop, done, &got);
    ASSERT(c != NULL);
    for (int i = 0; i < FIRC_IFCHECK_BATCH; i++) { ASSERT_EQ(FIRC_OK, firc_ifcheck_queue(c, "up0", 0, 1)); }
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_ifcheck_queue(c, "up0", 0, 1));
    firc_ifcheck_free(c);
    firc_loop_destroy(loop);
    PASS();
}

TEST a_batch_still_queued_at_loop_destroy_is_dropped_without_a_leak(void) {
    got_t got = {.mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER};
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_ifcheck_t *c = firc_ifcheck_new(loop, done, &got);
    ASSERT(c != NULL);
    firc_ifcheck_settings_t s = {.timeout_s = 1};
    snprintf(s.url, sizeof(s.url), "%s", url_at(18112, "/204"));
    firc_ifcheck_configure(c, &s);
    ASSERT_EQ(FIRC_OK, firc_ifcheck_start(c));
    ASSERT_EQ(FIRC_OK, firc_ifcheck_queue(c, "up0", 0, 1));
    struct timespec ts = {0, 300 * 1000000L};
    nanosleep(&ts, NULL);
    firc_ifcheck_free(c);
    firc_loop_destroy(loop);
    ASSERT_EQ_FMTm("a dropped batch never reaches done", 0, got_count(&got), "%d");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    firc_sub_fetch_global_init();
    GREATEST_MAIN_BEGIN();
    RUN_TEST(only_a_204_passes);
    RUN_TEST(a_timeout_and_a_refusal_fail_with_libcurls_words);
    RUN_TEST(a_raised_stop_ends_a_check_inside_curl);
    RUN_TEST(the_mark_is_on_the_socket);
    RUN_TEST(a_round_tries_the_control_once_and_only_for_failures);
    RUN_TEST(a_refused_mark_guards_the_round);
    RUN_TEST(a_slow_entry_does_not_delay_the_others);
    RUN_TEST(a_round_whose_control_fails_marks_every_failure_guarded);
    RUN_TEST(a_round_whose_host_does_not_resolve_is_guarded);
    RUN_TEST(resolve_asks_the_upstream_for_an_a_record);
    RUN_TEST(the_settings_check_and_the_fetch_agree_on_every_url);
    RUN_TEST(the_thread_posts_a_round_to_the_loop);
    RUN_TEST(a_full_queue_refuses_the_seventeenth_job);
    RUN_TEST(a_batch_still_queued_at_loop_destroy_is_dropped_without_a_leak);
    GREATEST_MAIN_END();
}

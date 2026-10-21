#include "greatest.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/httpd.h"
#include "firc/loop.h"
#include "firc/release.h"
#include "firc/sub_fetch.h"
#include "firc/system.h"
#include "firc/update.h"
#include "firc/update_api.h"
#include "firc/update_handoff.h"

#define PAYLOAD_LEN 1000000
#define IPK_NAME "firc_0.3.0-1_entware_mipsel-3.4_kn.ipk"
#define PAYLOAD_SHA "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
#define INTERRUPTED \
    "the last install did not finish: its installer is gone and left no result; see the system log and opkg status firc"
#define FAKE "tests/unit/fixtures/fake_opkg.sh"
#define FAKE_BIN "tests/unit/fixtures/bin"

enum mode { M_FIXTURE, M_LIMITED, M_HOLD, M_INSTALL, M_NO_DIGEST };

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_hits;
static enum mode g_mode;
static bool g_release;
static bool g_stop;
static char *g_fixture;
static size_t g_fixture_len;
static bool g_dl_hold;
static bool g_dl_go;
static int g_dl_hits;
static bool g_verify_hold;
static bool g_verify_go;
static bool g_verifying;
static char *g_payload;
static char g_dl_prefix[96];
static char g_install_json[2048];
static char g_no_digest_json[2048];
static char g_opkg[PATH_MAX];
static char g_path[8192];

typedef struct {
    int fd;
    pthread_t thread;
    uint16_t port;
    bool up;
} stub_t;

static stub_t g_stub;
static char g_api[96];

static void send_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n <= 0) { return; }
        buf += n;
        len -= (size_t)n;
    }
}

static bool read_head(int fd) {
    char buf[4096];
    size_t got = 0;
    while (got < sizeof buf - 1) {
        ssize_t n = recv(fd, buf + got, sizeof buf - 1 - got, 0);
        if (n <= 0) { return false; }
        got += (size_t)n;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n") != NULL) {
            buf[strcspn(buf, "\r")] = 0;
            return strstr(buf, "/releases/download/") != NULL;
        }
    }
    return false;
}

static void serve_download(int fd) {
    char head[160];
    int n = snprintf(head, sizeof head, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
                     PAYLOAD_LEN);
    send_all(fd, head, (size_t)n);
    pthread_mutex_lock(&g_mu);
    g_dl_hits++;
    pthread_cond_broadcast(&g_cv);
    while (g_dl_hold && !g_dl_go && !g_stop) { pthread_cond_wait(&g_cv, &g_mu); }
    bool stop = g_stop;
    pthread_mutex_unlock(&g_mu);
    if (!stop) { send_all(fd, g_payload, PAYLOAD_LEN); }
}

static const char *json_for(enum mode m, size_t *len) {
    const char *j = m == M_INSTALL ? g_install_json : m == M_NO_DIGEST ? g_no_digest_json : g_fixture;
    *len = m == M_INSTALL || m == M_NO_DIGEST ? strlen(j) : g_fixture_len;
    return j;
}

static void answer(int fd, enum mode m) {
    char head[256];
    if (m == M_LIMITED) {
        int n = snprintf(head, sizeof head,
                         "HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nX-RateLimit-Reset: 1791831689\r\n"
                         "Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        send_all(fd, head, (size_t)n);
        return;
    }
    size_t len = 0;
    const char *body = json_for(m, &len);
    int n = snprintf(head, sizeof head,
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
                     len);
    send_all(fd, head, (size_t)n);
    send_all(fd, body, len);
}

static void *stub_thread(void *ud) {
    stub_t *s = ud;
    for (;;) {
        int c = accept(s->fd, NULL, NULL);
        if (c < 0) {
            pthread_mutex_lock(&g_mu);
            bool stop = g_stop;
            pthread_mutex_unlock(&g_mu);
            if (stop) { return NULL; }
            continue;
        }
        if (read_head(c)) {
            serve_download(c);
            close(c);
            continue;
        }
        pthread_mutex_lock(&g_mu);
        g_hits++;
        enum mode m = g_mode;
        pthread_cond_broadcast(&g_cv);
        while (m == M_HOLD && !g_release && !g_stop) { pthread_cond_wait(&g_cv, &g_mu); }
        bool stop = g_stop;
        pthread_mutex_unlock(&g_mu);
        if (!stop) { answer(c, m == M_HOLD ? M_FIXTURE : m); }
        close(c);
    }
}

static bool stub_start(void) {
    g_stub.fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof sa;
    if (g_stub.fd < 0 || bind(g_stub.fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        getsockname(g_stub.fd, (struct sockaddr *)&sa, &sl) != 0 || listen(g_stub.fd, 16) != 0) {
        return false;
    }
    g_stub.port = ntohs(sa.sin_port);
    snprintf(g_api, sizeof g_api, "http://127.0.0.1:%u/repos/hoaxisr/firc/releases/latest", (unsigned)g_stub.port);
    snprintf(g_dl_prefix, sizeof g_dl_prefix, "http://127.0.0.1:%u/hoaxisr/firc/releases/download/",
             (unsigned)g_stub.port);
    for (int digest = 0; digest < 2; digest++) {
        snprintf(digest ? g_install_json : g_no_digest_json, sizeof g_install_json,
                 "{\"tag_name\":\"0.3.0\",\"published_at\":\"2026-10-13T08:00:00Z\",\"body\":\"- notes\","
                 "\"draft\":false,\"prerelease\":false,\"assets\":[{\"name\":\"%s\",\"state\":\"uploaded\","
                 "\"size\":%d,%s\"browser_download_url\":\"%s0.3.0/%s\"}]}",
                 IPK_NAME, PAYLOAD_LEN, digest ? "\"digest\":\"sha256:" PAYLOAD_SHA "\"," : "", g_dl_prefix,
                 IPK_NAME);
    }
    pthread_mutex_lock(&g_mu);
    g_stop = false;
    pthread_mutex_unlock(&g_mu);
    if (pthread_create(&g_stub.thread, NULL, stub_thread, &g_stub) != 0) { return false; }
    g_stub.up = true;
    return true;
}

static void stub_stop(void) {
    if (!g_stub.up) { return; }
    pthread_mutex_lock(&g_mu);
    g_stop = true;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
    shutdown(g_stub.fd, SHUT_RDWR);
    pthread_join(g_stub.thread, NULL);
    close(g_stub.fd);
    g_stub.up = false;
}

static void stub_release(void) {
    pthread_mutex_lock(&g_mu);
    g_release = true;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static void set_mode(enum mode m) {
    pthread_mutex_lock(&g_mu);
    g_mode = m;
    g_release = false;
    g_hits = 0;
    pthread_mutex_unlock(&g_mu);
}

static void set_holds(bool download, bool verify) {
    pthread_mutex_lock(&g_mu);
    g_dl_hold = download;
    g_dl_go = false;
    g_dl_hits = 0;
    g_verify_hold = verify;
    g_verify_go = false;
    g_verifying = false;
    pthread_mutex_unlock(&g_mu);
}

static void dl_go(void) {
    pthread_mutex_lock(&g_mu);
    g_dl_go = true;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static void verify_go(void) {
    pthread_mutex_lock(&g_mu);
    g_verify_go = true;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static int dl_hits(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_dl_hits;
    pthread_mutex_unlock(&g_mu);
    return n;
}

static void hold_verified(void *ud) {
    (void)ud;
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);
    end.tv_sec += 10;
    pthread_mutex_lock(&g_mu);
    g_verifying = true;
    pthread_cond_broadcast(&g_cv);
    while (g_verify_hold && !g_verify_go && !g_stop) {
        if (pthread_cond_timedwait(&g_cv, &g_mu, &end) != 0) { break; }
    }
    pthread_mutex_unlock(&g_mu);
}

static bool hits_reach(int n, int ms) {
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);
    end.tv_sec += ms / 1000;
    end.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (end.tv_nsec >= 1000000000L) {
        end.tv_sec++;
        end.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&g_mu);
    while (g_hits < n) {
        if (pthread_cond_timedwait(&g_cv, &g_mu, &end) != 0) { break; }
    }
    bool ok = g_hits >= n;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

static int hits(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_hits;
    pthread_mutex_unlock(&g_mu);
    return n;
}

static bool loopback_ok(void *ud, const char *url) {
    (void)ud;
    return strncmp(url, "http://127.0.0.1:", 17) == 0;
}

typedef struct {
    firc_loop_t *loop;
    firc_httpd_t *http;
    firc_update_t *u;
    firc_update_api_ctx_t ctx;
    firc_system_ctx_t sys;
    pthread_t thread;
    bool running;
    char dir[64];
    char sock[96];
    char udir[96];
    char hold[96];
    char script[96];
} daemon_t;

typedef struct {
    const char *version, *target;
    uint64_t (*free_bytes)(const char *dir);
    void (*verified)(void *ud);
} dopts_t;

static daemon_t *g_d;

static void *loop_thread(void *ud) {
    firc_loop_run(((daemon_t *)ud)->loop);
    return NULL;
}

static bool daemon_up_with(daemon_t *d, const char *api, const char *prefix, const char *version, const char *target,
                           uint32_t revision, const dopts_t *o) {
    memset(d, 0, sizeof *d);
    g_d = d;
    snprintf(d->dir, sizeof d->dir, "/tmp/firc_update_api_XXXXXX");
    if (mkdtemp(d->dir) == NULL) { return false; }
    snprintf(d->sock, sizeof d->sock, "%s/api.sock", d->dir);
    snprintf(d->udir, sizeof d->udir, "%s/update", d->dir);
    snprintf(d->hold, sizeof d->hold, "%s/hold", d->dir);
    snprintf(d->script, sizeof d->script, "%s/S99stand-in", d->dir);
    FILE *fp = fopen(d->script, "w");
    if (fp == NULL) { return false; }
    fputs("#!/bin/sh\n: > \"$(dirname \"$0\")/restarted\"\n", fp);
    fclose(fp);
    chmod(d->script, 0755);
    if (firc_loop_create(&d->loop) != FIRC_OK || firc_httpd_create(d->loop, &d->http) != FIRC_OK) { return false; }
    firc_update_deps_t deps = {
        .loop = d->loop,
        .dir = d->udir,
        .api_url = api,
        .download_prefix = prefix,
        .version = version,
        .target = target,
        .sh = "/bin/sh",
        .opkg = g_opkg,
        .revision = revision,
        .url_ok = loopback_ok,
        .checked = firc_update_api_checked,
        .ud = &d->ctx,
        .free_bytes = o != NULL ? o->free_bytes : NULL,
        .verified = o != NULL ? o->verified : NULL,
    };
    d->u = firc_update_new(&deps);
    if (d->u == NULL) { return false; }
    d->ctx.update = d->u;
    d->ctx.sys = &d->sys;
    d->sys.update = d->u;
    d->sys.init_script = d->script;
    d->sys.restart_timeout_ms = 60000;
    firc_update_register_routes(d->http, &d->ctx);
    firc_settings_register_routes(d->http, &d->sys);
    if (firc_httpd_listen_unix(d->http, d->sock) != FIRC_OK || firc_update_start(d->u) != FIRC_OK) { return false; }
    if (pthread_create(&d->thread, NULL, loop_thread, d) != 0) { return false; }
    d->running = true;
    return true;
}

static bool daemon_up(daemon_t *d, const char *api, const char *version, const char *target, uint32_t revision) {
    return daemon_up_with(d, api, FIRC_UPDATE_DOWNLOAD_PREFIX, version, target, revision, NULL);
}

static bool installer_up(daemon_t *d, const dopts_t *o) {
    const char *version = o != NULL && o->version != NULL ? o->version : "0.1.3";
    const char *target = o != NULL && o->target != NULL ? o->target : "mipsel-3.4_kn";
    if (!daemon_up_with(d, g_api, g_dl_prefix, version, target, 1, o)) { return false; }
    return setenv("FAKE_OPKG_HOLD", d->hold, 1) == 0;
}

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void clear_update_dir(daemon_t *d) {
    FILE *fp = fopen(d->hold, "w");
    if (fp != NULL) { fclose(fp); }
    for (int i = 0; i < 1000; i++) {
        firc_update_marker_t m = firc_update_marker_read(d->udir, NULL, 0, NULL);
        if (m == FIRC_UPDATE_MARKER_NONE || m == FIRC_UPDATE_MARKER_STALE) { break; }
        sleep_ms(10);
    }
    DIR *dir = opendir(d->udir);
    if (dir != NULL) {
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            if (de->d_name[0] != '.') { (void)unlinkat(dirfd(dir), de->d_name, 0); }
        }
        closedir(dir);
    }
    rmdir(d->udir);
    unlink(d->hold);
    unlink(d->script);
    char ran[128];
    snprintf(ran, sizeof ran, "%s/restarted", d->dir);
    unlink(ran);
    unsetenv("FAKE_OPKG_HOLD");
    unsetenv("FAKE_OPKG_RC");
}

static bool daemon_up_without_checker(daemon_t *d) {
    memset(d, 0, sizeof *d);
    g_d = d;
    snprintf(d->dir, sizeof d->dir, "/tmp/firc_update_api_XXXXXX");
    if (mkdtemp(d->dir) == NULL) { return false; }
    snprintf(d->sock, sizeof d->sock, "%s/api.sock", d->dir);
    if (firc_loop_create(&d->loop) != FIRC_OK || firc_httpd_create(d->loop, &d->http) != FIRC_OK) { return false; }
    firc_update_register_routes(d->http, &d->ctx);
    if (firc_httpd_listen_unix(d->http, d->sock) != FIRC_OK) { return false; }
    if (pthread_create(&d->thread, NULL, loop_thread, d) != 0) { return false; }
    d->running = true;
    return true;
}

static void daemon_down(daemon_t *d) {
    if (d->running) {
        firc_loop_stop(d->loop);
        pthread_join(d->thread, NULL);
        d->running = false;
    }
    firc_update_api_close(&d->ctx);
    firc_update_free(d->u);
    d->u = NULL;
    firc_httpd_destroy(d->http);
    d->http = NULL;
    if (d->loop != NULL) { firc_loop_destroy(d->loop); }
    d->loop = NULL;
    clear_update_dir(d);
    unlink(d->sock);
    rmdir(d->dir);
    g_d = NULL;
}

static int connect_unix(const daemon_t *d) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", d->sock);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        if (fd >= 0) { close(fd); }
        return -1;
    }
    struct timeval tv = {8, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

static int send_request_body(const daemon_t *d, const char *method, const char *path, const char *body) {
    int fd = connect_unix(d);
    if (fd < 0) { return -1; }
    char req[1024];
    int n = snprintf(req, sizeof req, "%s %s HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     method, path, strlen(body), body);
    send_all(fd, req, (size_t)n);
    return fd;
}

static int send_request(const daemon_t *d, const char *method, const char *path) {
    return send_request_body(d, method, path, "");
}

static int read_response(int fd, cJSON **body) {
    char buf[65536];
    size_t got = 0;
    for (;;) {
        ssize_t n = recv(fd, buf + got, sizeof buf - 1 - got, 0);
        if (n <= 0) { break; }
        got += (size_t)n;
        if (got == sizeof buf - 1) { break; }
    }
    close(fd);
    buf[got] = 0;
    int status = -1;
    if (sscanf(buf, "HTTP/1.1 %d", &status) != 1) { return -1; }
    const char *b = strstr(buf, "\r\n\r\n");
    if (body != NULL) { *body = b != NULL ? cJSON_Parse(b + 4) : NULL; }
    return status;
}

static int request(const daemon_t *d, const char *method, const char *path, cJSON **body) {
    int fd = send_request(d, method, path);
    if (fd < 0) { return -1; }
    return read_response(fd, body);
}

static int install(const daemon_t *d, const char *body, cJSON **out) {
    int fd = send_request_body(d, "POST", "/api/v1/system/update/install", body);
    if (fd < 0) { return -1; }
    return read_response(fd, out);
}

static const cJSON *at(const cJSON *o, const char *k) { return cJSON_GetObjectItemCaseSensitive(o, k); }

static const char *str_at(const cJSON *o, const char *k) {
    const cJSON *v = at(o, k);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

static double num_at(const cJSON *o, const char *k) {
    const cJSON *v = at(o, k);
    return cJSON_IsNumber(v) ? v->valuedouble : -12345.0;
}

static void setup(void *ud) {
    (void)ud;
    set_mode(M_FIXTURE);
    set_holds(false, false);
    (void)stub_start();
}

static void teardown(void *ud) {
    (void)ud;
    stub_release();
    verify_go();
    if (g_d != NULL) { daemon_down(g_d); }
    stub_stop();
    set_holds(false, false);
}

/* Catches revision or target hard-coded, or canInstall true without a target. */
TEST get_reports_the_build_and_why_it_cannot_install(void) {
    static daemon_t d;
    ASSERT(daemon_up(&d, g_api, "0.2.0", "", 3));
    cJSON *b = NULL;
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", &b));
    ASSERT(b != NULL);
    const cJSON *inst = at(b, "installed");
    ASSERT(cJSON_IsObject(inst));
    ASSERT_EQ(3, cJSON_GetArraySize(inst));
    ASSERT_STR_EQ("0.2.0", str_at(inst, "version"));
    ASSERT_EQ(3, (int)num_at(inst, "revision"));
    ASSERT_STR_EQ("", str_at(inst, "target"));
    ASSERT(cJSON_IsFalse(at(b, "canInstall")));
    ASSERT_STR_EQ("no-target", str_at(b, "reason"));
    ASSERT(cJSON_IsNull(at(b, "check")));
    ASSERT_STR_EQ("idle", str_at(b, "state"));
    ASSERT(cJSON_IsNull(at(b, "progress")));
    ASSERT(cJSON_IsNull(at(b, "error")));
    ASSERT(cJSON_IsNull(at(b, "result")));
    ASSERT_EQ(0, hits());
    cJSON_Delete(b);
    PASS();
}

/* Catches a check answered before it ran, or a body that is not the refreshed status. */
TEST a_check_answers_the_refreshed_status(void) {
    static daemon_t d;
    ASSERT(daemon_up(&d, g_api, "0.1.3", "mipsel-3.4_kn", 1));
    cJSON *b = NULL;
    ASSERT_EQ(200, request(&d, "POST", "/api/v1/system/update/check", &b));
    ASSERT(b != NULL);
    ASSERT_EQ(1, hits());
    ASSERT(cJSON_IsTrue(at(b, "canInstall")));
    ASSERT(cJSON_IsNull(at(b, "reason")));
    ASSERT_STR_EQ("idle", str_at(b, "state"));
    const cJSON *c = at(b, "check");
    ASSERT(cJSON_IsObject(c));
    double age = num_at(c, "ageS");
    ASSERT(age == 0.0 || age == 1.0);
    double now = (double)time(NULL);
    ASSERT(num_at(c, "checkedAt") >= now - 5 && num_at(c, "checkedAt") <= now);
    ASSERT(cJSON_IsTrue(at(c, "newer")));
    ASSERT(cJSON_IsTrue(at(c, "installable")));
    ASSERT(cJSON_IsNull(at(c, "reason")));
    ASSERT(cJSON_IsNull(at(c, "error")));
    const cJSON *l = at(c, "latest");
    ASSERT(cJSON_IsObject(l));
    ASSERT_STR_EQ("0.2.0", str_at(l, "version"));
    ASSERT_EQ(1, (int)num_at(l, "revision"));
    ASSERT_STR_EQ("0.2.0", str_at(l, "tag"));
    ASSERT_STR_EQ("2026-10-07T20:27:40Z", str_at(l, "publishedAt"));
    ASSERT(str_at(l, "notes") != NULL);
    const cJSON *a = at(l, "asset");
    ASSERT(cJSON_IsObject(a));
    ASSERT_STR_EQ("firc_0.2.0-1_entware_mipsel-3.4_kn.ipk", str_at(a, "name"));
    ASSERT_EQ(829104, (int)num_at(a, "size"));
    cJSON_Delete(b);
    PASS();
}

/* Catches a rate limit answered as 502, or without GitHub's reset time. */
TEST a_rate_limited_check_is_429_with_the_reset_time(void) {
    static daemon_t d;
    set_mode(M_LIMITED);
    ASSERT(daemon_up(&d, g_api, "0.1.3", "mipsel-3.4_kn", 1));
    cJSON *b = NULL;
    ASSERT_EQ(429, request(&d, "POST", "/api/v1/system/update/check", &b));
    ASSERT(b != NULL);
    ASSERT_EQ(1791831689.0, num_at(b, "resetAt"));
    ASSERT_STR_EQ("GitHub refuses more checks from this address until 2026-10-12T19:01:29Z", str_at(b, "error"));
    cJSON_Delete(b);
    PASS();
}

/* Catches libcurl's message replaced by the error code's generic text, or a refusal answered 200. */
TEST an_unreachable_github_is_502_with_libcurls_words(void) {
    static daemon_t d;
    int hole = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof sa;
    ASSERT(hole >= 0);
    ASSERT_EQ(0, bind(hole, (struct sockaddr *)&sa, sizeof sa));
    ASSERT_EQ(0, getsockname(hole, (struct sockaddr *)&sa, &sl));
    char api[96];
    char port[8];
    snprintf(api, sizeof api, "http://127.0.0.1:%u/repos/hoaxisr/firc/releases/latest", (unsigned)ntohs(sa.sin_port));
    snprintf(port, sizeof port, "%u", (unsigned)ntohs(sa.sin_port));
    bool up = daemon_up(&d, api, "0.1.3", "mipsel-3.4_kn", 1);
    cJSON *b = NULL;
    int status = up ? request(&d, "POST", "/api/v1/system/update/check", &b) : -1;
    close(hole);
    ASSERT(up);
    ASSERT_EQ(502, status);
    const char *e = str_at(b, "error");
    ASSERT(e != NULL);
    ASSERT(e[0] != '\0');
    ASSERT(strcmp(e, "I/O error") != 0);
    ASSERT(strcmp(e, firc_err_str(FIRC_ERR_IO)) != 0);
    ASSERT(strstr(e, port) != NULL);
    cJSON_Delete(b);
    PASS();
}

/* Catches a waiter answered after its client left (use after free under ASan), or a daemon that stops answering. */
TEST a_client_that_leaves_mid_check_costs_nothing(void) {
    static daemon_t d;
    set_mode(M_HOLD);
    ASSERT(daemon_up(&d, g_api, "0.1.3", "mipsel-3.4_kn", 1));
    int fd = send_request(&d, "POST", "/api/v1/system/update/check");
    ASSERT(fd >= 0);
    ASSERT(hits_reach(1, 5000));
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", NULL));
    close(fd);
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", NULL));
    stub_release();
    cJSON *b = NULL;
    bool checked = false;
    for (int i = 0; i < 100 && !checked; i++) {
        cJSON_Delete(b);
        b = NULL;
        ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", &b));
        const char *st = str_at(b, "state");
        checked = cJSON_IsObject(at(b, "check")) && st != NULL && strcmp(st, "idle") == 0;
        if (!checked) {
            struct timespec ts = {0, 50 * 1000000L};
            nanosleep(&ts, NULL);
        }
    }
    ASSERT(checked);
    ASSERT_STR_EQ("0.2.0", str_at(at(at(b, "check"), "latest"), "version"));
    cJSON_Delete(b);
    PASS();
}

/* Catches a waiting check leaked, or left open, when the daemon stops mid-check. */
TEST waiting_checks_end_when_the_daemon_stops(void) {
    static daemon_t d;
    set_mode(M_HOLD);
    ASSERT(daemon_up(&d, g_api, "0.1.3", "mipsel-3.4_kn", 1));
    int fd = send_request(&d, "POST", "/api/v1/system/update/check");
    ASSERT(fd >= 0);
    ASSERT(hits_reach(1, 5000));
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", NULL));
    firc_loop_stop(d.loop);
    pthread_join(d.thread, NULL);
    d.running = false;
    firc_update_api_close(&d.ctx);
    ASSERT_EQ(0, (int)d.ctx.n_waiting);
    char c;
    ASSERT_EQ(0, (int)recv(fd, &c, 1, 0));
    close(fd);
    daemon_down(&d);
    PASS();
}

/* Catches an unbounded list of waiting checks, or the ninth turned away with anything but 503. */
TEST a_ninth_waiting_check_is_turned_away(void) {
    static daemon_t d;
    set_mode(M_HOLD);
    ASSERT(daemon_up(&d, g_api, "0.1.3", "mipsel-3.4_kn", 1));
    int fds[FIRC_UPDATE_API_WAITING_MAX];
    for (int i = 0; i < FIRC_UPDATE_API_WAITING_MAX; i++) {
        fds[i] = send_request(&d, "POST", "/api/v1/system/update/check");
        ASSERT(fds[i] >= 0);
    }
    ASSERT(hits_reach(1, 5000));
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", NULL));
    cJSON *b = NULL;
    ASSERT_EQ(503, request(&d, "POST", "/api/v1/system/update/check", &b));
    ASSERT_STR_EQ("too many checks waiting", str_at(b, "error"));
    cJSON_Delete(b);
    stub_release();
    int ok = 0;
    for (int i = 0; i < FIRC_UPDATE_API_WAITING_MAX; i++) { ok += read_response(fds[i], NULL) == 200; }
    ASSERT_EQ(FIRC_UPDATE_API_WAITING_MAX, ok);
    ASSERT_EQ(1, hits());
    PASS();
}

/* Catches a daemon with no checker crashing on a status request instead of answering 503. */
TEST a_status_without_a_checker_is_503(void) {
    static daemon_t d;
    ASSERT(daemon_up_without_checker(&d));
    cJSON *b = NULL;
    ASSERT_EQ(503, request(&d, "GET", "/api/v1/system/update", &b));
    ASSERT_STR_EQ("the update checker is not running", str_at(b, "error"));
    cJSON_Delete(b);
    PASS();
}

/* Catches a check asked of a daemon with no checker crashing, or waiting forever, instead of answering 503. */
TEST a_check_without_a_checker_is_503(void) {
    static daemon_t d;
    ASSERT(daemon_up_without_checker(&d));
    cJSON *b = NULL;
    ASSERT_EQ(503, request(&d, "POST", "/api/v1/system/update/check", &b));
    ASSERT_STR_EQ("the update checker is not running", str_at(b, "error"));
    ASSERT_EQ(0, (int)d.ctx.n_waiting);
    ASSERT_EQ(0, hits());
    cJSON_Delete(b);
    PASS();
}


static bool state_reached(const daemon_t *d, const char *want, cJSON **out) {
    for (int i = 0; i < 500; i++) {
        cJSON *b = NULL;
        if (request(d, "GET", "/api/v1/system/update", &b) == 200) {
            const char *st = str_at(b, "state");
            if (st != NULL && strcmp(st, want) == 0) {
                if (out != NULL) {
                    *out = b;
                } else {
                    cJSON_Delete(b);
                }
                return true;
            }
        }
        cJSON_Delete(b);
        sleep_ms(10);
    }
    return false;
}

static bool idle_with_result(const daemon_t *d, cJSON **out) {
    for (int i = 0; i < 500; i++) {
        cJSON *b = NULL;
        if (state_reached(d, "idle", &b) && cJSON_IsObject(at(b, "result"))) {
            *out = b;
            return true;
        }
        cJSON_Delete(b);
        sleep_ms(10);
    }
    return false;
}

static bool checked(const daemon_t *d, enum mode m) {
    set_mode(m);
    return request(d, "POST", "/api/v1/system/update/check", NULL) == 200;
}

static bool error_is(const cJSON *b, const char *want) {
    const char *e = str_at(b, "error");
    return e != NULL && strcmp(e, want) == 0;
}

static uint64_t one_byte_free(const char *dir) {
    (void)dir;
    return 1;
}

static void write_file(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) { return; }
    fputs(text, fp);
    fclose(fp);
}

static bool make_dir(const char *path) { return mkdir(path, 0700) == 0; }

static void write_marker(const daemon_t *d, pid_t pid, uint64_t start) {
    char path[160], text[160];
    snprintf(path, sizeof path, "%s/installing", d->udir);
    snprintf(text, sizeof text, "0.3.0 %lld\n%ld %llu\n", (long long)time(NULL), (long)pid, (unsigned long long)start);
    write_file(path, text);
}

static pid_t sleeper(void) {
    pid_t pid = fork();
    if (pid == 0) {
        for (;;) { pause(); }
    }
    return pid;
}

static void reap(pid_t pid) {
    if (pid <= 0) { return; }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

/* Catches the 202 body naming the wrong thing, or the GET not following the job through to opkg's result. */
TEST an_install_answers_202_and_the_status_moves_to_installing(void) {
    static daemon_t d;
    set_holds(true, true);
    ASSERT(installer_up(&d, &(dopts_t){.verified = hold_verified}));
    ASSERT(checked(&d, M_INSTALL));
    cJSON *b = NULL;
    ASSERT_EQ(202, install(&d, "{\"version\":\"0.3.0\"}", &b));
    ASSERT(b != NULL);
    ASSERT_EQ(3, cJSON_GetArraySize(b));
    ASSERT_STR_EQ("0.3.0", str_at(b, "version"));
    ASSERT_STR_EQ(IPK_NAME, str_at(b, "asset"));
    ASSERT_EQ(PAYLOAD_LEN, (int)num_at(b, "size"));
    cJSON_Delete(b);
    b = NULL;
    ASSERT(state_reached(&d, "downloading", &b));
    ASSERT_EQ(PAYLOAD_LEN, (int)num_at(at(b, "progress"), "total"));
    ASSERT(cJSON_IsNull(at(b, "result")));
    cJSON_Delete(b);
    dl_go();
    ASSERT(state_reached(&d, "verifying", NULL));
    verify_go();
    b = NULL;
    ASSERT(state_reached(&d, "installing", &b));
    ASSERT(cJSON_IsNull(at(b, "progress")));
    cJSON_Delete(b);
    write_file(d.hold, "");
    b = NULL;
    ASSERT(idle_with_result(&d, &b));
    const cJSON *r = at(b, "result");
    ASSERT_EQ(4, cJSON_GetArraySize(r));
    ASSERT_STR_EQ("0.3.0", str_at(r, "version"));
    ASSERT_EQ(0, (int)num_at(r, "opkgExit"));
    ASSERT_STR_EQ("Installing firc (0.3.0-1) to root...\nopkg: an error on stderr\n", str_at(r, "log"));
    double now = (double)time(NULL);
    ASSERT(num_at(r, "finishedAt") >= now - 10 && num_at(r, "finishedAt") <= now);
    ASSERT(cJSON_IsNull(at(b, "error")));
    cJSON_Delete(b);
    PASS();
}

static enum greatest_test_res refused(const daemon_t *d, const char *body, int want_status, const char *want_error,
                                      const char *want_reason) {
    cJSON *b = NULL;
    int status = install(d, body, &b);
    ASSERT_EQm(want_error, want_status, status);
    ASSERT(b != NULL);
    ASSERT_STR_EQ(want_error, str_at(b, "error"));
    if (want_reason != NULL) {
        ASSERT_STR_EQ(want_reason, str_at(b, "reason"));
        ASSERT_EQ(2, cJSON_GetArraySize(b));
    } else {
        ASSERT_EQ(1, cJSON_GetArraySize(b));
    }
    cJSON_Delete(b);
    PASS();
}

/* Catches a status mapping swapped or a refusal text changed: the WebUI branches on 409 and 507. */
TEST each_refusal_has_its_status(void) {
    static daemon_t d;
    const char *body = "{\"version\":\"0.3.0\"}";
    const char *bad_body = "the body is {\"version\": \"<tag>\"}";

    ASSERT(installer_up(&d, &(dopts_t){.target = ""}));
    CHECK_CALL(refused(&d, body, 403, "this build cannot install updates: no-target", "no-target"));
    daemon_down(&d);

    ASSERT(installer_up(&d, NULL));
    CHECK_CALL(refused(&d, "", 400, bad_body, NULL));
    CHECK_CALL(refused(&d, "{\"version\":", 400, bad_body, NULL));
    CHECK_CALL(refused(&d, "[\"0.3.0\"]", 400, bad_body, NULL));
    CHECK_CALL(refused(&d, "{\"version\":3}", 400, bad_body, NULL));
    CHECK_CALL(refused(&d, "{\"version\":\"\"}", 400, bad_body, NULL));
    CHECK_CALL(refused(&d, body, 409, "check again: the last check did not offer 0.3.0", NULL));
    CHECK_CALL(refused(&d,
                       "{\"version\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u00e9bbbbb\"}",
                       409,
                       "check again: the last check did not offer "
                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                       NULL));
    ASSERT(checked(&d, M_INSTALL));
    CHECK_CALL(refused(&d, "{\"version\":\"0.2.9\"}", 409, "check again: the last check did not offer 0.2.9", NULL));
    set_mode(M_HOLD);
    int fd = send_request(&d, "POST", "/api/v1/system/update/check");
    ASSERT(fd >= 0);
    ASSERT(hits_reach(1, 5000));
    CHECK_CALL(refused(&d, body, 409, "a check is under way; try again in a moment", NULL));
    stub_release();
    ASSERT_EQ(200, read_response(fd, NULL));
    ASSERT(checked(&d, M_INSTALL));
    set_holds(true, false);
    ASSERT_EQ(202, install(&d, body, NULL));
    ASSERT(state_reached(&d, "downloading", NULL));
    CHECK_CALL(refused(&d, body, 409, "an install is under way", NULL));
    daemon_down(&d);
    stub_stop();
    set_holds(false, false);
    ASSERT(stub_start());

    ASSERT(installer_up(&d, NULL));
    ASSERT(checked(&d, M_INSTALL));
    ASSERT_EQ(202, request(&d, "POST", "/api/v1/system/restart", NULL));
    CHECK_CALL(refused(&d, body, 409, "a restart is under way", NULL));
    daemon_down(&d);

    ASSERT(installer_up(&d, &(dopts_t){.version = "0.3.1"}));
    ASSERT(checked(&d, M_INSTALL));
    CHECK_CALL(refused(&d, body, 400, "0.3.0 is not newer than 0.3.1", NULL));
    daemon_down(&d);

    ASSERT(installer_up(&d, NULL));
    ASSERT(checked(&d, M_NO_DIGEST));
    CHECK_CALL(refused(&d, body, 400, "0.3.0 cannot be installed: no-digest", "no-digest"));
    daemon_down(&d);

    ASSERT(installer_up(&d, &(dopts_t){.free_bytes = one_byte_free}));
    ASSERT(checked(&d, M_INSTALL));
    cJSON *b = NULL;
    ASSERT_EQ(507, install(&d, body, &b));
    ASSERT(b != NULL);
    ASSERT_EQ(3, cJSON_GetArraySize(b));
    ASSERT_STR_EQ("the update directory's filesystem has 1 bytes free; the install needs 11388608",
                  str_at(b, "error"));
    ASSERT_EQ(1.0, num_at(b, "free"));
    ASSERT_EQ(11388608.0, num_at(b, "need"));
    cJSON_Delete(b);
    ASSERT_EQ(0, dl_hits());
    PASS();
}

/* Catches an install started while S99firc restart is stopping the daemon, which would race opkg's prerm. */
TEST an_install_is_refused_while_a_restart_is_under_way(void) {
    static daemon_t d;
    ASSERT(installer_up(&d, NULL));
    ASSERT(checked(&d, M_INSTALL));
    ASSERT_EQ(202, request(&d, "POST", "/api/v1/system/restart", NULL));
    cJSON *b = NULL;
    ASSERT_EQ(409, install(&d, "{\"version\":\"0.3.0\"}", &b));
    ASSERT(error_is(b, "a restart is under way"));
    cJSON_Delete(b);
    b = NULL;
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", &b));
    ASSERT_STR_EQ("idle", str_at(b, "state"));
    cJSON_Delete(b);
    sleep_ms(100);
    ASSERT_EQ(0, dl_hits());
    PASS();
}

static bool restart_ran(const daemon_t *d) {
    char path[128];
    snprintf(path, sizeof path, "%s/restarted", d->dir);
    return access(path, F_OK) == 0;
}

/* Catches a restart let through while the package downloads or is checked, racing the hand-off to opkg. */
TEST a_restart_is_refused_during_the_download_and_the_check(void) {
    static daemon_t d;
    set_holds(true, true);
    ASSERT(installer_up(&d, &(dopts_t){.verified = hold_verified}));
    ASSERT(checked(&d, M_INSTALL));
    ASSERT_EQ(202, install(&d, "{\"version\":\"0.3.0\"}", NULL));
    ASSERT(state_reached(&d, "downloading", NULL));
    cJSON *b = NULL;
    ASSERT_EQ(409, request(&d, "POST", "/api/v1/system/restart", &b));
    ASSERT(error_is(b, "an update is being installed"));
    cJSON_Delete(b);
    dl_go();
    ASSERT(state_reached(&d, "verifying", NULL));
    b = NULL;
    ASSERT_EQ(409, request(&d, "POST", "/api/v1/system/restart", &b));
    ASSERT(error_is(b, "an update is being installed"));
    cJSON_Delete(b);
    sleep_ms(200);
    ASSERT_FALSE(restart_ran(&d));
    verify_go();
    ASSERT(state_reached(&d, "installing", NULL));
    write_file(d.hold, "");
    b = NULL;
    ASSERT(idle_with_result(&d, &b));
    cJSON_Delete(b);
    ASSERT_EQ(202, request(&d, "POST", "/api/v1/system/restart", NULL));
    bool ran = false;
    for (int i = 0; i < 300 && !ran; i++) {
        ran = restart_ran(&d);
        if (!ran) { sleep_ms(10); }
    }
    ASSERT(ran);
    PASS();
}

/* Catches a restarted daemon reporting idle mid-opkg: the WebUI would reload too early, or a restart be allowed. */
TEST a_new_daemon_reports_an_install_it_did_not_start(void) {
    static daemon_t d;
    ASSERT(installer_up(&d, NULL));
    ASSERT(make_dir(d.udir));
    pid_t child = sleeper();
    ASSERT(child > 0);
    uint64_t start = 0;
    bool started = firc_proc_starttime(child, &start);
    if (!started) { reap(child); }
    ASSERT(started);
    write_marker(&d, child, start);
    cJSON *b = NULL;
    int status = request(&d, "GET", "/api/v1/system/update", &b);
    const char *st = str_at(b, "state");
    bool installing = status == 200 && st != NULL && strcmp(st, "installing") == 0 && cJSON_IsNull(at(b, "result"));
    cJSON_Delete(b);
    b = NULL;
    int restart = request(&d, "POST", "/api/v1/system/restart", &b);
    bool refused_restart = restart == 409 && error_is(b, "an update is being installed");
    cJSON_Delete(b);
    reap(child);
    ASSERT(installing);
    ASSERT(refused_restart);
    char path[160], text[96];
    snprintf(path, sizeof path, "%s/installing", d.udir);
    unlink(path);
    long long finished = (long long)time(NULL);
    snprintf(path, sizeof path, "%s/result", d.udir);
    snprintf(text, sizeof text, "0.3.0 0 %lld\n", finished);
    write_file(path, text);
    b = NULL;
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", &b));
    ASSERT_STR_EQ("idle", str_at(b, "state"));
    ASSERT(cJSON_IsNull(at(b, "error")));
    const cJSON *r = at(b, "result");
    ASSERT(cJSON_IsObject(r));
    ASSERT_STR_EQ("0.3.0", str_at(r, "version"));
    ASSERT_EQ(0, (int)num_at(r, "opkgExit"));
    ASSERT_EQ((double)finished, num_at(r, "finishedAt"));
    ASSERT_STR_EQ("", str_at(r, "log"));
    cJSON_Delete(b);
    PASS();
}

/* Catches a dead installer's marker read as idle, which would hide an upgrade that never finished. */
TEST an_interrupted_install_is_reported(void) {
    static daemon_t d;
    ASSERT(installer_up(&d, NULL));
    ASSERT(make_dir(d.udir));
    uint64_t start = 0;
    ASSERT(firc_proc_starttime(getpid(), &start));
    write_marker(&d, getpid(), start + 1);
    cJSON *b = NULL;
    ASSERT_EQ(200, request(&d, "GET", "/api/v1/system/update", &b));
    ASSERT_STR_EQ("failed", str_at(b, "state"));
    ASSERT_STR_EQ(INTERRUPTED, str_at(b, "error"));
    ASSERT(cJSON_IsNull(at(b, "result")));
    cJSON_Delete(b);
    ASSERT_EQ(202, request(&d, "POST", "/api/v1/system/restart", NULL));
    PASS();
}

/* Catches the settle rule applied in the job but not in the API: the WebUI would see installing for ever. */
TEST a_refused_install_answers_idle_with_opkgs_exit(void) {
    static daemon_t d;
    ASSERT(installer_up(&d, NULL));
    unsetenv("FAKE_OPKG_HOLD");
    ASSERT_EQ(0, setenv("FAKE_OPKG_RC", "255", 1));
    ASSERT(checked(&d, M_INSTALL));
    ASSERT_EQ(202, install(&d, "{\"version\":\"0.3.0\"}", NULL));
    cJSON *b = NULL;
    ASSERT(idle_with_result(&d, &b));
    ASSERT_STR_EQ("0.3.0", str_at(at(b, "result"), "version"));
    ASSERT_EQ(255, (int)num_at(at(b, "result"), "opkgExit"));
    cJSON_Delete(b);
    ASSERT_EQ(202, install(&d, "{\"version\":\"0.3.0\"}", NULL));
    b = NULL;
    ASSERT(idle_with_result(&d, &b));
    ASSERT_EQ(255, (int)num_at(at(b, "result"), "opkgExit"));
    cJSON_Delete(b);
    ASSERT_EQ(2, dl_hits());
    ASSERT_EQ(202, request(&d, "POST", "/api/v1/system/restart", NULL));
    PASS();
}

SUITE(update_api) {
    GREATEST_SET_SETUP_CB(setup, NULL);
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(get_reports_the_build_and_why_it_cannot_install);
    RUN_TEST(a_check_answers_the_refreshed_status);
    RUN_TEST(a_rate_limited_check_is_429_with_the_reset_time);
    RUN_TEST(an_unreachable_github_is_502_with_libcurls_words);
    RUN_TEST(a_client_that_leaves_mid_check_costs_nothing);
    RUN_TEST(waiting_checks_end_when_the_daemon_stops);
    RUN_TEST(a_ninth_waiting_check_is_turned_away);
    RUN_TEST(a_status_without_a_checker_is_503);
    RUN_TEST(a_check_without_a_checker_is_503);
    RUN_TEST(an_install_answers_202_and_the_status_moves_to_installing);
    RUN_TEST(each_refusal_has_its_status);
    RUN_TEST(an_install_is_refused_while_a_restart_is_under_way);
    RUN_TEST(a_restart_is_refused_during_the_download_and_the_check);
    RUN_TEST(a_new_daemon_reports_an_install_it_did_not_start);
    RUN_TEST(an_interrupted_install_is_reported);
    RUN_TEST(a_refused_install_answers_idle_with_opkgs_exit);
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

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    g_fixture = read_file("tests/unit/fixtures/release-0.2.0.json", &g_fixture_len);
    if (g_fixture == NULL) {
        fprintf(stderr, "fixture not read\n");
        return 1;
    }
    g_payload = malloc(PAYLOAD_LEN);
    char cwd[PATH_MAX - sizeof(FAKE) - 1];
    if (g_payload == NULL || getcwd(cwd, sizeof cwd) == NULL) {
        fprintf(stderr, "setup failed\n");
        return 1;
    }
    memset(g_payload, 'a', PAYLOAD_LEN);
    snprintf(g_opkg, sizeof g_opkg, "%s/%s", cwd, FAKE);
    const char *path = getenv("PATH");
    int n = snprintf(g_path, sizeof g_path, "%s/%s:%s", cwd, FAKE_BIN, path != NULL ? path : "/usr/bin:/bin");
    if (n < 0 || (size_t)n >= sizeof g_path || setenv("PATH", g_path, 1) != 0) {
        fprintf(stderr, "PATH not set\n");
        return 1;
    }
    unsetenv("FAKE_OPKG_LOG");
    unsetenv("FAKE_OPKG_DAEMON");
    unsetenv("FAKE_OPKG_KILL_PARENT");
    signal(SIGPIPE, SIG_IGN);
    firc_sub_fetch_global_init();
    RUN_SUITE(update_api);
    firc_sub_fetch_global_cleanup();
    free(g_payload);
    free(g_fixture);
    GREATEST_MAIN_END();
}

#include "greatest.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "fake_iptables.h"
#include "fake_nflog.h"
#include "firc/autolistrules.h"
#include "firc/netfilter_cleaner.h"
#include "firc/system.h"
#include "firc/yamlio.h"

static uint16_t g_tcp_port;

typedef struct {
    firc_config_t cfg;
    firc_fakeip_t *pool;
    firc_fake_ipt_t *fake;
    firc_ipt_t *ipt;
    firc_app_t *app;
    firc_loop_t *loop;
    firc_httpd_t *tcp;
    firc_system_ctx_t system_ctx;
    pthread_t th;
} rig_t;

static fake_nflog_t *g_kernel[3];

static firc_nflog_t *fake_open(uint16_t group, uint16_t copy_range) {
    int w = group - FIRC_AUTOLIST_GROUP_HELLO;
    if (w < 0 || w > 2) { return NULL; }
    fake_nflog_stop(g_kernel[w]);
    int fd = -1;
    g_kernel[w] = fake_nflog_start(&fd);
    if (g_kernel[w] == NULL) { return NULL; }
    return firc_nflog_open_fd(fd, group, copy_range);
}

static void kernels_stop(void) {
    for (int w = 0; w < 3; w++) {
        fake_nflog_stop(g_kernel[w]);
        g_kernel[w] = NULL;
    }
}

static pthread_mutex_t g_probed_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_probed[8][FIRC_AUTOLIST_NAME_MAX];
static size_t g_n_probed;

static firc_autolist_verdict_t fake_probe(const char *host, const firc_autolist_check_opts_t *o, _Atomic bool *stop,
                                          char *error, size_t cap) {
    (void)o;
    (void)stop;
    pthread_mutex_lock(&g_probed_mu);
    if (g_n_probed < 8) { snprintf(g_probed[g_n_probed++], FIRC_AUTOLIST_NAME_MAX, "%s", host); }
    pthread_mutex_unlock(&g_probed_mu);
    snprintf(error, cap, "fake");
    return strcmp(host, "www.up.example") == 0 ? FIRC_AUTOLIST_REACHABLE : FIRC_AUTOLIST_BLOCKED;
}

static bool probed(const char *host) {
    bool found = false;
    pthread_mutex_lock(&g_probed_mu);
    for (size_t i = 0; i < g_n_probed; i++) { found = found || strcmp(g_probed[i], host) == 0; }
    pthread_mutex_unlock(&g_probed_mu);
    return found;
}

static void *loop_thread(void *ud) {
    firc_loop_run((firc_loop_t *)ud);
    return NULL;
}

static const char CONFIG[] =
    "configVersion: 0.99.0\n"
    "app:\n"
    "  link: [br0]\n"
    "  autolist: {enabled: true, group: 0a0b0c0d, recheck: true, recheckInterval: 1h}\n"
    "groups:\n"
    "  - id: 0a0b0c0d\n"
    "    name: Autolist\n"
    "    interface: nwg9\n"
    "    enable: true\n"
    "    rules:\n"
    "      - {id: 00000001, type: namespace, rule: up.example, enable: true, autolist: www.up.example}\n"
    "      - {id: 00000002, type: namespace, rule: down.example, enable: true, autolist: down.example}\n"
    "      - {id: 00000003, type: namespace, rule: hand.example, enable: true}\n"
    "      - {id: 00000004, type: namespace, rule: off.example, enable: false, autolist: off.example}\n";

static bool rig_up(rig_t *r) {
    static int nth = 0;
    g_tcp_port = (uint16_t)(18399 + ++nth);
    memset(r, 0, sizeof(*r));
    g_n_probed = 0;
    if (firc_config_init_defaults(&r->cfg) != FIRC_OK) { return false; }
    if (firc_config_load_buffer(&r->cfg, CONFIG, strlen(CONFIG)) != FIRC_OK) { return false; }
    firc_fakeip_cfg_t pc = {0};
    pc.v4.base.len = 4; pc.v4.base.b[0] = 198; pc.v4.base.b[1] = 18;
    pc.v4.pool_cidr = 15; pc.v4.chunk_cidr = 24;
    pc.v6.base.len = 16; pc.v6.base.b[0] = 0xfd; pc.v6.base.b[1] = 0x37;
    pc.v6.pool_cidr = 48; pc.v6.chunk_cidr = 64;
    pc.max_names = 64; pc.idle_secs = 86400; pc.clamp_secs = 300;
    if (firc_fakeip_new(&pc, &r->pool) != FIRC_OK) { return false; }
    r->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    r->ipt = firc_ipt_new(firc_fake_ipt_as_xt(r->fake), "FIRC_");
    firc_netfilter_register_base_chains(r->ipt, NULL);
    if (firc_loop_create(&r->loop) != FIRC_OK) { return false; }
    firc_app_deps_t deps = {.cfg = &r->cfg, .ipt4 = r->ipt, .pool = r->pool, .loop = r->loop, .nflog_open = fake_open};
    r->app = firc_app_create(&deps);
    if (r->app == NULL) { return false; }
    firc_app_set_autolist_probe_for_test(r->app, fake_probe);
    if (firc_app_autolist_apply(r->app) != FIRC_OK) { return false; }
    if (firc_httpd_create(r->loop, &r->tcp) != FIRC_OK) { return false; }
    r->system_ctx.app = r->app;
    firc_system_register_routes(r->tcp, &r->system_ctx);
    if (firc_httpd_listen_tcp(r->tcp, "127.0.0.1", g_tcp_port) != FIRC_OK) { return false; }
    return pthread_create(&r->th, NULL, loop_thread, r->loop) == 0;
}

static void rig_stop_loop(rig_t *r) {
    firc_loop_stop(r->loop);
    pthread_join(r->th, NULL);
}

static void rig_down(rig_t *r) {
    firc_httpd_destroy(r->tcp);
    firc_app_destroy(r->app);
    kernels_stop();
    firc_ipt_free(r->ipt);
    firc_fakeip_free(r->pool);
    firc_loop_destroy(r->loop);
    firc_config_clear(&r->cfg);
}

static int request(const char *method, const char *path, char *out, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(g_tcp_port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    bool connected = false;
    for (int i = 0; i < 100 && !connected; i++) {
        connected = connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
        if (!connected) {
            struct timespec ts = {0, 10000000};
            nanosleep(&ts, NULL);
        }
    }
    if (!connected) {
        close(fd);
        return -1;
    }
    char req[256];
    int n = snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", method, path);
    if (write(fd, req, (size_t)n) != n) {
        close(fd);
        return -1;
    }
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t total = 0;
    for (;;) {
        ssize_t got = read(fd, out + total, cap - 1 - total);
        if (got <= 0) { break; }
        total += (size_t)got;
        if (total >= cap - 1) { break; }
    }
    close(fd);
    out[total] = '\0';
    int code = 0;
    sscanf(out, "HTTP/1.1 %d", &code);
    return code;
}

static const firc_rule_t *rule_of(firc_app_t *app, const char *text) {
    firc_id_t gid;
    if (firc_id_parse("0a0b0c0d", &gid) != FIRC_OK) { return NULL; }
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, gid);
    const firc_group_t *g = rs != NULL ? firc_ruleset_group(rs) : NULL;
    for (size_t i = 0; g != NULL && i < g->n_rules; i++) {
        if (strcmp(g->rules[i]->rule, text) == 0) { return g->rules[i]; }
    }
    return NULL;
}

static bool wait_checked(void) {
    char buf[2048];
    for (int i = 0; i < 200; i++) {
        if (request("GET", "/api/v1/system/autolist", buf, sizeof(buf)) == 200 &&
            strstr(buf, "\"checking\":false") != NULL && strstr(buf, "\"checkedAt\":0") == NULL) {
            return true;
        }
        struct timespec ts = {0, 10000000};
        nanosleep(&ts, NULL);
    }
    return false;
}

TEST a_domain_that_opens_again_is_switched_off_and_the_rest_stay(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char buf[2048];
    ASSERT_EQ(200, request("POST", "/api/v1/system/autolist/check", buf, sizeof(buf)));
    ASSERT(wait_checked());
    ASSERT_EQ(200, request("GET", "/api/v1/system/autolist", buf, sizeof(buf)));
    ASSERTm(buf, strstr(buf, "\"switchedOff\":1") != NULL);
    rig_stop_loop(&r);

    ASSERTm("the host the domain was added for is what is checked", probed("www.up.example"));
    ASSERT(probed("down.example"));
    ASSERTm("a rule added by hand is never checked", !probed("hand.example"));
    ASSERTm("a rule already off is not checked", !probed("off.example"));
    ASSERT_FALSE(rule_of(r.app, "up.example")->enable);
    ASSERT(rule_of(r.app, "down.example")->enable);
    ASSERT(rule_of(r.app, "hand.example")->enable);
    ASSERT_STR_EQm("it keeps its mark, so it can come back", "www.up.example", rule_of(r.app, "up.example")->autolist);
    rig_down(&r);
    PASS();
}

TEST a_check_while_the_list_is_off_is_refused(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    rig_stop_loop(&r);
    r.cfg.app.autolist.enabled = false;
    ASSERT_EQ(FIRC_OK, firc_app_autolist_apply(r.app));
    ASSERT_EQ(FIRC_ERR_STATE, firc_app_autolist_recheck_now(r.app));
    rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_domain_that_opens_again_is_switched_off_and_the_rest_stay);
    RUN_TEST(a_check_while_the_list_is_off_is_refused);
    GREATEST_MAIN_END();
}

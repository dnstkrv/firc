#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "firc/subparse.h"

static void parse(const uint8_t *body, size_t len) {
    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    firc_sub_parse_stats_t st;
    if (firc_sub_parse_rules_stats((const char *)body, len, &rs, &st, NULL, NULL) == FIRC_OK) {
        for (size_t i = 0; i < rs.n; i++) {
            (void)firc_sub_rules_text(&rs, i);
            (void)firc_sub_rules_proto(&rs, i);
            (void)firc_sub_rules_ports(&rs, i);
        }
    }
    firc_sub_rules_free(&rs);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) { return 0; }
    size_t n = size - 2;
    uLongf zn = compressBound((uLong)n);
    uint8_t *body = malloc(4 + (n > zn ? n : zn) + 1);
    if (body == NULL) { return 0; }
    memcpy(body, "SRS", 3);
    body[3] = (uint8_t)(data[1] % 0x20);
    size_t len;
    if (data[0] & 1) {
        memcpy(body + 4, data + 2, n);
        len = 4 + n;
    } else {
        compress2(body + 4, &zn, data + 2, (uLong)n, 1);
        len = 4 + zn;
    }
    body[len] = '\0';
    parse(body, len);
    free(body);
    return 0;
}

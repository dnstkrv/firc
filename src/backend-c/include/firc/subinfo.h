#ifndef FIRC_SUBINFO_H
#define FIRC_SUBINFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool have;
    uint64_t upload, download;
    uint64_t total;
    int64_t expire;
} firc_subinfo_t;

#define FIRC_SUBINFO_HEADER "subscription-userinfo"
#define FIRC_SUBINFO_LINE_MAX 160

bool firc_subinfo_parse(const char *value, firc_subinfo_t *out);

bool firc_subinfo_from_body(const char *body, size_t len, firc_subinfo_t *out);

void firc_subinfo_format(const firc_subinfo_t *info, char *buf, size_t cap);

#endif

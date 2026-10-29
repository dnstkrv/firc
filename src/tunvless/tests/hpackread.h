#ifndef TUNVLESS_TESTS_HPACKREAD_H
#define TUNVLESS_TESTS_HPACKREAD_H
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define HR_MAX 256

struct hr_field {
    int kind;
    unsigned index;
    char name[64];
    char value[20000];
};

struct hr_block {
    size_t n;
    struct hr_field f[HR_MAX];
};

static const char *hr_static_name(unsigned i) {
    switch (i) {
        case 1: return ":authority";
        case 2: case 3: return ":method";
        case 4: case 5: return ":path";
        case 6: case 7: return ":scheme";
        case 17: return "accept-language";
        case 19: return "accept";
        case 24: return "cache-control";
        case 31: return "content-type";
        case 32: return "cookie";
        case 51: return "referer";
        case 58: return "user-agent";
        default: return NULL;
    }
}

static const char *hr_static_value(unsigned i) {
    switch (i) {
        case 2: return "GET";
        case 3: return "POST";
        case 4: return "/";
        case 5: return "/index.html";
        case 6: return "http";
        case 7: return "https";
        default: return NULL;
    }
}

static int hr_int(const unsigned char *d, size_t n, size_t *p, unsigned bits, uint32_t *out) {
    if (*p >= n) return -1;
    uint32_t max = (1u << bits) - 1;
    uint32_t v = d[(*p)++] & max;
    if (v < max) { *out = v; return 0; }
    unsigned shift = 0;
    for (;;) {
        if (*p >= n || shift > 28) return -1;
        unsigned char c = d[(*p)++];
        v += (uint32_t)(c & 0x7F) << shift;
        shift += 7;
        if (!(c & 0x80)) break;
    }
    *out = v;
    return 0;
}

static int hr_str(const unsigned char *d, size_t n, size_t *p, char *out, size_t cap) {
    if (*p >= n || (d[*p] & 0x80)) return -1;
    uint32_t len;
    if (hr_int(d, n, p, 7, &len)) return -1;
    if (len >= cap || *p + len > n) return -1;
    memcpy(out, d + *p, len);
    out[len] = '\0';
    *p += len;
    return 0;
}

static int hr_decode(const unsigned char *d, size_t n, struct hr_block *b) {
    size_t p = 0;
    b->n = 0;
    while (p < n) {
        if (b->n >= HR_MAX) return -1;
        struct hr_field *f = &b->f[b->n];
        uint32_t idx;
        if (d[p] & 0x80) {
            if (hr_int(d, n, &p, 7, &idx)) return -1;
            const char *nm = hr_static_name(idx), *vl = hr_static_value(idx);
            if (!nm || !vl) return -1;
            f->kind = 'i';
            f->index = idx;
            snprintf(f->name, sizeof f->name, "%s", nm);
            snprintf(f->value, sizeof f->value, "%s", vl);
        } else if ((d[p] & 0xF0) == 0x00) {
            if (hr_int(d, n, &p, 4, &idx)) return -1;
            if (idx) {
                const char *nm = hr_static_name(idx);
                if (!nm) return -1;
                f->kind = 'l';
                snprintf(f->name, sizeof f->name, "%s", nm);
            } else {
                f->kind = 'n';
                if (hr_str(d, n, &p, f->name, sizeof f->name)) return -1;
            }
            f->index = idx;
            if (hr_str(d, n, &p, f->value, sizeof f->value)) return -1;
        } else {
            return -1;
        }
        b->n++;
    }
    return 0;
}

static int hr_first_headers(const unsigned char *d, size_t n, struct hr_block *b) {
    size_t p = 0;
    if (n >= 24 && memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) p = 24;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > n) return -1;
        if (d[p + 3] == 0x01) return hr_decode(d + p + 9, len, b);
        p += 9 + len;
    }
    return -1;
}

static int hr_nth_headers(const unsigned char *d, size_t n, int k, struct hr_block *b) {
    size_t p = 0;
    if (n >= 24 && memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) p = 24;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > n) return -1;
        if (d[p + 3] == 0x01 && k-- == 0) return hr_decode(d + p + 9, len, b);
        p += 9 + len;
    }
    return -1;
}

static int hr_nth_headers_flags(const unsigned char *d, size_t n, int k) {
    size_t p = 0;
    if (n >= 24 && memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) p = 24;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > n) return -1;
        if (d[p + 3] == 0x01 && k-- == 0) return d[p + 4];
        p += 9 + len;
    }
    return -1;
}

static int hr_count_frames(const unsigned char *d, size_t n, unsigned char type) {
    size_t p = 0;
    int k = 0;
    if (n >= 24 && memcmp(d, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) p = 24;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)d[p] << 16) | ((uint32_t)d[p + 1] << 8) | d[p + 2];
        if (p + 9 + len > n) return -1;
        k += d[p + 3] == type;
        p += 9 + len;
    }
    return k;
}

static size_t hr_list_size(const struct hr_block *b) {
    size_t s = 0;
    for (size_t i = 0; i < b->n; i++) s += strlen(b->f[i].name) + strlen(b->f[i].value) + 32;
    return s;
}

static int hr_find_from(const struct hr_block *b, const char *name, int from) {
    for (size_t i = (size_t)from; i < b->n; i++)
        if (strcmp(b->f[i].name, name) == 0) return (int)i;
    return -1;
}

static int hr_find(const struct hr_block *b, const char *name) {
    for (size_t i = 0; i < b->n; i++)
        if (strcmp(b->f[i].name, name) == 0) return (int)i;
    return -1;
}

#endif

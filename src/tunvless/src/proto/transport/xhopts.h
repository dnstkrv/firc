#ifndef TUNVLESS_XHOPTS_H
#define TUNVLESS_XHOPTS_H
#include <stddef.h>
#include <stdint.h>

#define XH_PATH_MAX 2048

enum xh_place { XHP_PATH, XHP_QUERY, XHP_HEADER, XHP_COOKIE, XHP_BODY, XHP_AUTO, XHP_QUERY_IN_HEADER };

struct xh_opts {
    enum xh_place sess_place, seq_place, data_place, pad_place;
    char sess_key[64], seq_key[64], data_key[64], pad_key[64], pad_header[64];
    char table[128];
    uint16_t id_len_from, id_len_to;
    uint32_t chunk_from, chunk_to;
    char method[16];
    uint8_t obfs, tokenish;
};

int xh_opts_parse(const char *xhx, const char *mode, const char *headers, uint16_t pad_to,
                  struct xh_opts *o, char *why, size_t why_n);

#endif

#define _GNU_SOURCE
#include "unit.h"
#include "../src/proto/vless/vldial.c"

static void fnv_gid(const unsigned char *in, size_t n, unsigned char gid[8]) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= in[i]; h *= 1099511628211ULL; }
    h ^= h >> 32;
    for (int i = 0; i < 8; i++) gid[i] = (unsigned char)(h >> (56 - 8 * i));
}

static struct flow_key key6(unsigned char first, unsigned char last) {
    struct flow_key k;
    memset(&k, 0, sizeof k);
    k.v6 = 1;
    k.proto = 17;
    k.src.b[0] = first;
    k.src.b[1] = 0x0d;
    k.src.b[15] = last;
    k.dst.b[0] = 0x20; k.dst.b[1] = 0x01; k.dst.b[2] = 0x0d; k.dst.b[3] = 0xb8;
    k.dst.b[15] = 0x07;
    k.sport = 5000;
    k.dport = 443;
    return k;
}

int main(void) {
    static const unsigned char dg[5] = { 0, 3, 'a', 'b', 'c' };
    unsigned char out[128];
    unsigned char a[8], b[8], want[8];
    struct flow_key k6 = key6(0xfd, 1);
    struct flow_key k4;
    memset(&k4, 0, sizeof k4);
    k4.proto = 17;
    k4.src.b[0] = 192; k4.src.b[1] = 0; k4.src.b[2] = 2; k4.src.b[3] = 1;
    k4.dst.b[0] = 198; k4.dst.b[1] = 51; k4.dst.b[2] = 100; k4.dst.b[3] = 7;
    k4.sport = 5000;
    k4.dport = 443;

    size_t n = xudp_frames(&k6, 1, dg, sizeof dg, out, sizeof out);
    check("v6 New frame: total length", 2 + 32 + 2 + 3, (long)n);
    check_hex("v6 New frame: meta before the GlobalID",
              "0020" "0000" "010102" "01bb" "03" "20010db8000000000000000000000007", out, 26);
    check_hex("v6 New frame: datagram after the GlobalID", "0003616263", out + 34, 5);

    xudp_gid(&k6, want);
    check_mem("v6 New frame: GlobalID is the key's", want, out + 26, 8);

    n = xudp_frames(&k4, 1, dg, sizeof dg, out, sizeof out);
    check("v4 New frame: total length unchanged", 2 + 20 + 2 + 3, (long)n);
    check_hex("v4 New frame: meta before the GlobalID",
              "0014" "0000" "010102" "01bb" "01" "c6336407", out, 14);
    check_hex("v4 New frame: datagram after the GlobalID", "0003616263", out + 14 + 8, 5);

    unsigned char in4[16 + 6], in6[16 + 16 + 2];
    memcpy(in4, g_xudp_key, 16);
    memcpy(in4 + 16, k4.src.b, 4);
    in4[20] = 5000 >> 8; in4[21] = 5000 & 0xff;
    fnv_gid(in4, sizeof in4, want);
    xudp_gid(&k4, a);
    check_mem("v4 GlobalID: key, 4 source bytes, source port", want, a, 8);

    memcpy(in6, g_xudp_key, 16);
    memcpy(in6 + 16, k6.src.b, 16);
    in6[32] = 5000 >> 8; in6[33] = 5000 & 0xff;
    fnv_gid(in6, sizeof in6, want);
    xudp_gid(&k6, a);
    check_mem("v6 GlobalID: key, 16 source bytes, source port", want, a, 8);

    static const unsigned char pos[] = { 0, 4, 8, 15 };
    for (size_t i = 0; i < sizeof pos; i++) {
        struct flow_key o = k6;
        char what[64];
        o.src.b[pos[i]] ^= 0x80;
        xudp_gid(&k6, a);
        xudp_gid(&o, b);
        snprintf(what, sizeof what, "v6 GlobalID differs when source byte %u differs", pos[i]);
        check(what, 1, memcmp(a, b, 8) != 0);
    }

    struct flow_key o = k6;
    o.sport++;
    xudp_gid(&k6, a);
    xudp_gid(&o, b);
    check("v6 GlobalID differs when the source port differs", 1, memcmp(a, b, 8) != 0);

    struct flow_key m = k4;
    memset(m.src.b + 4, 0, 12);
    m.v6 = 1;
    xudp_gid(&k4, a);
    xudp_gid(&m, b);
    check("v4 and v6 keys with the same first 4 bytes differ", 1, memcmp(a, b, 8) != 0);

    return unit_done("xudpmatch");
}

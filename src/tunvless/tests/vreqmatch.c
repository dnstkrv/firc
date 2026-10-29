#include "unit.h"
#include "vless_proto.h"

static const unsigned char uuid[16] = { 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
                                        0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
static const char *uuid_hex = "11111111222233334444555555555555";

int main(void) {
    unsigned char out[128];
    unsigned char v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07 };
    unsigned char v4[4] = { 192, 0, 2, 9 };
    char want[256];
    size_t n;

    n = vless_build_request(uuid, VLESS_CMD_TCP, NULL, v6, 16, 443, NULL, out, sizeof out);
    snprintf(want, sizeof want, "00%s0001" "01bb" "03" "20010db8000000000000000000000007", uuid_hex);
    check("v6 request: length", 38, (long)n);
    check_hex("v6 request: bytes, type 3 and all 16 address bytes", want, out, n);

    n = vless_build_request(uuid, VLESS_CMD_TCP, NULL, v4, 4, 443, NULL, out, sizeof out);
    snprintf(want, sizeof want, "00%s0001" "01bb" "01" "c0000209", uuid_hex);
    check("v4 request: length", 26, (long)n);
    check_hex("v4 request: bytes unchanged", want, out, n);

    n = vless_build_request(uuid, VLESS_CMD_UDP, NULL, v6, 16, 53, NULL, out, sizeof out);
    snprintf(want, sizeof want, "00%s0002" "0035" "03" "20010db8000000000000000000000007", uuid_hex);
    check_hex("v6 request over UDP: command 2", want, out, n);

    n = vless_build_request(uuid, VLESS_CMD_TCP, "a.io", v6, 16, 443, NULL, out, sizeof out);
    snprintf(want, sizeof want, "00%s0001" "01bb" "02" "04" "612e696f", uuid_hex);
    check_hex("a name wins over a v6 address", want, out, n);

    n = vless_build_request(uuid, VLESS_CMD_MUX, NULL, NULL, 0, 0, NULL, out, sizeof out);
    snprintf(want, sizeof want, "00%s0003", uuid_hex);
    check_hex("mux: nothing after the command", want, out, n);

    check("v6 request: one byte short of the cap is refused", 0,
          (long)vless_build_request(uuid, VLESS_CMD_TCP, NULL, v6, 16, 443, NULL, out, 37));
    check("v6 request: exact cap fits", 38,
          (long)vless_build_request(uuid, VLESS_CMD_TCP, NULL, v6, 16, 443, NULL, out, 38));
    check("an address length other than 4 or 16 is refused", 0,
          (long)vless_build_request(uuid, VLESS_CMD_TCP, NULL, v6, 8, 443, NULL, out, sizeof out));

    check("an address length of 20 is refused", 0,
          (long)vless_build_request(uuid, VLESS_CMD_TCP, NULL, v6, 20, 443, NULL, out, sizeof out));

    return unit_done("vreqmatch");
}

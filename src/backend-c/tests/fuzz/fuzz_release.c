#include <stdint.h>
#include <stdlib.h>

#include "firc/release.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const firc_release_want_t want = {"mipsel-3.4_kn", FIRC_UPDATE_DOWNLOAD_PREFIX};
    firc_release_t r;
    if (firc_release_parse((const char *)data, size, &want, &r) == FIRC_OK) { firc_release_clear(&r); }
    return 0;
}

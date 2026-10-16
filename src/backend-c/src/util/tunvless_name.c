#include "firc/tunvless_name.h"

#include <string.h>

int firc_tunvless_index(const char *name) {
    static const char stem[] = "tunvless";
    if (name == NULL || strncmp(name, stem, sizeof(stem) - 1) != 0) { return -1; }
    const char *d = name + sizeof(stem) - 1;
    if (d[0] < '0' || d[0] > '9') { return -1; }
    if (d[1] == '\0') { return d[0] - '0'; }
    if (d[0] == '0' || d[1] < '0' || d[1] > '9' || d[2] != '\0') { return -1; }
    return (d[0] - '0') * 10 + (d[1] - '0');
}

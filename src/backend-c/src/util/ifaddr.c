#include "firc/ifaddr.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

int firc_iface_ipv4(const char *name, char *out, size_t cap) {
    struct ifaddrs *list = NULL;
    if (name == NULL || cap == 0 || getifaddrs(&list) != 0) { return -1; }
    int rc = -1;
    for (const struct ifaddrs *a = list; a != NULL; a = a->ifa_next) {
        if (a->ifa_addr != NULL && a->ifa_addr->sa_family == AF_INET && strcmp(a->ifa_name, name) == 0) {
            if (inet_ntop(AF_INET, &((const struct sockaddr_in *)(const void *)a->ifa_addr)->sin_addr, out,
                          (socklen_t)cap) != NULL) {
                rc = 0;
            }
            break;
        }
    }
    freeifaddrs(list);
    return rc;
}

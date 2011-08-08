#include "topology_set.h"

/**
  * Checks whether the two IP addresses are the same.
  *
  * Returns 0 if they are not, any other number otherwise.
  */
uint32_t ip_addr_eq(struct ip_addr_t a, struct ip_addr_t b) {
    if (a.protocol != b.protocol)
        return 0;

    if (a.protocol == IPv4) {
        return memcmp(&a.addr.v4, &b.addr.v4, sizeof(a.addr.v4)) == 0;
    } else {
        return memcmp(&a.addr.v6, &b.addr.v6, sizeof(a.addr.v6)) == 0;
    }
}

inline static uint32_t ip_addr_hash_code4(struct ip_addr_t addr) {
    return 23 * addr.addr.v4.s_addr;
}

inline static uint32_t ip_addr_hash_code6(struct ip_addr_t addr) {
    uint32_t hashcode = 0;

    int i;

    for (i = 0; i < 4; i++) {
        hashcode = hashcode * 23 + *(addr.addr.v6.s6_addr + i);
    }

    return hashcode;
}

uint32_t ip_addr_hash_code(struct ip_addr_t addr) {
    if (addr.protocol == IPv4) {
        return ip_addr_hash_code4(addr);
    } else {
        return ip_addr_hash_code6(addr);
    }
}

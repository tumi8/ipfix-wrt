#ifndef TOPOLOGY_SET_H_
#define TOPOLOGY_SET_H_

#include "khash.h"
#include "flows.h"
#include "olsr_protocol.h"



struct topology_set_entry {
    union olsr_ip_addr dest_addr;
    uint16_t seq;
    time_t time;

    struct topology_set_entry *next;
};

struct topology_set {
    // Holds the underlying network protocol of the topology_set_entries
    network_protocol protocol;
    struct topology_set_entry *first;
    struct topology_set_entry *last;
};

uint32_t ip_addr_hash_code(struct ip_addr_t addr);
uint32_t ip_addr_eq(struct ip_addr_t a, struct ip_addr_t b);

#define ip_addr_hash_code_macro(key) ip_addr_hash_code(key)
#define ip_addr_hash_eq_macro(a, b) ip_addr_eq(a, b)

KHASH_INIT(2, struct ip_addr_t, struct topology_set *, 1, ip_addr_hash_code_macro, ip_addr_hash_eq_macro)

#endif

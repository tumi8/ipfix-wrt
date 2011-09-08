#ifndef HELLO_SET_H_
#define HELLO_SET_H_

#include "olsr_protocol.h"
#include "khash.h"
#include "flows.h"

struct hello_set_entry {
	union olsr_ip_addr neighbor_addr;
	time_t vtime;
	uint8_t link_code;
	uint32_t lq_parameters;

	struct hello_set_entry *next;
};

struct hello_set {
	// Holds the underlying network protocol of the hello_set_entries
	network_protocol protocol;
	time_t htime;
	struct hello_set_entry *first;
	struct hello_set_entry *last;
};

KHASH_INIT(3, struct ip_addr_t, struct hello_set *, 1, ip_addr_hash_code_macro, ip_addr_hash_eq_macro)

typedef khash_t(3) hello_set_hash;

struct hello_set *find_or_create_hello_set(hello_set_hash *hello_set, union olsr_ip_addr *addr);
struct hello_set_entry *find_or_create_hello_set_entry(struct hello_set *hs, union olsr_ip_addr *addr);

#endif HELLO_SET_H_

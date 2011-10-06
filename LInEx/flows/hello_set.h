#ifndef HELLO_SET_H
#define HELLO_SET_H

#include "olsr_protocol.h"
#include "khash.h"
#include "flows.h"
#include "node_set.h"

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

struct hello_set *find_or_create_hello_set(node_set_hash *node_set,
										   struct ip_addr_t *addr);
struct hello_set_entry *find_or_create_hello_set_entry(struct hello_set *hs,
													   union olsr_ip_addr *addr);

void expire_hello_set_entries(struct hello_set *set, time_t now);
#endif

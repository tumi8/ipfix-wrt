#ifndef HELLO_SET_H
#define HELLO_SET_H

#include "olsr_protocol.h"
#include "khash.h"
#include "flows.h"
#include "node_set.h"

struct hello_set_entry {
	struct set_entry_common common;

	union olsr_ip_addr neighbor_addr;
	uint8_t link_code;
	uint32_t lq_parameters;

	struct hello_set_entry *next;
};

struct hello_set {
	time_t htime;

	struct hello_set_entry *first;
	struct hello_set_entry *last;
};

struct hello_set *find_or_create_hello_set(node_set_hash *node_set,
										   struct ip_addr_t *addr);
struct hello_set_entry *find_or_create_hello_set_entry(struct hello_set *hs,
													   union olsr_ip_addr *addr,
													   network_protocol protocol);

void expire_hello_set_entries(struct hello_set *set, time_t now);
#endif

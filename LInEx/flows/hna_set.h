#ifndef HNA_SET_H_
#define HNA_SET_H_

#include "olsr_protocol.h"
#include "khash.h"
#include "flows.h"
#include "node_set.h"

struct hna_set_entry {
	union olsr_ip_addr network;
	uint8_t netmask;
	time_t vtime;

	struct hna_set_entry *next;
};

struct hna_set {
	network_protocol protocol;

	struct hna_set_entry *first;
	struct hna_set_entry *last;
};

struct hna_set *find_or_create_hna_set(node_set_hash *node_set,
									   struct ip_addr_t *addr);
struct hna_set_entry *find_or_create_hna_set_entry(struct hna_set *hs,
												   union olsr_ip_addr *addr, uint8_t netmask);

void expire_hna_set_entries(struct hna_set *set, time_t now);

#endif

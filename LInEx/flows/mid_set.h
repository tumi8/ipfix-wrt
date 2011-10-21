#ifndef MID_SET_H_
#define MID_SET_H_
#include "node_set.h"

struct mid_set_entry {
	struct set_entry_common common;

	union olsr_ip_addr addr;

	struct mid_set_entry *next;
};

struct mid_set {
	struct mid_set_entry *first;
	struct mid_set_entry *last;
};

struct mid_set *find_or_create_mid_set(node_set_hash *node_set,
									   struct ip_addr_t *addr);
struct mid_set_entry *find_or_create_mid_set_entry(struct mid_set *hs,
												   union olsr_ip_addr *addr,
												   network_protocol protocol);

void expire_mid_set_entries(struct mid_set *set, time_t now);

#endif

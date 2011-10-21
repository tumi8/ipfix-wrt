#ifndef TOPOLOGY_SET_H_
#define TOPOLOGY_SET_H_

#include "khash.h"
#include "flows.h"
#include "olsr_protocol.h"
#include "node_set.h"

struct topology_set_entry {
	struct set_entry_common common;

	union olsr_ip_addr dest_addr;

	uint16_t seq;
	uint32_t lq_parameters;

	struct topology_set_entry *next;
};

struct topology_set {
	struct topology_set_entry *first;
	struct topology_set_entry *last;
};

struct topology_set_entry *find_or_create_topology_set_entry(struct topology_set *ts,
															 union olsr_ip_addr *addr,
															 network_protocol protocol);

struct topology_set *find_or_create_topology_set(node_set_hash *node_set,
												 struct ip_addr_t *addr);

void expire_topology_set_entries(struct topology_set *ts, time_t now);
#endif

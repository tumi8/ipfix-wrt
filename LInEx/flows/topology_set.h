#ifndef TOPOLOGY_SET_H_
#define TOPOLOGY_SET_H_

#include "khash.h"
#include "flows.h"
#include "olsr_protocol.h"
#include "node_set.h"

struct topology_set_entry {
	union olsr_ip_addr dest_addr;
	uint16_t seq;
	time_t time;
	uint32_t lq_parameters;

	struct topology_set_entry *next;
};

struct topology_set {
	// Holds the underlying network protocol of the topology_set_entries
	network_protocol protocol;
	struct topology_set_entry *first;
	struct topology_set_entry *last;
};

struct topology_set_entry
		*find_or_create_topology_set_entry(struct topology_set *ts,
										   union olsr_ip_addr *addr);

struct topology_set *find_or_create_topology_set(node_set_hash *node_set,
												 struct ip_addr_t *addr);

void expire_topology_set_entries(struct topology_set *ts, time_t now);
#endif

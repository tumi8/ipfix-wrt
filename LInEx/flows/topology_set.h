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
	uint8_t backoff:1;
	uint32_t lq_parameters;

	struct topology_set_entry *next;
};

vtime_container_init(topology_set, struct topology_set_entry)

#endif

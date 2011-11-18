#ifndef HNA_SET_H_
#define HNA_SET_H_

#include "olsr_protocol.h"
#include "khash.h"
#include "flows.h"
#include "node_set.h"

struct hna_set_entry {
	struct set_entry_common common;

	union olsr_ip_addr network;
	uint8_t netmask;

	struct hna_set_entry *next;
};

vtime_container_init(hna_set, struct hna_set_entry)

#endif

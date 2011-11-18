#ifndef MID_SET_H_
#define MID_SET_H_
#include "node_set.h"

struct mid_set_entry {
	struct set_entry_common common;

	union olsr_ip_addr addr;

	struct mid_set_entry *next;
};

vtime_container_init(mid_set, struct mid_set_entry)

#endif

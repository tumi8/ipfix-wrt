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

struct vtime_bucket_hello_set {
	time_t vtime;
	struct hello_set_entry *first;
	struct hello_set_entry *last;
	struct vtime_bucket_hello_set *next;
};
vtime_container_iterator(hello_set) {
	struct vtime_bucket_hello_set *prev_bucket;
	struct vtime_bucket_hello_set *bucket;
	struct hello_set_entry *next_elem;
	struct hello_set_entry *elem;
	struct hello_set_entry *prev_elem;
	uint8_t stop;
};
struct vtime_container_hello_set {
	time_t htime;
	struct vtime_bucket_hello_set *first;
	struct vtime_bucket_hello_set *last;
};

#endif

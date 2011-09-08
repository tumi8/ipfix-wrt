#include "topology_set.h"

/**
  * Checks whether the two IP addresses are the same.
  *
  * Returns 0 if they are not, any other number otherwise.
  */
uint32_t ip_addr_eq(struct ip_addr_t a, struct ip_addr_t b) {
	if (a.protocol != b.protocol)
		return 0;

	if (a.protocol == IPv4) {
		return memcmp(&a.addr.v4, &b.addr.v4, sizeof(a.addr.v4)) == 0;
	} else {
		return memcmp(&a.addr.v6, &b.addr.v6, sizeof(a.addr.v6)) == 0;
	}
}

inline static uint32_t ip_addr_hash_code4(struct ip_addr_t addr) {
	return 23 * addr.addr.v4.s_addr;
}

inline static uint32_t ip_addr_hash_code6(struct ip_addr_t addr) {
	uint32_t hashcode = 0;

	int i;

	for (i = 0; i < 4; i++) {
		hashcode = hashcode * 23 + *(addr.addr.v6.s6_addr + i);
	}

	return hashcode;
}

uint32_t ip_addr_hash_code(struct ip_addr_t addr) {
	if (addr.protocol == IPv4) {
		return ip_addr_hash_code4(addr);
	} else {
		return ip_addr_hash_code6(addr);
	}
}

/**
  * Attempts to find the topology set stored in the given topology control set \a tc_set
  * associated with the given network address.
  *
  * Returns a reference to the topology set (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
struct topology_set *find_or_create_topology_set(tc_set_hash *tc_set, union olsr_ip_addr *addr) {
	struct ip_addr_t originator_addr = { IPv4, *addr };
	khiter_t k;

	k = kh_get(2, tc_set, originator_addr);

	if (k == kh_end(tc_set)) {
		// Create new entry
		struct topology_set *ts = (struct topology_set *) malloc(sizeof(struct topology_set));
		ts->first = ts->last = NULL;

		int ret;
		k = kh_put(2, tc_set, originator_addr, &ret);
		kh_value(tc_set, k) = ts;

		return ts;
	}

	return kh_value(tc_set, k);
}

/**
  * Attempts to find the topology set entry stored in the given topology set which has
  * the given network address. This function will create a new entry in the topology
  * set if an existing one could not be found.
  *
  * Returns a reference to the topology set entry (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
struct topology_set_entry *find_or_create_topology_set_entry(struct topology_set *ts, union olsr_ip_addr *addr) {
	struct topology_set_entry *ts_entry = ts->first;

	while (ts_entry != NULL) {
		if (ts->protocol == IPv4) {
			if (ts_entry->dest_addr.v4.s_addr == addr->v4.s_addr)
				break;
		} else {
			if (memcmp(&ts_entry->dest_addr.v6, &addr->v6, sizeof(addr->v6)))
				break;
		}

		ts_entry = ts_entry->next;
	}

	if (ts_entry == NULL) {
		ts_entry = (struct topology_set_entry *) malloc (sizeof(struct topology_set_entry));
		ts_entry->next = NULL;

		if (ts_entry == NULL)
			return NULL;

		ts_entry->dest_addr = *addr;
		if (ts->last != NULL)
			ts->last->next = ts_entry;
		if (ts->first == NULL)
			ts->first = ts_entry;

		ts->last = ts_entry;
	}

	return ts_entry;
}


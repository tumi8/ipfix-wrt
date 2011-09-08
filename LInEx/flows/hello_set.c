#include "hello_set.h"

/**
  * Attempts to find the hello set stored in the given hello set \a hello_set
  * associated with the given network address.
  *
  * Returns a reference to the hello set (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
struct hello_set *find_or_create_hello_set(hello_set_hash *hello_set, union olsr_ip_addr *addr) {
	struct ip_addr_t originator_addr = { IPv4, *addr };
	khiter_t k;

	k = kh_get(3, hello_set, originator_addr);

	if (k == kh_end(hello_set)) {
		// Create new entry
		struct hello_set *hs = (struct hello_set *) malloc(sizeof(struct hello_set));
		hs->first = hs->last = NULL;

		int ret;
		k = kh_put(3, hello_set, originator_addr, &ret);
		kh_value(hello_set, k) = hs;

		return hs;
	}

	return kh_value(hello_set, k);
}

/**
  * Attempts to find the topology set entry stored in the given topology set which has
  * the given network address. This function will create a new entry in the topology
  * set if an existing one could not be found.
  *
  * Returns a reference to the topology set entry (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
struct hello_set_entry *find_or_create_hello_set_entry(struct hello_set *hs, union olsr_ip_addr *addr) {
	struct hello_set_entry *hs_entry = hs->first;

	while (hs_entry != NULL) {
		if (hs->protocol == IPv4) {
			if (hs_entry->neighbor_addr.v4.s_addr == addr->v4.s_addr)
				break;
		} else {
			if (memcmp(&hs_entry->neighbor_addr.v6, &addr->v6, sizeof(addr->v6)))
				break;
		}

		hs_entry = hs_entry->next;
	}

	if (hs_entry == NULL) {
		hs_entry = (struct hello_set_entry *) malloc (sizeof(struct hello_set_entry));
		hs_entry->next = NULL;

		if (hs_entry == NULL)
			return NULL;

		hs_entry->neighbor_addr = *addr;
		if (hs->last != NULL)
			hs->last->next = hs_entry;
		if (hs->first == NULL)
			hs->first = hs_entry;

		hs->last = hs_entry;
	}

	return hs_entry;
}

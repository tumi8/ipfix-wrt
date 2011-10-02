#include "hello_set.h"

/**
  * Attempts to find the hello set stored in the given node set \a node_set
  * associated with the given network address.
  *
  * Returns a reference to the hello set (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
struct hello_set *find_or_create_hello_set(node_set_hash *node_set,
										   union olsr_ip_addr *addr) {
	struct ip_addr_t originator_addr = { IPv4, *addr };
	struct node_entry *node_entry = find_or_create_node_entry(node_set,
															  &originator_addr);

	if (!node_entry->hello_set) {
		// Create new entry
		struct hello_set *hs = (struct hello_set *) malloc(sizeof(struct hello_set));
		hs->first = hs->last = NULL;

		node_entry->hello_set = hs;
	}

	return node_entry->hello_set;
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

struct hello_set_entry *hello_set_remove_entry(struct hello_set *set,
											   struct hello_set_entry *entry,
											   struct hello_set_entry *previous_entry) {
	struct hello_set_entry *next = entry->next;

	if (entry == set->first)
		set->first = entry->next;

	if (entry == set->last)
		set->last = previous_entry;

	if (previous_entry)
		previous_entry->next = entry->next;

	free(entry);

	return next;
}

/**
  * Expires the entries in the hello set (i.e. if their validity time is less
  * then the time specified in \a now.
  */
void expire_hello_set_entries(struct hello_set *set, time_t now) {
	struct hello_set_entry *entry = set->first;
	struct hello_set_entry *previous_entry = NULL;

	while (entry != NULL) {
		if (entry->vtime < now) {
			entry = hello_set_remove_entry(set, entry, previous_entry);
		} else {
			previous_entry = entry;
			entry = entry->next;
		}
	}
}

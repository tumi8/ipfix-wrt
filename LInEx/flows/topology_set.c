#include "topology_set.h"

/**
  * Attempts to find the topology set stored in the given node_set
  * associated with the given network address.
  *
  * Returns a reference to the topology set (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
struct topology_set *find_or_create_topology_set(node_set_hash *node_set,
												 struct ip_addr_t *addr) {
	struct node_entry *node = find_or_create_node_entry(node_set,
														&addr);

	if (!node->topology_set) {
		struct topology_set *ts =
				(struct topology_set *) malloc(sizeof(struct topology_set));
		ts->first = ts->last = NULL;
		ts->protocol = addr->protocol;

		node->topology_set = ts;
	}

	return node->topology_set;
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
#ifdef SUPPORT_IPV6
			if (memcmp(&ts_entry->dest_addr.v6, &addr->v6, sizeof(addr->v6)))
				break;
#endif
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

struct topology_set_entry *topology_set_remove_entry(struct topology_set *set,
													 struct topology_set_entry *entry,
													 struct topology_set_entry *previous_entry) {
	struct topology_set_entry *next = entry->next;

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
  * This function removes topology set entries which have expired (i.e. those
  * entries whose vtime is less than the time specified in \a now.
  */
void expire_topology_set_entries(struct topology_set *ts, time_t now) {
	struct topology_set_entry *entry = ts->first;
	struct topology_set_entry *previous_entry = NULL;

	while (entry != NULL) {
		if (entry->time < now) {
			entry = topology_set_remove_entry(ts, entry, previous_entry);
		} else {
			previous_entry = entry;
			entry = entry->next;
		}
	}
}

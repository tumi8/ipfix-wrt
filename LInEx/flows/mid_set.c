#include "mid_set.h"

struct mid_set *find_or_create_mid_set(node_set_hash *node_set,
									   struct ip_addr_t *addr) {
	struct node_entry *node_entry = find_or_create_node_entry(node_set,
															  addr);

	if (!node_entry->mid_set) {
		// Create new entry
		struct mid_set *mid_set = (struct mid_set *) malloc(sizeof(struct mid_set));
		mid_set->first = mid_set->last = NULL;
		mid_set->protocol = addr->protocol;

		node_entry->mid_set = mid_set;
	}

	return node_entry->mid_set;
}

struct mid_set_entry *find_or_create_mid_set_entry(struct mid_set *hs,
												   union olsr_ip_addr *addr) {
	struct mid_set_entry *mid_set_entry = hs->first;

	while (mid_set_entry != NULL) {
		if (hs->protocol == IPv4) {
			if (mid_set_entry->addr.v4.s_addr == addr->v4.s_addr)
				break;
		} else {
#ifdef SUPPORT_IPV6
			if (memcmp(&mid_set_entry->addr.v6, &addr->v6, sizeof(addr->v6)))
				break;
#endif
		}

		mid_set_entry = mid_set_entry->next;
	}

	if (mid_set_entry == NULL) {
		mid_set_entry = (struct mid_set_entry *) malloc (sizeof(struct mid_set_entry));
		mid_set_entry->next = NULL;

		if (mid_set_entry == NULL)
			return NULL;

		mid_set_entry->addr = *addr;

		if (hs->last != NULL)
			hs->last->next = mid_set_entry;
		if (hs->first == NULL)
			hs->first = mid_set_entry;

		hs->last = mid_set_entry;
	}

	return mid_set_entry;
}

struct mid_set_entry *mid_set_remove_entry(struct mid_set *set,
										   struct mid_set_entry *entry,
										   struct mid_set_entry *previous_entry) {
	struct mid_set_entry *next = entry->next;

	if (entry == set->first)
		set->first = entry->next;

	if (entry == set->last)
		set->last = previous_entry;

	if (previous_entry)
		previous_entry->next = entry->next;

	free(entry);

	return next;
}

void expire_mid_set_entries(struct mid_set *set, time_t now) {
	struct mid_set_entry *entry = set->first;
	struct mid_set_entry *previous_entry = NULL;

	while (entry != NULL) {
		if (entry->vtime < now) {
			entry = mid_set_remove_entry(set, entry, previous_entry);
		} else {
			previous_entry = entry;
			entry = entry->next;
		}
	}
}

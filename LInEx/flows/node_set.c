#include "node_set.h"
#include "topology_set.h"
#include "hello_set.h"
#include "hna_set.h"
#include "mid_set.h"

inline void init_set_entry_common(struct set_entry_common *common) {
	common->created = 1;
	common->changed = 0;
	common->expired = 0;
}

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
#ifdef SUPPORT_IPV6
		return memcmp(&a.addr.v6, &b.addr.v6, sizeof(a.addr.v6)) == 0;
#endif
	}

	return -1;
}

inline static uint32_t ip_addr_hash_code4(struct ip_addr_t addr) {
	return 23 * addr.addr.v4.s_addr;
}

inline static uint32_t ip_addr_hash_code6(struct ip_addr_t addr) {
	uint32_t hashcode = 0;

	int i;

	for (i = 0; i < 4; i++) {
#ifdef SUPPORT_IPV6
		hashcode = hashcode * 23 + *(addr.addr.v6.s6_addr + i);
#endif
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

struct node_entry *find_or_create_node_entry(node_set_hash *node_set,
											 const struct ip_addr_t *addr) {
	khiter_t k;

	k = kh_get(2, node_set, *addr);

	if (k == kh_end(node_set)) {
		// Create new entry
		struct node_entry *node =
				(struct node_entry *) malloc(sizeof(struct node_entry));

		node->hello_set = NULL;
		node->topology_set = NULL;
		node->hna_set = NULL;
		node->mid_set = NULL;

		int ret;
		k = kh_put(2, node_set, *addr, &ret);
		kh_value(node_set, k) = node;

		return node;
	}

	return kh_value(node_set, k);

}

void expire_node_set_entries(node_set_hash *node_set) {
	time_t now = time(NULL);
	khint_t k;

	for (k = kh_begin(node_set); k != kh_end(node_set); ++k) {
		if (!kh_exist(node_set, k))
			continue;

		struct node_entry *node = kh_value(node_set, k);

		if (node->topology_set) {
			vtime_container_expire(node->topology_set, now);
			if (node->topology_set->first == NULL
					&& node->topology_set->last == NULL) {
				free(node->topology_set);
				node->topology_set = NULL;
			}
		}

		if (node->hello_set) {
			vtime_container_expire(node->hello_set, now);
			if (node->hello_set->first == NULL
					&& node->hello_set->last == NULL) {
				free(node->hello_set);
				node->hello_set = NULL;
			}
		}

		if (node->hna_set) {
			vtime_container_expire(node->hna_set, now);
			if (node->hna_set->first == NULL
					&& node->hna_set->last == NULL) {
				free(node->hna_set);
				node->hna_set = NULL;
			}
		}

		if (node->mid_set) {
			vtime_container_expire(node->mid_set, now);
			if (node->mid_set->first == NULL
					&& node->mid_set->last == NULL) {
				free(node->mid_set);
				node->mid_set = NULL;
			}
		}

		if (node->topology_set == NULL && node->hello_set == NULL
				&& node->hna_set == NULL) {
			free(node);
			kh_del(2, node_set, k);
		}
	}
}

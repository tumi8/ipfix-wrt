#ifndef NODE_SET_H_
#define NODE_SET_H_

#include "khash.h"
#include "olsr_protocol.h"
#include "flows.h"

struct node_entry {
	struct topology_set *topology_set;
	struct hello_set *hello_set;
	struct hna_set *hna_set;
};

/**
  * Hashing functions for IP addresses
  */
uint32_t ip_addr_hash_code(struct ip_addr_t addr);
uint32_t ip_addr_eq(struct ip_addr_t a, struct ip_addr_t b);

#define ip_addr_hash_code_macro(key) ip_addr_hash_code(key)
#define ip_addr_hash_eq_macro(a, b) ip_addr_eq(a, b)

KHASH_INIT(2,
		   struct ip_addr_t,
		   struct node_entry *,
		   1,
		   ip_addr_hash_code_macro,
		   ip_addr_hash_eq_macro);

typedef khash_t(2) node_set_hash;

struct node_entry *find_or_create_node_entry(node_set_hash *node_set,
											 const struct ip_addr_t *addr);

void expire_node_set_entries(node_set_hash *node_set);
#endif

#ifndef NODE_SET_H_
#define NODE_SET_H_

#include "khash.h"
#include "olsr_protocol.h"
#include "flows.h"

#define vtime_container(name) \
	struct vtime_container_##name
#define vtime_container_iterator(name) \
	struct vtime_container_iterator_##name
#define vtime_bucket(name) \
	struct vtime_bucket_##name

#define vtime_container_init(name, type) \
	struct vtime_bucket_##name { \
		time_t vtime; \
		type *first; \
		type *last; \
		struct vtime_bucket_##name *next; \
	}; \
	struct vtime_container_iterator_##name { \
		struct vtime_bucket_##name *prev_bucket; \
		struct vtime_bucket_##name *bucket; \
		type *next_elem; \
		type *elem; \
		type *prev_elem; \
		uint8_t stop; \
	}; \
	struct vtime_container_##name { \
		struct vtime_bucket_##name *first; \
		struct vtime_bucket_##name *last; \
	};

#define find_or_create_vtime_container(name, out, node_set, ip_addr) \
		struct node_entry *node = find_or_create_node_entry(node_set, \
															ip_addr); \
		out = node->name; \
		if (!out) { \
			out = (typeof(out)) malloc(sizeof(typeof(*out))); \
			out->first = out->last = NULL; \
			node->name = out; \
		}

#define ll_append(container, item) \
	item->next = NULL; \
	if (container->last) \
		container->last->next = item; \
	if (!container->first) \
		container->first = item; \
	container->last = item;

#define ll_remove(container, item, prev_item) \
	if (prev_item) \
		prev_item->next = item->next; \
	if (item == container->first) \
		container->first = item->next; \
	if (item == container->last) \
		container->last = prev_item; \

#define ll_remove_iterator(iterator) \
	iterator.next_elem = iterator.elem->next; \
	ll_remove(iterator.bucket, iterator.elem, iterator.prev_elem); \
	iterator.elem = iterator.prev_elem; \
	iterator.prev_elem = NULL; \

#define vtime_container_init_iterator(container, iterator) \
	iterator.prev_elem = NULL; \
	iterator.elem = container->first ? container->first->first : NULL; \
	iterator.next_elem = iterator.elem ? iterator.elem->next : NULL; \
	iterator.prev_bucket = NULL; \
	iterator.bucket = container->first; \
	iterator.stop = 0;

#define vtime_container_clear_iterator(iterator) \
	iterator.elem = iterator.prev_elem = iterator.next_elem = NULL; \
	iterator.bucket = iterator.prev_bucket = NULL; \
	iterator.stop = 0; \

#define vtime_container_foreach(iterator) \
	for (; iterator.bucket && !iterator.stop; !iterator.stop && iterator.bucket ? (iterator.prev_bucket = iterator.bucket, iterator.bucket = iterator.bucket->next, (iterator.bucket ? iterator.elem = iterator.bucket->first : NULL)) : 0) \
		for (; iterator.elem && !iterator.stop; (!iterator.stop && iterator.elem) ? (iterator.prev_elem = iterator.elem, iterator.elem = iterator.next_elem, (iterator.elem ? (iterator.next_elem = iterator.elem->next) : (iterator.next_elem = NULL))) : 0)

#define vtime_container_insert_bucket(container, bucket) \
	if (container->last && container->last->vtime < bucket->vtime) { \
		ll_append(container, bucket); \
	} else { \
		typeof(container->first) _entry, _prev_entry = NULL; \
		for (_entry = container->first; _entry; _prev_entry = _entry, _entry = _entry->next) \
			if (_entry->vtime > bucket->vtime) \
				break; \
		if (_prev_entry) { \
			bucket->next = _prev_entry->next; \
			_prev_entry->next = bucket; \
		} else { \
			bucket->next = container->first; \
			container->first = bucket; \
		} \
	}

#define vtime_container_find_or_create_bucket(container, vtime_bucket, vtime_check) \
	vtime_bucket = container->first; \
	for (vtime_bucket = container->first; vtime_bucket; vtime_bucket = vtime_bucket->next) \
		if (vtime_bucket->vtime == vtime_check) \
			break; \
	if (!vtime_bucket) { \
		vtime_bucket = (typeof(vtime_bucket)) malloc(sizeof(typeof(*vtime_bucket))); \
		vtime_bucket->first = vtime_bucket->last = NULL; \
		vtime_bucket->vtime = vtime_check; \
		vtime_container_insert_bucket(container, vtime_bucket); \
	}

#define vtime_container_find_entry(it, cmp, args...) \
	vtime_container_foreach(it) { \
		if (cmp(it.elem, args) == 1) { \
			it.stop = 1; \
			break; \
		} \
	}

#define vtime_bucket_free(bucket) \
	while (bucket->first) { \
		free(bucket->first); \
		bucket->first = bucket->first->next; \
	}

#define vtime_container_expire(container, now) \
	while (container->first) { \
		if (container->first->vtime < now) { \
			typeof(container->first) _bucket = container->first; \
			container->first = _bucket->next; \
			if (container->last == _bucket) \
				container->last = NULL; \
			vtime_bucket_free(_bucket); \
			free(_bucket); \
		} else { \
			break; \
		} \
	} \

#define vtime_container_move_to_bucket(container, it, vtime) \
	ll_remove(it.bucket, it.elem, it.prev_elem); \
	if (!it.bucket->first && !it.bucket->last) { \
		ll_remove(container, it.bucket, it.prev_bucket); \
		free(it.bucket); \
	} \
	vtime_container_find_or_create_bucket(container, it.bucket, vtime) \
	ll_append(it.bucket, it.elem)

struct node_entry {
	vtime_container(topology_set) *topology_set;
	vtime_container(hello_set) *hello_set;
	vtime_container(hna_set) *hna_set;
	vtime_container(mid_set) *mid_set;
};

struct set_entry_common {
	bool created:1;
	bool changed:1;
	bool expired:1;
};

inline void init_set_entry_common(struct set_entry_common *common);

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

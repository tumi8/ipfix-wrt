#ifndef OBJECT_CACHE_H_
#define OBJECT_CACHE_H_

#include <stddef.h>
#include <stdint.h>

#define OBJECT_CACHE_DEBUG
struct object_cache;

struct object_cache *init_object_cache(uint16_t max_entries,
									   size_t entry_size);
void free_object_cache(struct object_cache *cache);
void *allocate_object(struct object_cache *cache);
void release_object(struct object_cache *cache, void *obj);
#ifdef OBJECT_CACHE_DEBUG
void object_cache_statistics(struct object_cache *cache);
#endif
#endif

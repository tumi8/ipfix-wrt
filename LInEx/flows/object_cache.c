#include "object_cache.h"
#include "../ipfixlolib/msg.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

struct object_cache_entry {
	void *data;
};

struct object_cache {
	uint16_t max_entries;
	size_t entry_size;
	uint16_t first_taken_entry;
	uint16_t first_free_entry;
#ifdef OBJECT_CACHE_DEBUG
	uint64_t malloc_count;
	uint64_t reuse_count;
#endif
	void **entries;
};

/**
  * Initializes a new object cache structure.
  *
  * The memory taken by the object cache is equal to sizeof(struct object_cache)
  * + max_entries * sizeof(void *).
  *
  * \param max_entries The maximum number of unclaimed instances to keep around.
  * \param entry_size The size of an entry which is stored in this object cache.
  */
struct object_cache *init_object_cache(uint16_t max_entries,
									   size_t entry_size) {
	struct object_cache *cache =
			(struct object_cache *) malloc(sizeof(struct object_cache));
	if (!cache)
		return NULL;
	cache->max_entries = max_entries;
	cache->first_taken_entry = 0;
	cache->first_free_entry = 0;
#ifdef OBJECT_CACHE_DEBUG
	cache->malloc_count = 0;
	cache->reuse_count = 0;
#endif
	cache->entry_size = entry_size;
	if (max_entries == 0) {
		cache->entries = NULL;
	} else {
		cache->entries = (void **) malloc(max_entries * sizeof(void *));
		size_t i;
		for (i = 0; i < max_entries; i++) {
			void **ptr = cache->entries + i;
			*ptr = NULL;
		}
	}

	return cache;
}

/**
  * Frees all memory claimed by this object cache.
  */
void free_object_cache(struct object_cache *cache) {
	if (cache->entries)
		free(cache->entries);
	free(cache);
}

/**
  * Returns a pointer to an unused memory region of the \a entry_size specified
  * in the initialization method.
  *
  * \returns A pointer to the memory region or NULL if memory could not be
  *          allocated.
  */
void *allocate_object(struct object_cache *cache) {
	if (cache->entries != NULL) {
		void **entry = cache->entries + cache->first_taken_entry;
		if (*entry) {

			void *obj = *entry;
			*entry = NULL;
			cache->first_taken_entry =
					(cache->first_taken_entry + 1) % cache->max_entries;
#ifdef OBJECT_CACHE_DEBUG
			cache->reuse_count = cache->reuse_count + 1;
#endif
			return obj;
		}
	}

#ifdef OBJECT_CACHE_DEBUG
	cache->malloc_count++;
#endif
	return malloc(cache->entry_size);
}


/**
  * Releases the memory occupied by \a obj.
  */
void release_object(struct object_cache *cache, void *obj) {
	void **entry = cache->entries + cache->first_free_entry;
	if (cache->entries == NULL || *entry != NULL) {

		free(obj);
		return;
	}

	*entry = obj;
	cache->first_free_entry =
			(cache->first_free_entry + 1) % cache->max_entries;
}

void object_cache_statistics(struct object_cache *cache) {
	printf("Malloc count: %llu Reuse count: %llu\n",
			cache->malloc_count,
			cache->reuse_count);
}

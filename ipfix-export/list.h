/*
 * list
 *
 *  Created on: 06.12.2009
 *      Author: kami
 *
 * This library is a minimal implementation of a doubly linked list.
 * It only supports the methods to create a list and to append an element to it.
 * Since these two methods suffice for the config file data structure, no other methods,
 * like removing elements, were implemented.
 */

#ifndef LIST_
#define LIST_

/**
 * A doubly linked list node. Contains a pointer to the next and previous
 * node and a pointer to the payload data.
 */
typedef struct lnode {
		void* data;
		struct lnode *next;
		struct lnode *prev;
	} list_node;

/**
 * A doubly linked list. Contains the <size> of the list and a pointer to the
 * <first> and <last> element of the list.
 */
typedef struct {
		list_node* first;
		list_node* last;
		int size;
} list;

/**
 * Insert a new data element into a list
 */
list_node* list_insert(list* list, void* data);

/**
 * Create a new list
 */
list* list_create();

#endif /* LIST_ */

/*
 * list
 *
 *  Created on: 06.12.2009
 *      Author: kami
 */

#ifndef LIST_
#define LIST_

typedef struct lnode {
		void* data;
		struct lnode *next;
		struct lnode *prev;
	} list_node;

typedef struct {
		list_node* first;
		list_node* last;
		int size;
} list;

list_node* list_insert(list* list, void* data);
list* list_create();
#endif /* LIST_ */

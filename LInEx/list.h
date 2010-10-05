/*
 * LInEx - Lightweight Information Export
 * Copyright (C) 2010 Vermont Project (http://vermont.berlios.de)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

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

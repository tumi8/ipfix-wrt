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

#include <stdio.h>
#include <stdlib.h>

#include "list.h"

int debug = 0;

list* list_create(){
	list* l = (list*)malloc(sizeof(list));
	l->size = 0;
	l->first = NULL;
	l->last = NULL;
	return l;
}

list_node* list_insert(list* list, void* data){
	list_node* new_node = (list_node*)malloc(sizeof(list_node));
	new_node->data = data;
	if(list->size == 0){
		list->first = new_node;
		list->last = new_node;
		new_node->prev = NULL;
		new_node->next = NULL;
	} else {
		list_node* last = list->last;
		last->next = new_node;
		new_node->prev = last;
		new_node->next = NULL;
		list->last = new_node;
	}
	list->size = list->size + 1;
	return new_node;
}


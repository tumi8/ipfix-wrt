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
	}
	list->size = list->size + 1;
	return new_node;
}


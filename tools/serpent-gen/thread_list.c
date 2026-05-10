#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "thread_list.h"

void
thread_list_join_destroy(struct thread_list *list) {
	struct thread_list_node *current = list->head;
	while (current) {
		thrd_join(current->thread, nullptr);
		free(current->arg);
		current->arg = nullptr;
		current->thread = nullptr;
		current = current->next;
	}

	current = list->head;
	while (list->head) {
		current = list->head;
		list->head = current->next;

		free(current);
	}
	list->tail = nullptr;
	mtx_destroy(&list->lock);
}

int
thread_list_add(struct thread_list *list,
    int (*fn)(void *), void *arg, size_t arg_sz) {
	struct thread_list_node *node;
	int error;
	
	if (!(node = malloc(sizeof(struct thread_list_node))))
		return errno;

	if (!(node->arg = malloc(arg_sz))) {
		free(node);
		return errno;
	}

	memcpy(node->arg, arg, arg_sz);
	node->arg_sz = arg_sz;

	mtx_lock(&list->lock);

	node->threadnum = list->lastnum + 1;
	if (list->tail)
		node->next = list->tail->next;
	else
		node->next = nullptr;
	error = thrd_create(&node->thread, fn, node->arg);
	if (error) {
		free(node->arg);
		free(node);
		mtx_unlock(&list->lock);
		return error;
	}
	if (list->tail)	list->tail->next = node;
	if (!list->head) list->head = node;
	list->tail = node;
	list->lastnum++;

	mtx_unlock(&list->lock);

	return 0;
}

unsigned
thread_list_num_of(struct thread_list *list, thrd_t thread) {
	struct thread_list_node	*current;
	unsigned		threadnum = -1;

	mtx_lock(&list->lock);
	current = list->head;
	while (current) {
		if (current->thread == thread)
			threadnum = current->threadnum;
		current = current->next;
	}
	mtx_unlock(&list->lock);
	return threadnum;
}

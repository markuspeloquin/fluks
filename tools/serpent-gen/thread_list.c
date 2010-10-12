#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "thread_list.h"

void
thread_list_join_destroy(struct thread_list *list)
{
	struct thread_list_node *current = list->head;
	while (current) {
		pthread_join(current->thread, 0);
		free(current->arg);
		current->arg = 0;
		current->thread = 0;
		current = current->next;
	}

	current = list->head;
	while (list->head) {
		current = list->head;
		list->head = current->next;

		free(current);
	}
	list->tail = 0;
	pthread_mutex_destroy(&list->lock);
}

int
thread_list_add(struct thread_list *list,
    void *(*fn)(void *), void *arg, size_t arg_sz)
{
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

	pthread_mutex_lock(&list->lock);

	node->threadnum = list->lastnum + 1;
	if (list->tail)
		node->next = list->tail->next;
	else
		node->next = 0;
	error = pthread_create(&node->thread, 0, fn, node->arg);
	if (error) {
		free(node->arg);
		free(node);
		pthread_mutex_unlock(&list->lock);
		return error;
	}
	if (list->tail)	list->tail->next = node;
	if (!list->head) list->head = node;
	list->tail = node;
	list->lastnum++;

	pthread_mutex_unlock(&list->lock);

	return 0;
}

unsigned
thread_list_num_of(struct thread_list *list, pthread_t thread)
{
	struct thread_list_node	*current;
	unsigned		threadnum = -1;

	pthread_mutex_lock(&list->lock);
	current = list->head;
	while (current) {
		if (current->thread == thread)
			threadnum = current->threadnum;
		current = current->next;
	}
	pthread_mutex_unlock(&list->lock);
	return threadnum;
}

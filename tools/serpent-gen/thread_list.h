#ifndef THREAD_LIST_H
#define THREAD_LIST_H

#include <pthread.h>
#include <stddef.h>

struct thread_list_node {
	void		*arg;
	size_t		arg_sz;
	pthread_t	thread;
	unsigned	threadnum;

	struct thread_list_node *next;
};

struct thread_list {
	pthread_mutex_t		lock;
	struct thread_list_node	*head, *tail;
	unsigned		lastnum;
};


static inline void
		thread_list_init(struct thread_list *);
void		thread_list_join_destroy(struct thread_list *);

int		thread_list_add(struct thread_list *,
		    void *(*fn)(void *), void *arg, size_t arg_sz);

static inline unsigned
		thread_list_nextnum(struct thread_list *);
unsigned	thread_list_num_of(struct thread_list *, pthread_t);



static inline void
thread_list_init(struct thread_list *list)
{
	pthread_mutex_init(&list->lock, 0);
	list->head = list->tail = 0;
	list->lastnum = -1; /* actually UINT_MAX */
}

static inline unsigned
thread_list_nextnum(struct thread_list *list)
{
	unsigned next;
	pthread_mutex_lock(&list->lock);
	next = list->lastnum + 1;
	pthread_mutex_unlock(&list->lock);
	return next;
}

#endif

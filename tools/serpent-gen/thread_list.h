#ifndef THREAD_LIST_H
#define THREAD_LIST_H

#include <stddef.h>
#include <threads.h>

struct thread_list_node {
	void		*arg;
	size_t		arg_sz;
	thrd_t		thread;
	unsigned	threadnum;

	struct thread_list_node *next;
};

struct thread_list {
	mtx_t			lock;
	struct thread_list_node	*head, *tail;
	unsigned		lastnum;
};


static inline void
		thread_list_init(struct thread_list *);
void		thread_list_join_destroy(struct thread_list *);

int		thread_list_add(struct thread_list *,
		    int (*fn)(void *), void *arg, size_t arg_sz);

static inline unsigned
		thread_list_nextnum(struct thread_list *);
unsigned	thread_list_num_of(struct thread_list *, thrd_t);



static inline void
thread_list_init(struct thread_list *list) {
	mtx_init(&list->lock, mtx_plain);
	list->head = list->tail = nullptr;
	list->lastnum = -1; /* actually UINT_MAX */
}

static inline unsigned
thread_list_nextnum(struct thread_list *list) {
	unsigned next;
	mtx_lock(&list->lock);
	next = list->lastnum + 1;
	mtx_unlock(&list->lock);
	return next;
}

#endif

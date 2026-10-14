#ifndef OPENFORTIVPN_THREAD_GROUP_H
#define OPENFORTIVPN_THREAD_GROUP_H
#include <pthread.h>
#include <errno.h>
#include <stddef.h>

struct ofv_thread_group {
	pthread_t threads[5];
	size_t count;
};
typedef int (*ofv_thread_creator)(pthread_t *, const pthread_attr_t *,
                                  void *(*)(void *), void *);

static inline int ofv_thread_start(struct ofv_thread_group *group,
                                   void *(*entry)(void *), void *arg,
                                   ofv_thread_creator create)
{
	int result;

	if (group->count == 5)
		return EAGAIN;
	result = create(&group->threads[group->count], NULL, entry, arg);
	if (!result)
		group->count++;
	return result;
}

/* The caller first unblocks cooperative workers; Unix can instead cancel.
 * Join only successfully created handles, including partial startup failure.
 */
static inline int ofv_thread_join(struct ofv_thread_group *group,
                                  int cancel)
{
	int failed = 0;

	if (cancel)
		for (size_t i = group->count; i > 0; i--)
			if (pthread_cancel(group->threads[i - 1]))
				failed = 1;
	for (size_t i = group->count; i > 0; i--)
		if (pthread_join(group->threads[i - 1], NULL))
			failed = 1;
	group->count = 0;
	return failed;
}
#endif

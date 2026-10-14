#include "thread_group.h"
#include "exit_codes.h"
#include "io.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <unistd.h>

static int failure_at, attempts, live;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int create_worker(pthread_t *thread, const pthread_attr_t *attr,
                         void *(*entry)(void *), void *arg)
{
	if (attempts++ == failure_at)
		return EAGAIN;
	return pthread_create(thread, attr, entry, arg);
}
static void exited(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&lock);
	live--;
	pthread_mutex_unlock(&lock);
}
static void *worker(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&lock);
	live++;
	pthread_mutex_unlock(&lock);
	pthread_cleanup_push(exited, NULL);
	while (1)
		usleep(1000);
	pthread_cleanup_pop(1);
	return NULL;
}
static void *pool_waiter(void *pool)
{
	return ofv_pool_pop(pool);
}
int main(void)
{
	for (failure_at = 0; failure_at <= 5; failure_at++) {
		struct ofv_thread_group group = {0};

		attempts = 0;
		for (int i = 0; i < 5; i++)
			if (ofv_thread_start(&group, worker, NULL, create_worker))
				break;
		assert(group.count == (size_t)failure_at);
		assert(ofv_thread_join(&group, 1) == 0);
		assert(live == 0);
		assert(ofv_thread_join(&group, 1) == 0);
	}
	assert(ofv_exit_retryable(OFV_EXIT_TCP_FAILED));
	assert(!ofv_exit_retryable(OFV_EXIT_AUTH_FAILED));
	assert(!ofv_exit_retryable(OFV_EXIT_CONFIG_FAILED));
	{
		struct ppp_packet_pool pool;
		struct ofv_thread_group group = {0};

		init_ppp_packet_pool(&pool);
		assert(ofv_thread_start(&group, pool_waiter, &pool,
		                        pthread_create) == 0);
		usleep(10000);
		assert(ofv_thread_join(&group, 1) == 0);
		assert(pthread_mutex_trylock(&pool.mutex) == 0);
		pthread_mutex_unlock(&pool.mutex);
		destroy_ppp_packet_pool(&pool);
	}
	return 0;
}

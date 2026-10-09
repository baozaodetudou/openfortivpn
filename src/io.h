/*
 *  Copyright (c) 2015 Adrien Vergé
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef OPENFORTIVPN_IO_H
#define OPENFORTIVPN_IO_H

#ifndef _WIN32
#include <sys/types.h>
#endif
#include <pthread.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * For performance reasons, we store the 6-byte header used by the TLS
 * communication right in front of the real PPP packet data. This way,
 * SSL_write can be called directly on packet->content, instead of memcpy'ing
 * the header + data to a temporary buffer.
 */
struct ppp_packet {
	struct ppp_packet *next;
	size_t len; // length of data; actual length is 6 + len
	uint8_t content[];
};
#define pkt_header(packet)	((packet)->content)
#define pkt_data(packet)	((packet)->content + 6)

struct ppp_packet_pool {
	pthread_mutex_t mutex;
	pthread_cond_t new_data;
	struct ppp_packet *list_head;
};

#define init_ppp_packet_pool(pool) \
	do { \
		pthread_mutex_init(&(pool)->mutex, NULL); \
		pthread_cond_init(&(pool)->new_data, NULL); \
		(pool)->list_head = NULL; \
	} while (0)

/* Call only after every producer/consumer has joined. */
static inline void destroy_ppp_packet_pool(struct ppp_packet_pool *pool)
{
	while (pool->list_head) {
		struct ppp_packet *packet = pool->list_head;
		pool->list_head = packet->next;
		free(packet);
	}
	pthread_cond_destroy(&pool->new_data);
	pthread_mutex_destroy(&pool->mutex);
}

#ifndef _WIN32
static inline void ofv_pool_unlock(void *mutex)
{
	pthread_mutex_unlock((pthread_mutex_t *)mutex);
}

static inline struct ppp_packet *ofv_pool_pop(struct ppp_packet_pool *pool)
{
	struct ppp_packet *first;
	pthread_mutex_lock(&pool->mutex);
	/* cond_wait reacquires the mutex before cancellation cleanup runs. */
	pthread_cleanup_push(ofv_pool_unlock, &pool->mutex);
	while (pool->list_head == NULL)
		pthread_cond_wait(&pool->new_data, &pool->mutex);
	first = pool->list_head;
	pool->list_head = first->next;
	first->next = NULL;
	pthread_cleanup_pop(1);
	return first;
}
#endif

struct tunnel;

int io_loop(struct tunnel *tunnel);

int get_sig_received(void);

#endif

#include "event_loop.h"
#include "ipfixlolib/msg.h"


#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <sys/time.h>

struct dynamic_array {
	/**
	  * Size of one item in the array.
	  */
	size_t item_size;

	/**
	  * Number of set items in the array.
	  */
	size_t size;

	/**
	  * Total amount of space allocated in this array.
	  */
	size_t space;

	/**
	  * Buffer in which the array items are stored.
	  */
	char *buffer;
};

struct event_loop_fd_entry {
	int fd;
	event_fd_callback callback;
	event_fd_error_callback error_callback;
	void *user_param;
};

struct event_loop_timer_entry {
	uint32_t ms_timeout;
	event_timer_callback callback;
	void *user_param;
	struct timeval next_run;
};

struct event_loop {
	struct pollfd *fds;

	uint32_t min_timer_value;

	struct dynamic_array fd_entries;
	struct dynamic_array timer_entries;
};

struct event_loop global_event_loop = {
	NULL, // fds
	4294967295U, // min_timer_value
	{ sizeof(struct event_loop_fd_entry), 0, 0, NULL }, // fd_entries
	{ sizeof(struct event_loop_timer_entry), 0, 0, NULL } // timer_entries
};

static char *array_alloc_new_item(struct dynamic_array *array) {
	if (array->buffer == NULL) {
		array->buffer = malloc(array->item_size);

		if (array->buffer == NULL)
			return NULL;

		array->space = 1;
	} else if (array->space == array->size) {
		void *new_buffer = realloc(array->buffer, array->item_size * (array->space + 1));

		if (new_buffer == NULL)
			return NULL;

		array->buffer = new_buffer;
		array->space++;
	}

	array->size++;

	return array->buffer + ((array->size - 1) * array->item_size);
}

static int array_remove_item(struct dynamic_array *array, uint32_t index) {
	if (index >= array->size)
		return -1;

	array->size--;


	memmove(array->buffer + (index * array->item_size),
			array->buffer + ((index + 1) * array->item_size),
			array->item_size * (array->size - index));

	if (array->space - array->size >= 4) {
		char *new_buffer = realloc(array->buffer, array->item_size * array->size);

		if (new_buffer != NULL) {
			array->buffer = new_buffer;
			array->space = array->size;
		}
	}

	return 0;
}

static void add_time(const struct timeval *source, struct timeval *dest, uint32_t ms_time) {
	dest->tv_usec = source->tv_usec + (ms_time * 1000);
	dest->tv_sec = source->tv_sec + (dest->tv_usec / 1000000);
	dest->tv_usec %= 100000;
}

int event_loop_add_fd(int fd,
					  event_fd_callback callback,
					  event_fd_error_callback error_callback,
					  void *user_param) {
	struct event_loop_fd_entry *fd_entry =
			(struct event_loop_fd_entry *) array_alloc_new_item(&global_event_loop.fd_entries);

	if (fd_entry == NULL)
		return -1;

	if (global_event_loop.fds == NULL) {
		global_event_loop.fds = (struct pollfd *) malloc(sizeof(struct pollfd));

		if (global_event_loop.fds == NULL)
			return -1;
	} else {
		struct pollfd *fds =
				(struct pollfd *) realloc(global_event_loop.fds, sizeof(struct pollfd) * (global_event_loop.fd_entries.size));

		if (fds == NULL)
			return -1;

		global_event_loop.fds = fds;
	}

	fd_entry->fd = fd;
	fd_entry->callback = callback;
	fd_entry->error_callback = error_callback;
	fd_entry->user_param = user_param;

	struct pollfd *poll_fd = (global_event_loop.fds + global_event_loop.fd_entries.size - 1);

	poll_fd->fd = fd;
	poll_fd->events = POLLIN;

	return 0;
}

int event_loop_add_timer(uint32_t ms_timeout, event_timer_callback callback, void *user_param) {
	struct event_loop_timer_entry *timer_entry = (struct event_loop_timer_entry *) array_alloc_new_item(&global_event_loop.timer_entries);

	if (timer_entry == NULL)
		return -1;

	timer_entry->ms_timeout = ms_timeout;
	timer_entry->callback = callback;
	timer_entry->user_param = user_param;

	gettimeofday(&timer_entry->next_run, NULL);

	add_time(&timer_entry->next_run, &timer_entry->next_run, ms_timeout);

	if (ms_timeout < global_event_loop.min_timer_value) {
		global_event_loop.min_timer_value = ms_timeout;
	}

	return 0;
}

int event_loop_run() {
	int timeout = global_event_loop.min_timer_value;

	while (1) {
		int ret = poll(global_event_loop.fds, global_event_loop.fd_entries.size, timeout);

		if (ret == -1) {
			msg(MSG_ERROR, "Error occured while polling: %s", strerror(errno));
			continue;
		}

		if (ret > 0) {
			// At least one file descriptor is ready for reading
			size_t i;

			for (i = 0; i < global_event_loop.fd_entries.size; i++) {
				struct event_loop_fd_entry *fd_entry =
						((struct event_loop_fd_entry *) global_event_loop.fd_entries.buffer) + i;
				struct pollfd *fd = global_event_loop.fds + i;

				// DPRINTF("%d", fd->revents);
				if (fd->revents & POLLIN)
					(*fd_entry->callback)(fd_entry->fd, fd_entry->user_param);
				else if (fd->revents & (POLLERR | POLLHUP | POLLNVAL)) {
					if (fd_entry->error_callback)
						(*fd_entry->error_callback)(fd_entry->fd, fd_entry->user_param);

					// Remove from event loop
					array_remove_item(&global_event_loop.fd_entries, i);

					// Remove from pollfd list
					memmove(global_event_loop.fds + i,
							global_event_loop.fds + i + 1,
							global_event_loop.fd_entries.size - i);
					global_event_loop.fds =
							(struct pollfd *) realloc(global_event_loop.fds,
													  sizeof(struct pollfd) * (global_event_loop.fd_entries.size));
					i--;
				}
			}
		}

		size_t i;
		struct timeval now;
		int diff;
		timeout = global_event_loop.min_timer_value;
		gettimeofday(&now, NULL);

		for (i = 0; i < global_event_loop.timer_entries.size; i++) {
			struct event_loop_timer_entry *timer_entry = ((struct event_loop_timer_entry *) global_event_loop.timer_entries.buffer) + i;

			if (timer_entry->next_run.tv_sec < now.tv_sec || (timer_entry->next_run.tv_sec == now.tv_sec && timer_entry->next_run.tv_usec <= now.tv_usec)) {
				DPRINTF("Running timer due to expiry");

				(*timer_entry->callback)(timer_entry->user_param);

				add_time(&now, &timer_entry->next_run, timer_entry->ms_timeout);
			}

			diff = (timer_entry->next_run.tv_sec - now.tv_sec) * 1000 + (timer_entry->next_run.tv_usec - now.tv_usec) / 1000;

			if (diff < timeout && diff != 0)
				timeout = diff;
		}
	}

	return 0;

}

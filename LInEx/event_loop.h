#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <stdint.h>

typedef void(*event_fd_callback)(int fd, void *user_param);
typedef void(*event_timer_callback)(void *user_param);

int event_loop_add_fd(int fd, event_fd_callback callback, void *user_param);
int event_loop_add_timer(uint32_t ms_timeout, event_timer_callback callback, void *user_param);
int event_loop_run();

#endif

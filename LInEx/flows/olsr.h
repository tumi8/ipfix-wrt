#ifndef OLSR_H_
#define OLSR_H_

struct capture_info;
struct capture_session;

struct capture_info *olsr_add_capture_interface(struct capture_session *session,
												const char *interface);

#endif

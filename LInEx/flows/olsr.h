#ifndef OLSR_H_
#define OLSR_H_

struct capture_info;
struct capture_session;

#define PACKET_MMAP_OLSR_BLOCK_NR 16

struct capture_info *olsr_add_capture_interface(struct capture_session *session,
												const char *interface);

#endif

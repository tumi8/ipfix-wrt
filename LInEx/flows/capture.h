#ifndef CAPTURE_H_
#define CAPTURE_H_

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>
#include <sys/time.h>
#include <stdbool.h>

#define MAXIMUM_INTERFACE_COUNT 2

struct capture_info {
	/**
	  * The file descriptor of the socket.
	  */
	int fd;
	/**
	  * The name of the interface.
	  */
	char interface_name[IFNAMSIZ];
#ifdef SUPPORT_PACKET_MMAP
	/**
	  * Current frame.
	  */
	uint8_t *current_frame;
	/**
	  * Total number of frames which the buffer can hold.
	  */
	uint16_t frame_nr;
	/**
	  * Size of a single frame in the buffer.
	  */
	uint16_t frame_size;
	/**
	  * Pointer to buffer.
	  */
	uint8_t *buffer;

	/**
	  * Pointer to end of buffer.
	  */
	uint8_t *buffer_end;
#else
	/**
	  * The number of bytes which should be captured.
	  */
	size_t snapshot_len;
#endif
};

struct capture_session {
	size_t interface_count;
	struct capture_info *interfaces[MAXIMUM_INTERFACE_COUNT];
};

struct capture_statistics {
	/**
	  * Total number of packets captured since last call to capture_statistics.
	  */
	uint32_t total_captured;
	/**
	  * Amount of packets dropped since last call to capture_statistics.
	  */
	uint32_t total_dropped;
};

struct sock_fprog;

struct capture_session *start_capture_session();
bool contains_interface(struct capture_session *session,
						const char *interface_name);
void remove_capture_interface(struct capture_session *session,
							  struct capture_info *info);
void free_capture_session(struct capture_session *session);
struct capture_info *start_capture(struct capture_session *session,
								   const char *interface, size_t snapshot_len,
								   struct sock_fprog *filter,
								   uint32_t buffer_size);
void stop_capture(struct capture_info *info);
uint8_t *capture_packet(struct capture_info *info, size_t *len, size_t *orig_len, struct timeval *tp, bool first_call);
void capture_packet_done(struct capture_info *info);
int capture_statistics(const struct capture_info *info,
					   struct capture_statistics *statistics);
#endif

#ifndef CAPTURE_H_
#define CAPTURE_H_

#include <stdint.h>
#include <stddef.h>

#ifdef SUPPORT_PACKET_MMAP
// TODO - Experiment which value fits best
#define PACKET_MMAP_BLOCK_NR 16
#endif

struct capture_info {
	/**
	  * The file descriptor of the socket.
	  */
	int fd;
#ifdef SUPPORT_PACKET_MMAP
	/**
	  * Total number of frames which the buffer can hold.
	  */
	uint16_t frame_nr;
	/**
	  * Current frame number.
	  */
	uint16_t current_frame_nr;
	/**
	  * Size of a single frame in the buffer.
	  */
	uint16_t frame_size;
	/**
	  * Pointer to buffer.
	  */
	uint8_t *buffer;
#else
	/**
	  * The number of bytes which should be captured.
	  */
	size_t snapshot_len;
#endif
};

struct sock_fprog;

struct capture_info *start_capture(const char *interface, size_t snapshot_len,
								   struct sock_fprog *filter);
void stop_capture(struct capture_info *info);
uint8_t *capture_packet(struct capture_info *info, size_t *len, size_t *orig_len);
void capture_packet_done(struct capture_info *info);
#endif

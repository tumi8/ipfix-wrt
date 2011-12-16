#include "capture.h"
#include "iface.h"
#include "../ipfixlolib/msg.h"

#include <sys/socket.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef SUPPORT_PACKET_MMAP
#include <sys/user.h>
#include <sys/mman.h>
#else
#include <fcntl.h>
#endif
#ifdef __mips__
#include <sys/cachectl.h>
#include <asm/cachectl.h>
#endif
static int setup_interface(const char *device_name,
						   bool enable_promisc,
						   int *if_index,
						   int *if_mtu);

#ifndef SUPPORT_PACKET_MMAP
/**
  * Buffer which holds the received packets.
  */
static uint8_t *packet_buffer = 0;
static size_t packet_buffer_size = 0;
#endif

struct capture_session *start_capture_session() {
	struct capture_session *session =
			(struct capture_session *) malloc (sizeof(struct capture_session));
	if (!session)
		return NULL;

	session->interface_count = 0;

	return session;
}

bool contains_interface(struct capture_session *session,
						const char *interface_name) {
	size_t index;

	for (index = 0; index < session->interface_count; index++) {
		if (strcmp(session->interfaces[index]->interface_name, interface_name) == 0)
			return 1;
	}

	return 0;
}

void remove_capture_interface(struct capture_session *session,
							  struct capture_info *info) {
	size_t index;

	for (index = 0; index < session->interface_count; index++) {
		if (session->interfaces[index] == info)
			break;
	}

	if (session->interfaces[index] != info)
		return;

	stop_capture(session->interfaces[index]);

	session->interface_count--;

	memmove(session->interfaces,
			session->interfaces + index + 1,
			session->interface_count - index);
}

void free_capture_session(struct capture_session *session) {
	size_t i;
	for (i = 0; i < session->interface_count; i++) {
		stop_capture(session->interfaces[i]);
		free(session->interfaces[i]);
	}

	free(session);
}

/**
  * Starts capturing on the given interface. If a snapshot length is specified
  * (i.e. it is set to a value larger than 0) packets may be truncated to
  * that length.
  *
  * \return A capture_info struct containing a file descriptor which can be
  *         polled for incoming data or NULL if something went wrong.
  */
struct capture_info *start_capture(struct capture_session *session,
								   const char *interface, size_t snapshot_len,
								   struct sock_fprog *filter,
								   uint32_t buffer_size) {
	if (session->interface_count >= MAXIMUM_INTERFACE_COUNT) {
		msg(MSG_ERROR, "Maximum interface count (%d) for this session has been reached.", MAXIMUM_INTERFACE_COUNT);
		return NULL;
	}

	int index = 0, mtu = 0;

	if (setup_interface(interface, true, &index, &mtu))
		return NULL;

	if (snapshot_len == 0)
		snapshot_len = mtu;

	// Use SOCK_RAW rather than SOCK_DGRAM - otherwise the BPF filters do not work
	int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (fd == -1) {
		msg(MSG_ERROR, "Failed to open raw socket for interface %s.", interface);
		return NULL;
	}

	struct capture_info *info =
			(struct capture_info *) malloc (sizeof(struct capture_info));

#ifdef SUPPORT_PACKET_MMAP
	struct tpacket_req req = {
		PAGE_SIZE, // tp_block_size
		buffer_size, // tp_block_nr:
		snapshot_len, // tp_frame_size
		buffer_size * (PAGE_SIZE / snapshot_len) // tp_frame_nr
	};

	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *) &req, sizeof(req))) {
		msg(MSG_ERROR, "Failed to setup PACKET_RX_RING (make sure that PAGE_SIZE is an integral multiple of snapshot_len): %s", strerror(errno));
		close(fd);
		free(info);
		return NULL;
	}

	void *buffer = mmap(0, req.tp_block_size * req.tp_block_nr,
						PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buffer == MAP_FAILED) {
		msg(MSG_ERROR, "mmap failed to allocate buffer: %s", strerror(errno));
		close(fd);
		free(info);
		return NULL;
	}

	// Attempt to clear buffer
	memset(buffer, 0, req.tp_block_size * req.tp_block_nr);


	info->frame_nr = req.tp_frame_nr;
	info->frame_size = req.tp_frame_size;
	info->buffer = buffer;
	info->buffer_end = buffer + (info->frame_nr * info->frame_size);
	info->current_frame = buffer;
#else
	if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
		msg(MSG_ERROR, "Failed to put raw socket in non-blocking mode.");
		close(fd);
		free(info);
		return NULL;
	}
	int rcvbuf_size = buffer_size * 4096;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) == -1) {
		msg(MSG_ERROR, "Failed to set receive buffer size.");
		close(fd);
		free(info);
		return NULL;
	}
	msg(MSG_INFO, "Using receive buffer of %d bytes.", rcvbuf_size);
#endif

	// Clear packet statistics
	struct tpacket_stats kstats;
	socklen_t kstats_len = sizeof(kstats);
	if (getsockopt(info->fd, SOL_PACKET, PACKET_STATISTICS,
				   &kstats, &kstats_len)) {

	}

	if (filter->filter != NULL) {
		if (setsockopt(fd, SOL_SOCKET,  SO_ATTACH_FILTER, filter, sizeof(struct sock_fprog)) == -1) {
			msg(MSG_ERROR, "Failed to attach filter to file descriptor (%s)", strerror(errno));
			close(fd);
			free(info);
			return NULL;
		}
	}

	union {
		struct sockaddr_ll ll;
		struct sockaddr addr;
	} addr;

	memset(&addr, 0, sizeof(addr));

	addr.ll.sll_family = PF_PACKET;
	addr.ll.sll_ifindex = index;
	addr.ll.sll_protocol = htons(ETH_P_ALL);

	if (bind(fd, &addr.addr, sizeof(struct sockaddr_ll))) {
		msg(MSG_ERROR, "Failed to bind raw socket to interface %s (%s).",
			interface, strerror(errno));

		close(fd);
		free(info);
		return NULL;
	}

#ifndef SUPPORT_PACKET_MMAP
	// Create or reallocate packet buffer
	if (packet_buffer == NULL || packet_buffer_size < snapshot_len) {
		if (packet_buffer != NULL)
			free(packet_buffer);

		packet_buffer = (uint8_t *) malloc(mtu);

		if (packet_buffer == NULL) {
			msg(MSG_ERROR, "Failed to allocate packet buffer.");

			close(fd);
			free(info);
			return NULL;
		}

		packet_buffer_size = snapshot_len;
	}
	info->snapshot_len = snapshot_len;
#endif

	info->fd = fd;
	strncpy(info->interface_name, interface, sizeof(info->interface_name));
	info->interface_name[sizeof(info->interface_name) - 1] = 0;

	session->interfaces[session->interface_count] = info;
	session->interface_count++;

	return info;
}

/**
  * Stops capturing on the given file descriptor.
  *
  * Note: This function frees the memory occupied by the given \a info
  *       structure.
  */
void stop_capture(struct capture_info *info) {
	close(info->fd);
}

/**
  * Attempts to capture a packet from the capture info structure. The length
  * of the buffer is written into the len variable. The \a orig_len parameter
  * holds the original length of the packet.
  *
  * \returns A pointer to the beginning of the packet or NULL if an error
  *          occured or no data was ready.
  */
uint8_t *capture_packet(struct capture_info *info, size_t *len, size_t *orig_len, struct timeval *tp, bool first_call) {
#ifdef SUPPORT_PACKET_MMAP
	uint8_t *frame = info->current_frame;
	uint8_t *const start_frame = frame;
	struct tpacket_hdr *hdr = (struct tpacket_hdr *) frame;

	if (!hdr->tp_status && !first_call)
		return NULL;

	if (!hdr->tp_status) {
		while (!hdr->tp_status) {
			frame = frame + info->frame_size;
			if (frame >= info->buffer_end)
				frame = info->buffer;
			if (info->current_frame >= info->buffer_end)
				info->current_frame = info->buffer;

			hdr = (struct tpacket_hdr *) frame;

			if (frame == start_frame) {
				return NULL;
			}
		}

		info->current_frame = frame;
	}

	if (frame != start_frame) {
		msg(MSG_INFO, "Frame != Start frame new index is: %d started at: %d First call: %d", (info->current_frame - info->buffer) / info->frame_size, (start_frame - info->buffer) / info->frame_size, first_call);
	}

	*len = hdr->tp_snaplen;
	*orig_len = hdr->tp_len;

	// Set time
	if (tp != NULL) {
		tp->tv_sec = hdr->tp_sec;
		tp->tv_usec = hdr->tp_usec;
	}

	return (frame + hdr->tp_mac);
#else
	union {
		struct sockaddr_ll ll_addr;
		struct sockaddr addr;
	} addr;
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	*len = recvfrom(info->fd,
					packet_buffer,
					info->snapshot_len,
					0,
					(struct sockaddr *) &addr.addr,
					&addr_len);

	if (*len == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			msg(MSG_ERROR, strerror(errno));
		return NULL;
	} else if (len == 0)
		return NULL;

	if (tp != NULL)
		gettimeofday(tp, NULL);
	return packet_buffer;
#endif
}

/**
  * Callback to indicate that the previous caller of capture_packet is done
  * processing the data.
  */
void capture_packet_done(struct capture_info *info) {
#ifdef SUPPORT_PACKET_MMAP
	struct tpacket_hdr *hdr = (struct tpacket_hdr *) info->current_frame;

	hdr->tp_status = 0;

	// Advance to next frame
	info->current_frame += info->frame_size;
	if (info->current_frame >= info->buffer_end)
		info->current_frame = info->buffer;
#endif
}

/**
  * Collects statistics about current capture session which are stored into
  * \a statistics.
  *
  * \returns 0 on success or -1 on failure.
  */
int capture_statistics(const struct capture_info *info, struct capture_statistics *statistics) {
	struct tpacket_stats kstats;
	socklen_t kstats_len = sizeof(kstats);
	if (getsockopt(info->fd, SOL_PACKET, PACKET_STATISTICS,
				   &kstats, &kstats_len)) {
		return -1;
	}

	statistics->total_captured = kstats.tp_packets;
	statistics->total_dropped = kstats.tp_drops;

	return 0;
}

static int setup_interface(const char *device_name,
						   bool enable_promisc,
						   int *if_index,
						   int *if_mtu) {
	int fd = -1;
	struct ifreq req;

	if ((*if_index = iface_info(device_name, &req, &fd)) == -1)
		return -1;

	if ((*if_mtu = iface_mtu(&req, fd)) < 0) {
		close(fd);
		return -1;
	}

	if (!enable_promisc) {
		close(fd);
		return 0;
	}

	if (ioctl(fd, SIOCGIFFLAGS, &req)) {
		msg(MSG_ERROR, "Failed to retrieve interface flags for interface %s (%s).", device_name, strerror(errno));
		close(fd);
		return -1;
	}

	req.ifr_flags |= IFF_PROMISC;

	if (ioctl(fd, SIOCSIFFLAGS, &req)) {
		msg(MSG_ERROR, "Failed to enable promisicious mode for interface %s (%s).", device_name, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

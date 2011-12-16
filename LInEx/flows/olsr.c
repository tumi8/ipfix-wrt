#include "olsr.h"
#include "topology_set.h"
#include "hello_set.h"
#include "hna_set.h"
#include "mid_set.h"
#include "olsr_protocol.h"
#include "capture.h"
#include "ip_helper.h"
#include "iface.h"
#include "../event_loop.h"
#include "../ipfixlolib/msg.h"

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <net/ethernet.h>


/**
  * Compiled BPF filter: udp and dst port 698
  */
static struct sock_filter olsr_filter[] = {
	{ 0x20, 0, 0, 0x00000008 },
	{ 0x15, 0, 2, 0xbeefaaaa },
	{ 0x28, 0, 0, 0x00000006 },
	{ 0x15, 15, 0, 0x0000dead },
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 4, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 11, 0x00000011 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 8, 9, 0x000002ba },
	{ 0x15, 0, 8, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 6, 0x00000011 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 4, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x48, 0, 0, 0x00000010 },
	{ 0x15, 0, 1, 0x000002ba },
	{ 0x6, 0, 0, 0x0000ffff },
	{ 0x6, 0, 0, 0x00000000 },
};


node_set_hash *node_set = NULL;

static int olsr_parse_packet_header(const u_char **data,
									const u_char *const end_data,
									struct olsr_packet *packet_hdr);
static int olsr_parse_message(const u_char **data,
							  const u_char *const end_data,
							  struct olsr_common *message,
							  network_protocol protocol);
static int olsr_handle_hello_message(const u_char **data,
									 struct olsr_hello_message *message,
									 network_protocol protocol);
static int olsr_handle_tc_message(const u_char **data,
								  struct olsr_tc_message *message,
								  network_protocol protocol);
static int olsr_handle_hna_message(const uint8_t **data,
								   struct olsr_common *hdr,
								   network_protocol protocol);
static int olsr_handle_mid_message(const uint8_t **data,
								   struct olsr_common *hdr,
								   network_protocol protocol);
int olsr_parse_packet(struct pktinfo *pkt, network_protocol protocol);

static int parse_packet_header(struct pktinfo *pkt);
static int parse_packet_header_ipv4(struct pktinfo *pkt);
#ifdef SUPPORT_IPV6
static int parse_packet_header_ipv6(struct pktinfo *pkt);
#endif

struct olsr_callback_param {
	struct capture_session *session;
	struct capture_info *info;
};

void olsr_callback(int fd, struct olsr_callback_param *info);
void olsr_error_callback(int fd, struct olsr_callback_param *info);

struct capture_info *olsr_add_capture_interface(struct capture_session *session,
												const char *interface) {

	struct sock_fprog filter = {
		sizeof(olsr_filter) / sizeof(struct sock_filter),
		(struct sock_filter *) malloc(sizeof(olsr_filter))
	};

	struct ifreq req;
	int fd = -1;

	if (iface_info(interface, &req, &fd) == -1) {
		return NULL;
	}

	struct sockaddr hwaddr;
	if (iface_hwaddr(&req, fd, &hwaddr)) {
		close(fd);
		return NULL;
	}

	close(fd);
	const char *macaddr = hwaddr.sa_data;

	memcpy(filter.filter, olsr_filter, sizeof(olsr_filter));
	int i;
	for (i = 0; i < sizeof(olsr_filter) / sizeof(struct sock_filter); i++) {
		if (filter.filter[i].k == 0xbeefaaaa) {
			filter.filter[i].k = ntohl(*((uint32_t *) (macaddr + 2)));
		} else if (filter.filter[i].k == 0xdead) {
			filter.filter[i].k = ntohs(*((uint16_t *) macaddr));
		}
	}

	close(fd);

	struct capture_info *info = start_capture(session, interface, 2048, &filter, PACKET_MMAP_OLSR_BLOCK_NR);
	if (!info)
		return NULL;

	struct olsr_callback_param *param =
			(struct olsr_callback_param *) malloc (sizeof(struct olsr_callback_param));

	param->session = session;
	param->info = info;

	event_loop_add_fd(info->fd, (event_fd_callback) &olsr_callback,
					  (event_fd_error_callback) &olsr_error_callback, param);

	return info;
}

void olsr_callback(int fd, struct olsr_callback_param *param) {
	size_t len;
	size_t orig_len;
	uint8_t *buffer;
	bool first_call = true;

	while ((buffer = capture_packet(param->info, &len, &orig_len, NULL, first_call))) {
		struct pktinfo pkt = { buffer, buffer + len, buffer, orig_len };

		parse_packet_header(&pkt);

		capture_packet_done(param->info);
		first_call = false;
	}
}

void olsr_error_callback(int fd, struct olsr_callback_param *param) {
	remove_capture_interface(param->session, param->info);
	free(param);
}

static int parse_packet_header(struct pktinfo *pkt) {
	const struct ether_header * const hdr = (const struct ether_header * const) pkt->data;

	pkt->data += sizeof(struct ether_header);

	switch (ntohs(hdr->ether_type)) {
	case ETHERTYPE_IP:
		return parse_packet_header_ipv4(pkt);
#ifdef SUPPORT_IPV6
	case ETHERTYPE_IPV6:
		return parse_packet_header_ipv6(pkt);
#endif
	default:
		DPRINTF("Unsupported link layer protocol (%x).", ntohs(hdr->ether_type));
		return -1;
	}
}

static int parse_packet_header_ipv4(struct pktinfo *pkt) {
	if (pkt->data + sizeof(struct iphdr) > pkt->end_data) {
		msg(MSG_ERROR, "Packet too short to be a valid IPv4 packet (by %t bytes).", (pkt->data + sizeof(struct iphdr) - pkt->end_data));
		return -1;
	}

	const struct iphdr * const hdr = (const struct iphdr * const) pkt->data;

	// Determine start address of payload based on the IHL header.
	pkt->data += hdr->ihl * 4;

	if (pkt->data > pkt->end_data) {
		msg(MSG_ERROR, "Packet payload points beyond capture end.");
		return -1;
	}

	if (hdr->protocol != SOL_UDP) {
		// OLSR uses UDP
		return -1;
	}

	if (pkt->data + sizeof(struct udphdr) > pkt->end_data) {
		msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
		return -1;
	}

	pkt->data += sizeof(struct udphdr);

	return olsr_parse_packet(pkt, IPv4);
}

#ifdef SUPPORT_IPV6
static int parse_packet_header_ipv6(struct pktinfo *pkt) {
	int transport_protocol = ipv6_extract_transport_protocol(pkt);

	if (transport_protocol == -1 || transport_protocol != SOL_UDP)
		return -1;

	if (pkt->data + sizeof(struct udphdr) > pkt->end_data) {
		msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
		return -1;
	}

	pkt->data += sizeof(struct udphdr);

	return olsr_parse_packet(pkt, IPv6);
}
#endif

/**
  * Attemps to parse an OLSR packet.
  *
  * Returns 0 if the packet could be parsed sucessfully or -1 if the packet was not a valid OLSR packet.
  */
int olsr_parse_packet(struct pktinfo *pkt, network_protocol protocol) {


	struct olsr_packet packet;

    if (olsr_parse_packet_header(&pkt->data, pkt->end_data, &packet)) {
        return -1;
    }

	// DPRINTF("Packet Info: Sequence Number %d, Size: %d", packet.seqno, packet.size);

    struct olsr_common message;
    while (pkt->data < pkt->end_data) {
		if (olsr_parse_message(&pkt->data, pkt->end_data, &message, protocol)) {
            return -1;
        }

		// DPRINTF("Message Info: Type: %d Hops: %d Size: %d", message.type, message.hops, message.size);

        switch (message.type) {
        case HELLO_MESSAGE:
        case HELLO_LQ_MESSAGE: {
            struct olsr_hello_message hello_message = { message };
			if (olsr_handle_hello_message(&pkt->data, &hello_message, protocol))
                return -1;
            break;
        }
        case TC_MESSAGE:
        case TC_LQ_MESSAGE: {
            struct olsr_tc_message tc_message = { message };
			if (olsr_handle_tc_message(&pkt->data, &tc_message, protocol))
                return -1;
            break;
        }
		case HNA_MESSAGE: {
			if (olsr_handle_hna_message(&pkt->data, &message, protocol))
				return -1;
			break;
		}
		case MID_MESSAGE:
			if (olsr_handle_mid_message(&pkt->data, &message, protocol))
				return -1;
			break;
        default:
            // Unsupported message type - ignore it
            break;
        }

        // Point to the end of the message
        pkt->data = message.end;
    }


    return 0;
}

inline int compare_topology_set_entry(struct topology_set_entry *entry,
									  union olsr_ip_addr *addr,
									  network_protocol protocol) {
	if (protocol == IPv4) {
		if (entry->dest_addr.v4.s_addr == addr->v4.s_addr)
			return 1;
	} else {
#ifdef SUPPORT_IPV6
		if (memcmp(&entry->dest_addr.v6, &addr->v6, sizeof(addr->v6)))
			return 1;
#endif
	}

	return 0;
}

/**
  * Attemps to parse a TC message.
  *
  * Returns 0 on success, -1 otherwise.
  */
static int olsr_handle_tc_message(const u_char **data,
								  struct olsr_tc_message *message,
								  network_protocol protocol) {
	if (*data + OLSR_TC_MESSAGE_HEADER_LEN > message->comm.end) {
        msg(MSG_ERROR, "Packet too short to be a valid OLSR TC packet.");

        return -1;
    }

    pkt_get_u16(data, &message->ansn); // ANSN
    pkt_ignore_u16(data); // Reserved

	struct ip_addr_t addr = { protocol, message->comm.orig };
	vtime_container(topology_set) *ts;
	find_or_create_vtime_container(topology_set, ts, node_set, &addr);

    if (ts == NULL) {
        msg(MSG_ERROR, "Failed to allocate memory for topology set.");

        return -1;
    }

	vtime_container_iterator(topology_set) it;
	vtime_container_init_iterator(ts, it);

	vtime_container_foreach(it) {
		if (SEQNO_GREATER_THAN(it.elem->seq, message->ansn)) {
			msg(MSG_INFO, "Stored sequence number is larger than received packet. Ignoring TC message.");

			return 0;
		}
	}

	time_t now = time(NULL);
	time_t vtime = now + message->comm.vtime / 1e3;
    while (*data < message->comm.end) {
		union olsr_ip_addr addr;

		pkt_get_ip_address(data, &addr, protocol);

#define cmp(a, args...) compare_topology_set_entry(a, args)
		vtime_container_init_iterator(ts, it);
		vtime_container_find_entry(it, cmp, &addr, protocol);

		struct topology_set_entry *ts_entry = it.elem;
		if (!ts_entry) {
			// Create new entry
			ts_entry = (struct topology_set_entry *) malloc (sizeof(struct topology_set_entry));
			ts_entry->next = NULL;

			init_set_entry_common(&ts_entry->common);
			ts_entry->dest_addr = addr;

			vtime_container_find_or_create_bucket(ts, it.bucket, vtime)
			ll_append(it.bucket, ts_entry)
		}

		ts_entry->backoff = 0;
		ts_entry->seq = message->ansn;

        if (message->comm.type == TC_LQ_MESSAGE) {
			// The LQ value depends on the utilized LQ plugin hence we read the whole 32 bits here so they can
			// be exported as-is.


			pkt_get_u32(data, &ts_entry->lq_parameters);
		}

		if (it.bucket->vtime != vtime) {
			vtime_container_move_to_bucket(ts, it, vtime)
		}
    }

	// Update old TC entries to expire within TC_INTERVAL if we have received
	// updated information (see RFC 3626 - 9.3)
	vtime_container_init_iterator(ts, it);
	vtime_container_foreach(it) {
		if (SEQNO_GREATER_THAN(message->ansn, it.elem->seq) && !it.elem->backoff) {
			// Move to new bucket
			struct topology_set_entry *entry = it.elem;
			entry->backoff = 1;
			ll_remove_iterator(it);

			vtime_bucket(topology_set) *bucket = NULL;
			vtime_container_find_or_create_bucket(ts, bucket, now + TC_INTERVAL)
			ll_append(bucket, entry);
		}
	}

    return 0;
}


inline int compare_hello_set_entry(struct hello_set_entry *entry,
									  union olsr_ip_addr *addr,
									  network_protocol protocol) {
	if (protocol == IPv4) {
		if (entry->neighbor_addr.v4.s_addr == addr->v4.s_addr)
			return 1;
	} else {
#ifdef SUPPORT_IPV6
		if (memcmp(&entry->neighbor_addr.v6, &addr->v6, sizeof(addr->v6)))
			return 1;
#endif
	}

	return 0;
}

/**
  * Attempts to parse an OLSR HELLO message.
  *
  */
static int olsr_handle_hello_message(const u_char **data,
									 struct olsr_hello_message *message,
									 network_protocol protocol) {
    if (*data + OLSR_HELLO_MESSAGE_HEADER_LEN > message->comm.end) {
        msg(MSG_ERROR, "Packet too short to be a valid OLSR HELLO packet.");

        return -1;
    }

	time_t now = time(NULL);

	struct ip_addr_t addr = { protocol, message->comm.orig };
	vtime_container(hello_set) *hs;
	vtime_container_iterator(hello_set) it;
	find_or_create_vtime_container(hello_set, hs, node_set, &addr);

	if (hs == NULL) {
		msg(MSG_ERROR, "Failed to allocate memory for hello set.");

		return -1;
	}

    pkt_ignore_u16(data); // Reserved
    pkt_get_reltime(data, &message->htime);
    pkt_get_u8(data, &message->will);

	hs->htime = now + message->htime;
	time_t vtime = now + message->comm.vtime;

	uint32_t neighbor_entry_len = ip_addr_len(protocol);
    if (message->comm.type == HELLO_LQ_MESSAGE)
		neighbor_entry_len += 4;

    while ((*data + OLSR_HELLO_INFO_HEADER_LEN) <= message->comm.end) {
        struct olsr_hello_message_info info;
        const u_char *hello_info_end = *data;

        pkt_get_u8(data, &info.link_code.val);
        pkt_ignore_u8(data);
        pkt_get_u16(data, &info.size);

        hello_info_end += info.size;

        if (hello_info_end > message->comm.end) {
            msg(MSG_ERROR, "Neighbor list points beyond end of buffer by %t bytes.", (hello_info_end - message->comm.end));

            return -1;
        }

        while ((*data + neighbor_entry_len) <= hello_info_end) {
            union olsr_ip_addr addr;

			pkt_get_ip_address(data, &addr, protocol);

#define hs_cmp(a, args...) compare_hello_set_entry(a, args)
			vtime_container_init_iterator(hs, it);
			vtime_container_find_entry(it, hs_cmp, &addr, protocol);

			if (!it.elem) {
				it.elem = (struct hello_set_entry *) malloc(sizeof(struct hello_set_entry));
				init_set_entry_common(&it.elem->common);
				it.elem->neighbor_addr = addr;
				vtime_container_find_or_create_bucket(hs, it.bucket, vtime)
				ll_append(it.bucket, it.elem)
			}

			it.elem->link_code = info.link_code.val;

			if (message->comm.type == HELLO_LQ_MESSAGE) {
				pkt_get_u32(data, &it.elem->lq_parameters);
			}

			if (it.bucket->vtime != vtime) {
				vtime_container_move_to_bucket(hs, it, vtime)
			}
        }
    }

    return 0;

}


/**
  * Parses the OLSR packet header storing the result in the given struct.
  *
  * All values are converted to host byte-order.
  *
  * Returns 0 on success and -1 if an error occured (i.e. the packet payload was too short to contain a valid OLSR header).
  */
static int olsr_parse_packet_header(const u_char **data, const u_char *const end_data, struct olsr_packet *packet) {
    if (*data + OLSR_PACKET_HEADER_LEN > end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid OLSR packet.");

        return -1;
    }

    pkt_get_u16(data, &packet->size);
    pkt_get_u16(data, &packet->seqno);

    return 0;
}

/**
  * Parses the message beginning at the location pointed to by data.
  *
  * After this method has finished the data pointer points at the beginning
  * of the next message.
  *
  * Returns 0 on success or -1 on failure.
  */
static int olsr_parse_message(const u_char **data,
							  const u_char *const end_data,
							  struct olsr_common *message,
							  network_protocol protocol) {
	if (*data + OLSR_MESSAGE_HEADER_LEN + ip_addr_len(protocol) >= end_data) {
        msg(MSG_ERROR, "Packet too short to contain OLSR message header.");

        return -1;
    }

    const u_char *start = *data;

    pkt_get_u8(data, &message->type);
    pkt_get_reltime(data, &message->vtime);
    pkt_get_u16(data, &message->size);
	pkt_get_ip_address(data, &message->orig, protocol);
    pkt_get_u8(data, &message->ttl);
    pkt_get_u8(data, &message->hops);
    pkt_get_u16(data, &message->seqno);

    if (start + message->size > end_data) {
		msg(MSG_ERROR, "Message end points beyond input buffer by %d bytes.", (start + message->size) - end_data);

        return -1;
    }

    message->end = start + message->size;

    return 0;
}

inline int compare_hna_set_entry(struct hna_set_entry *hs_entry,
									  union olsr_ip_addr *addr,
									  uint8_t netmask,
									  network_protocol protocol) {
	if (protocol == IPv4) {
		if (hs_entry->network.v4.s_addr == addr->v4.s_addr
				&& hs_entry->netmask == netmask)
			return 1;
	} else {
#ifdef SUPPORT_IPV6
		if (memcmp(&hs_entry->network.v6, &addr->v6, sizeof(addr->v6))
				&& hs_entry->netmask == netmask)
			return 1;
#endif
	}

	return 0;
}

static int olsr_handle_hna_message(const uint8_t **data,
								   struct olsr_common *hdr,
								   network_protocol protocol) {
	uint16_t network_len = ip_addr_len(protocol);
	uint8_t prefix_len;
	union olsr_ip_addr network;
	union olsr_ip_addr netmask;
	time_t now = time(NULL);
	time_t vtime = now + hdr->vtime;

	struct ip_addr_t orig = { protocol, hdr->orig };
	vtime_container(hna_set) *hs;
	vtime_container_iterator(hna_set) it;
	find_or_create_vtime_container(hna_set, hs, node_set, &orig);

	while (*data + (2 * network_len) <= hdr->end) {
		pkt_get_ip_address(data, &network, protocol);
		pkt_get_ip_address(data, &netmask, protocol);

		// Convert netmask to prefix notation
		uint8_t *n = NULL;

		switch (protocol) {
		case IPv4:
			n = (uint8_t * ) &netmask.v4.s_addr;
			break;
#ifdef SUPPORT_IPV6
		case IPv6:
			n = netmask.v6.s6_addr;
			break;
#endif
		}

		for (prefix_len = 0; *n && prefix_len < (network_len * 8);) {
			prefix_len++;
			*n &= *n - 1;
			if (prefix_len % 8 == 0)
				n++;
		}

#define hna_cmp(a, args...) compare_hna_set_entry(a, args)
		vtime_container_init_iterator(hs, it);
		vtime_container_find_entry(it, hna_cmp, &network, prefix_len, protocol);

		if (!it.elem) {
			it.elem = (struct hna_set_entry *) malloc(sizeof(struct hna_set_entry));
			init_set_entry_common(&it.elem->common);

			it.elem->network = network;
			it.elem->netmask = prefix_len;

			vtime_container_find_or_create_bucket(hs, it.bucket, vtime)
			ll_append(it.bucket, it.elem)
		}

		if (it.bucket->vtime != vtime) {
			vtime_container_move_to_bucket(hs, it, vtime)
		}
	}

	return 0;
}

inline int compare_mid_set_entry(struct mid_set_entry *entry,
									  union olsr_ip_addr *addr,
									  network_protocol protocol) {
	if (protocol == IPv4) {
		if (entry->addr.v4.s_addr == addr->v4.s_addr)
			return 1;
	} else {
#ifdef SUPPORT_IPV6
		if (memcmp(&entry->addr.v6, &addr->v6, sizeof(addr->v6)))
			return 1;
#endif
	}

	return 0;
}

static int olsr_handle_mid_message(const uint8_t **data,
								   struct olsr_common *hdr,
								   network_protocol protocol) {
	uint16_t network_len = ip_addr_len(protocol);
	time_t vtime = time(NULL) + hdr->vtime;
	union olsr_ip_addr addr;

	struct ip_addr_t orig = { protocol, hdr->orig };
	vtime_container(mid_set) *set;
	vtime_container_iterator(mid_set) it;
	find_or_create_vtime_container(mid_set, set, node_set, &orig);

	while (*data + (2 * network_len) <= hdr->end) {
		pkt_get_ip_address(data, &addr, protocol);

#define mid_cmp(a, args...) compare_mid_set_entry(a, args)
		vtime_container_init_iterator(set, it);
		vtime_container_find_entry(it, mid_cmp, &addr, protocol);

		if (!it.elem) {
			it.elem = (struct mid_set_entry *) malloc(sizeof(struct mid_set_entry));
			it.elem->addr = addr;

			vtime_container_find_or_create_bucket(set, it.bucket, vtime)
			ll_append(it.bucket, it.elem)
		}

		if (it.bucket->vtime != vtime) {
			vtime_container_move_to_bucket(set, it, vtime)
		}
	}

	return 0;
}

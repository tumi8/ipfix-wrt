#include "flows.h"
#include "../ipfixlolib/msg.h"
#include "iface.h"
#include "ip_helper.h"
#include "object_cache.h"

#include "../event_loop.h"

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <net/if.h>
#include <stdbool.h>
#include <fcntl.h>

uint32_t crc_polynom = 0;

static uint32_t crc(uint32_t seed, uint8_t *buf, size_t len);
static int parse_ipv4(flow_capture_session *session, struct pktinfo *pkt);
#ifdef SUPPORT_IPV6
static int parse_ipv6(flow_capture_session *session, struct pktinfo *pkt);
#endif
static int parse_udp(flow_capture_session *session, struct pktinfo *pkt, flow_key *flow);
static int parse_tcp(flow_capture_session *session, struct pktinfo *pkt, flow_key *flow);

struct flow_capture_callback_param {
	flow_capture_session *session;
	struct capture_info *info;
};

void capture_callback(int fd, struct flow_capture_callback_param *param);
void capture_error_callback(int fd, struct flow_capture_callback_param *param);

/**
  * Compiled BPF filter: tcpdump -dd "not ether src de:ad:be:ef:aa:aa and (ip or ip6)"
  */
static struct sock_filter egress_filter[] = {
    { 0x20, 0, 0, 0x00000008 },
    { 0x15, 0, 2, 0xbeefaaaa },
    { 0x28, 0, 0, 0x00000006 },
    { 0x15, 4, 0, 0x0000dead },
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 1, 0, 0x00000800 },
    { 0x15, 0, 1, 0x000086dd },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 }
};

/**
  * Sampling BPF filter.
  *
  * Note: It currently only supports IPv4 so IPv6 capturing will not work
  *       at all.
  */
static struct sock_filter hash_filter[] = {
#define PRIME 86477
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12), // Load ethernet proto
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x800, 0, 41), // Abort if this is not IPv4
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20), // Load fragmentation info
	BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1ffff, 39, 0), // Check if it is the first fragment - if not reject
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26), // Load source address
	BPF_STMT(BPF_ST, 0), // Store in scratch memory 0x0
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 30), // Load destination address
	BPF_STMT(BPF_ST, 1), // Store in scratch memory 0x1
	BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14), // Set index register to beginning of payload
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23), // Load protocol
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 1, 0), // Check if UDP
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x6, 0, 31), // Check if TCP
	BPF_STMT(BPF_LD | BPF_H | BPF_IND, 14),
	BPF_STMT(BPF_ST, 0x2), // Store source port in scratch memory 0x2
	BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),
	BPF_STMT(BPF_ST, 0x3), // Store destination port in scratch memory 0x3
	BPF_STMT(BPF_LD | BPF_MEM, 0x0), // Load source address
	BPF_STMT(BPF_LDX | BPF_MEM, 0x1), // Load destination address
	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0x0, 11, 0),
	BPF_STMT(BPF_LD | BPF_MEM, 0x0), // Load source address
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0x0), // Add destination address
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	BPF_STMT(BPF_LDX | BPF_MEM, 0x2), // Load source port
	BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0x0),
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	BPF_STMT(BPF_LDX | BPF_MEM, 0x3), // Load destination port
	BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0x0),
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	BPF_STMT(BPF_JMP | BPF_JA, 11),
	// SWAPPED begins here
	BPF_STMT(BPF_LD | BPF_MEM, 0x1), // Load destination address
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	BPF_STMT(BPF_LDX | BPF_MEM, 0x0), // Load source address
	BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0x0), // Add source address
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	BPF_STMT(BPF_LDX | BPF_MEM, 0x3), // Load destination port
	BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0x0),
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	BPF_STMT(BPF_LDX | BPF_MEM, 0x2), // Load source port
	BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0x0),
	BPF_STMT(BPF_ALU | BPF_MUL, PRIME),
	// RETURN_VALUE begins here
	BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0xdeadbeef, 1, 0),
	BPF_STMT(BPF_RET | BPF_K, 0xffff),
	// REJECT begins here
	BPF_STMT(BPF_RET | BPF_K, 0)
};
void set_sampling_polynom(uint32_t polynom) {
	crc_polynom = polynom;
	make_crc_table(polynom);
}

int start_flow_capture_session(flow_capture_session *session,
							   uint16_t export_timeout,
							   uint16_t max_flow_lifetime,
							   uint16_t object_cache_size,
							   enum flow_sampling_mode sampling_mode,
							   uint32_t sampling_max_value) {
	session->ipv4_flow_database = NULL;
#ifdef SUPPORT_IPV6
	session->ipv6_flow_database = NULL;
#endif
	session->capture_session = NULL;
	session->flow_key_cache = NULL;
	session->flow_info_cache = NULL;

	session->ipv4_flow_database = kh_init(1);
	if (!session->ipv4_flow_database)
		goto error;

#ifdef SUPPORT_IPV6
	session->ipv6_flow_database = kh_init(1);
	if (!session->ipv6_flow_database)
		goto error;
#endif
	session->flow_key_cache = init_object_cache(object_cache_size, sizeof(struct flow_key_t));
	if (!session->flow_key_cache)
		goto error;
	session->flow_info_cache = init_object_cache(object_cache_size, sizeof(struct flow_info_t));
	if (!session->flow_info_cache)
		goto error;

	session->capture_session = start_capture_session();
	if (!session->capture_session)
		goto error;

    session->export_timeout = export_timeout;
	session->max_flow_lifetime = max_flow_lifetime;

	session->sampling_mode = sampling_mode;
	session->sampling_max_value = sampling_max_value;
	session->sampling_accepted_packets = 0;
	session->sampling_dropped_packets = 0;

    return 0;

error:
	if (session->ipv4_flow_database)
		kh_destroy(1, session->ipv4_flow_database);
#ifdef SUPPORT_IPV6
	if (session->ipv6_flow_database)
		kh_destroy(1, session->ipv6_flow_database);
#endif
	if (session->flow_key_cache)
		free_object_cache(session->flow_key_cache);
	if (session->flow_info_cache)
		free_object_cache(session->flow_info_cache);
	if (session->capture_session)
		free_capture_session(session->capture_session);

	return -1;
}



static struct sock_fprog build_filter(flow_capture_session *session,
									  const struct sockaddr *hwaddr) {
    struct sock_fprog prog = { 0, NULL };

	switch (session->sampling_mode) {
	case CRC32SamplingMode:
	case NullSamplingMode:
		if (hwaddr->sa_family == ARPHRD_ETHER) {
			struct sock_filter *filter = egress_filter;

			const char *macaddr = hwaddr->sa_data;

			// Last 32 bit of MAC address
			filter[1].k = ntohl(*((uint32_t *) macaddr + 2));
			// First 16 bit of MAC address
			filter[3].k = ntohs(*((uint16_t *) macaddr));

			prog.len = sizeof(egress_filter) / sizeof(struct sock_filter);
			prog.filter = filter;

		}
		break;
	case BPFSamplingMode:
	{
		// Insert sampling max value into filter
		int i;
		for (i = 0; i < sizeof(hash_filter) / sizeof(struct sock_filter); i++) {
			if (hash_filter[i].k == 0xdeadbeef) {
				hash_filter[i].k = session->sampling_max_value;
			}
		}

		prog.filter = hash_filter;
		prog.len = sizeof(hash_filter) / sizeof(struct sock_filter);
		break;
	}
	}

    return prog;
}

/**
  * Adds the given interface to the capture list.
  */
int add_interface(flow_capture_session *session, char *device_name, bool enable_promisc) {
	struct ifreq req;
	int fd = -1;

	if (iface_info(device_name, &req, &fd) == -1) {
		return -1;
	}

	struct sockaddr hwaddr;
	if (iface_hwaddr(&req, fd, &hwaddr)) {
		close(fd);
		return -1;
	}

	close(fd);

	struct sock_fprog filter = build_filter(session, &hwaddr);
	struct capture_info *info = start_capture(session->capture_session,
											  device_name, 128, &filter);
	if (!info) {
		return -1;
	}

	struct flow_capture_callback_param *param =
			(struct flow_capture_callback_param *) malloc(sizeof(struct flow_capture_callback_param));

	param->session = session;
	param->info = info;

	event_loop_add_fd(info->fd, (event_fd_callback) &capture_callback, (event_fd_error_callback) &capture_error_callback, param);

    return 0;
}

static void free_flow_database(khash_t(1) *flow_database) {
	if (flow_database == NULL)
		return;

	khiter_t k;
	for (k = kh_begin(flow_database); k != kh_end(flow_database); ++k) {
		if (!kh_exist(flow_database, k))
			continue;
		flow_key *key = kh_key(flow_database, k);
		free(kh_value(flow_database, k));

		kh_del(1, flow_database, k);
		free(key);

	}
}

/**
  * Stops the given capture session. It is not possible to use this session from the
  * capture call afterwards.
  */
void stop_flow_capture_session(flow_capture_session *session) {
	free_flow_database(session->ipv4_flow_database);
	session->ipv4_flow_database = NULL;

#ifdef SUPPORT_IPV6
	free_flow_database(session->ipv6_flow_database);
	session->ipv6_flow_database = NULL;
#endif

	free_object_cache(session->flow_key_cache);
	free_object_cache(session->flow_info_cache);
}


static inline int parse_ethernet(flow_capture_session *session, struct pktinfo *pkt) {
    if (pkt->data + sizeof(struct ether_header) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid ethernet packet.");
        return -1;
    }
	// DPRINTF("Parsing ethernet header");

    const struct ether_header * const hdr = (const struct ether_header * const) pkt->data;

    pkt->data += sizeof(struct ether_header);

    switch (ntohs(hdr->ether_type)) {
    case ETHERTYPE_IP:
		return parse_ipv4(session, pkt);
#ifdef SUPPORT_IPV6
    case ETHERTYPE_IPV6:
		return parse_ipv6(session, pkt);
#endif
    default:
		DPRINTF("Unsupported link layer protocol (%x).", ntohs(hdr->ether_type));
        return 0;
    }
}

static inline int parse_ipv4(flow_capture_session *session, struct pktinfo *pkt) {
    if (pkt->data + sizeof(struct iphdr) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid IPv4 packet (by %t bytes).", (pkt->data + sizeof(struct iphdr) - pkt->end_data));
        return -1;
    }

	struct iphdr * const hdr = (struct iphdr * const) pkt->data;

    // Determine start address of payload based on the IHL header.
    pkt->data += hdr->ihl * 4;

    if (pkt->data > pkt->end_data) {
        msg(MSG_ERROR, "Packet payload points beyond capture end.");
        return -1;
    }

	flow_key key;

	key.protocol = IPv4;
	key.src_addr.v4.s_addr = hdr->saddr;
	key.dst_addr.v4.s_addr = hdr->daddr;

	switch (hdr->protocol) {
    case SOL_UDP:
		return parse_udp(session, pkt, &key);
        break;
    case SOL_TCP:
		return parse_tcp(session, pkt, &key);
    default:
        return 0;
    }
}

#ifdef SUPPORT_IPV6
static inline int parse_ipv6(flow_capture_session *session, struct pktinfo *pkt) {
	// No need to check the length - ipv6_extract_transport_protocol does that
	// for us.
	const struct ip6_hdr * const hdr = (const struct ip6_hdr * const) pkt->data;
	int transport_protocol = ipv6_extract_transport_protocol(pkt);

	if (transport_protocol == -1)
		return -1;

	struct flow_key_t flow;

	memcpy(&flow.dst_addr, &hdr->ip6_dst, sizeof(hdr->ip6_dst));
	memcpy(&flow.src_addr, &hdr->ip6_src, sizeof(hdr->ip6_src));
	flow.protocol = IPv6;

	switch (transport_protocol) {
	case 6:
		return parse_tcp(session, pkt, &flow);
	case 17:
		return parse_udp(session, pkt, &flow);
	default:
		return -1;
	}
}
#endif

static inline bool include_hash_code(flow_capture_session *session,
									 uint32_t hash_code) {
	if (session->sampling_mode != CRC32SamplingMode)
		return true;

	DPRINTF("Hashcode: %u Accepted: %u Dropped: %u", hash_code, session->sampling_accepted_packets, session->sampling_dropped_packets);

	if (hash_code > session->sampling_max_value) {
		session->sampling_dropped_packets++;

		// Handle wrap-around
		if (session->sampling_dropped_packets == 0) {
			session->sampling_accepted_packets = 0;
		}

		return false;
	} else {

		session->sampling_accepted_packets++;

		// Handle wrap-around
		if (session->sampling_accepted_packets == 0) {
			session->sampling_dropped_packets = 0;
		}

		return  true;
	}
}

static inline int parse_udp(flow_capture_session *session, struct pktinfo *pkt, flow_key *flow) {
    if (pkt->data + sizeof(struct udphdr) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
        return -1;
    }

    const struct udphdr * const hdr = (const struct udphdr * const) pkt->data;

	flow->t_protocol = TRANSPORT_UDP;
	flow->src_port = hdr->source;
	flow->dst_port = hdr->dest;

	uint32_t hash_code = flow_key_hash_code(flow);
	if (!include_hash_code(session, hash_code)) {
		return 0;
	}

    pkt->data += sizeof(struct udphdr);

    flow_info *info = NULL;
	khash_t(1) *flow_database = NULL;
	khiter_t k;

	switch (flow->protocol) {
	case IPv4:
		flow_database = session->ipv4_flow_database;
		break;
#ifdef SUPPORT_IPV6
	case IPv6:
		flow_database = session->ipv6_flow_database;
		break;
#endif
	}

	k = kh_get_hash_code(1, flow_database, flow, hash_code);

	if (k == kh_end(flow_database)) {
        int ret;

		info = (flow_info *) allocate_object(session->flow_info_cache);
        if (info == NULL) {
            msg(MSG_ERROR, "Failed to allocate memory for flow info structure.");
            return -1;
        }

		info->first_packet_timestamp = time(NULL);
		info->total_bytes = 0;

		// Create a copy of the key on the heap on the first insertion
		flow_key *old_flow = flow;
		flow = (flow_key *) allocate_object(session->flow_key_cache);
		memcpy(flow, old_flow, sizeof(flow_key));

		k = kh_put(1, flow_database, flow, &ret);
		kh_value(flow_database, k) = info;
    } else {
		info = (flow_info *) kh_value(flow_database, k);
    }

    info->last_packet_timestamp = time(NULL);
	info->total_bytes += pkt->orig_len;

    return 0;
}

static inline int parse_tcp(flow_capture_session *session, struct pktinfo *pkt, flow_key *flow) {
    if (pkt->data + sizeof(struct tcphdr) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
        return -1;
    }

    const struct tcphdr * const hdr = (const struct tcphdr * const) pkt->data;

	flow->t_protocol = TRANSPORT_TCP;
	flow->src_port = hdr->source;
	flow->dst_port = hdr->dest;

	uint32_t hash_code = flow_key_hash_code(flow);
	if (!include_hash_code(session, hash_code)) {
		return 0;
	}

    flow_info *info = NULL;
	khash_t(1) *flow_database = NULL;
    khiter_t k;

	switch (flow->protocol) {
	case IPv4:
		flow_database = session->ipv4_flow_database;
		break;
#ifdef SUPPORT_IPV6
	case IPv6:
		flow_database = session->ipv6_flow_database;
		break;
#endif
	}

	k = kh_get_hash_code(1, flow_database, flow, hash_code);

	if (k == kh_end(flow_database)) {
        int ret;

		/*
		Accept any packet - not only new connections: packets may be rerouted
		due to link failures and the failover path would not pick up the flow.

		if (!(hdr->syn == 1 && hdr->ack == 0)) {
            // This is not a new connection - ignore it
            return -1;
        }

		*/

		info = (flow_info *) allocate_object(session->flow_info_cache);

        if (info == NULL) {
            msg(MSG_ERROR, "Failed to allocate memory for flow info structure.");
            return -1;
        }

        info->first_packet_timestamp = time(NULL);
		info->total_bytes = 0;

		// Create a copy of the key on the heap on the first insertion
		flow_key *old_flow = flow;
		flow = (flow_key *) allocate_object(session->flow_key_cache);
		memcpy(flow, old_flow, sizeof(flow_key));

		k = kh_put(1, flow_database, flow, &ret);
		kh_value(flow_database, k) = info;


    } else {
		info = (flow_info *) kh_value(flow_database, k);
    }

    info->last_packet_timestamp = time(NULL);
	info->total_bytes += pkt->orig_len;

    return 0;
}

void capture_callback(int fd, struct flow_capture_callback_param *param) {
	size_t len;
	size_t orig_len;
	bool first_call = true;
	uint8_t *buffer;

	while ((buffer = capture_packet(param->info, &len, &orig_len, first_call))) {
		struct pktinfo pkt = { buffer, buffer + len, buffer, orig_len };
		parse_ethernet(param->session, &pkt);

		capture_packet_done(param->info);
		first_call = false;
	}

}

void capture_error_callback(int fd, struct flow_capture_callback_param *param) {
	remove_capture_interface(param->session->capture_session, param->info);
}

static uint32_t flow_key_hash_code_ipv4(flow_key *key, uint32_t hashcode) {
	uint32_t addr1;
	uint32_t addr2;
	uint16_t port1;
	uint16_t port2;

	if (key->src_addr.v4.s_addr < key->dst_addr.v4.s_addr) {
		addr1 = key->src_addr.v4.s_addr;
		addr2 = key->dst_addr.v4.s_addr;
		port1 = key->src_port;
		port2 = key->dst_port;
	} else if (key->src_addr.v4.s_addr >= key->dst_addr.v4.s_addr){
		addr1 = key->dst_addr.v4.s_addr;
		addr2 = key->src_addr.v4.s_addr;
		port1 = key->dst_port;
		port2 = key->src_port;
	} else {
		addr1 = key->src_addr.v4.s_addr;
		addr2 = key->dst_addr.v4.s_addr;
		if (key->src_port < key->dst_port) {
			port1 = key->src_port;
			port2 = key->dst_port;
		} else {
			port1 = key->dst_port;
			port2 = key->src_port;
		}
	}

	if (!crc_polynom) {
		/*
		  The following should be used if the correctness of the BPF filter
		  should be checked (it converts to host endianess):
		hashcode = ntohl(addr1) * PRIME;
		hashcode = (hashcode + ntohl(addr2)) * PRIME;
		hashcode = (hashcode + ntohs(port1)) * PRIME;
		hashcode = (hashcode + ntohs(port2)) * PRIME;
		*/

		hashcode = addr1 * PRIME;
		hashcode = (hashcode + addr2) * PRIME;
		hashcode = (hashcode + port1) * PRIME;
		hashcode = (hashcode + port2) * PRIME;
	} else {
		hashcode = crc(hashcode, (uint8_t *) &port1, sizeof(port1));
		hashcode = crc(hashcode, (uint8_t *) &port2, sizeof(port2));
		hashcode = crc(hashcode, (uint8_t *) &addr1, sizeof(addr1));
		hashcode = crc(hashcode, (uint8_t *) &addr2, sizeof(addr2));
	}

    return hashcode;
}

#ifdef SUPPORT_IPV6
static uint32_t flow_key_hash_code_ipv6(flow_key *key, uint32_t hashcode) {
	uint8_t *addr1;
	uint8_t *addr2;
	uint16_t port1;
	uint16_t port2;

	int cmp = memcmp(&key->src_addr, &key->dst_addr, sizeof(key->src_addr));
	if (cmp <= 0) {
		addr1 = (uint8_t *) key->src_addr.v6.s6_addr;
		addr2 = (uint8_t *) key->dst_addr.v6.s6_addr;
		if (cmp == 0) {
			// Handle the special case of src addr == orig addr
			if (key->src_port < key->dst_port) {
				port1 = key->src_port;
				port2 = key->dst_port;
			} else {
				port1 = key->dst_port;
				port2 = key->src_port;
			}
		} else {
			port1 = key->src_port;
			port2 = key->dst_port;
		}
	} else {
		addr1 = (uint8_t *) key->dst_addr.v6.s6_addr;
		addr2 = (uint8_t *) key->src_addr.v6.s6_addr;
		port1 = key->dst_port;
		port2 = key->src_port;
	}
    int i;

	if (!crc_polynom) {
		hashcode = hashcode * 23 + ((port1 << 16) | port2);

		for (i = 0; i < 4; i++) {
			if (!crc_polynom) {
				hashcode = hashcode * 23 + *addr1;
				hashcode = hashcode * 23 + *addr2;
			}
			addr1++;
			addr2++;
		}
	} else {
		hashcode = crc(hashcode, (uint8_t *) &port1, sizeof(port1));
		hashcode = crc(hashcode, (uint8_t *) &port2, sizeof(port2));
		hashcode = crc(hashcode, addr1, sizeof(struct in6_addr));
		hashcode = crc(hashcode, addr2, sizeof(struct in6_addr));
	}

    return hashcode;
}
#endif

uint32_t flow_key_hash_code(struct flow_key_t *key) {
	uint32_t hashcode = 0;

	if (!crc_polynom) {
		//hashcode = 17;

		//hashcode = hashcode * 23 + (((char) key->protocol) << 8 | (char) key->t_protocol);
	} else {
		hashcode = 0xffffffff;

		hashcode = crc(hashcode, (uint8_t *) &key->protocol, sizeof(key->protocol));
		hashcode = crc(hashcode, (uint8_t *) &key->t_protocol, sizeof(key->t_protocol));
	}

    switch (key->protocol) {
    case IPv4:
		return flow_key_hash_code_ipv4(key, hashcode);
#ifdef SUPPORT_IPV6
    case IPv6:
		return flow_key_hash_code_ipv6(key, hashcode);
#endif
    default:
		DPRINTF("Hashcode was called for unsupported flow key type.");
        return hashcode;
    }
}

static int flow_key_equals_ipv4(const flow_key *a, const flow_key *b) {
	return (a->src_addr.v4.s_addr == b->src_addr.v4.s_addr &&
			a->dst_addr.v4.s_addr == b->dst_addr.v4.s_addr &&
			a->src_port == b->src_port &&
			a->dst_port == b->dst_port)
			||
			(a->src_addr.v4.s_addr == b->dst_addr.v4.s_addr &&
			 a->dst_addr.v4.s_addr == b->src_addr.v4.s_addr &&
			 a->src_port == b->dst_port &&
			 a->dst_port == b->src_port);
}

#ifdef SUPPORT_IPV6
static int flow_key_equals_ipv6(const flow_key *a, const flow_key *b) {
	return (memcmp(&a->src_addr.v6, &b->src_addr.v6, sizeof(a->src_addr.v6)) == 0 &&
			memcmp(&a->dst_addr.v6, &b->dst_addr.v6, sizeof(a->dst_addr.v6)) == 0 &&
			a->src_port == b->src_port &&
			a->dst_port == b->dst_port)
			||
			(memcmp(&a->src_addr.v6, &b->dst_addr.v6, sizeof(a->src_addr.v6)) == 0 &&
			 memcmp(&a->dst_addr.v6, &b->src_addr.v6, sizeof(a->dst_addr.v6)) == 0 &&
			 a->src_port == b->dst_port &&
			 a->dst_port == b->src_port);
}
#endif


int flow_key_equals(struct flow_key_t *a, struct flow_key_t *b) {
    if (a->protocol != b->protocol ||
            a->t_protocol != b->t_protocol) {
        return 0;
    }

    switch (a->protocol) {
    case IPv4:
		return flow_key_equals_ipv4(a, b);
#ifdef SUPPORT_IPV6
    case IPv6:
		return flow_key_equals_ipv6(a, b);
#endif
    default:
        msg(MSG_ERROR, "Equals was called for unsupported flow key type.");
        return 0;
    }
}

/**
  * CRC code from http://www.w3.org/TR/PNG/#D-CRCAppendix with minor
  * modifications.
  */

/* Table of CRCs of all 8-bit messages. */
static uint32_t crc_table[256];

/**
 * Make the table for a fast CRC.
 * Note: The polynom should be in least-significant bit first form.
 */
void make_crc_table(const uint32_t polynom)
{
	uint32_t c;
	uint16_t n, k;

	for (n = 0; n < 256; n++) {
		c = n;
		for (k = 0; k < 8; k++) {
			if (c & 1)
				c = polynom ^ (c >> 1);
			else
				c = c >> 1;
		}
		crc_table[n] = c;
	}
}


/* Update a running CRC with the bytes buf[0..len-1]--the CRC
   should be initialized to all 1's, and the transmitted value
   is the 1's complement of the final running CRC (see the
   crc() routine below). */

static uint32_t update_crc(uint32_t crc, uint8_t *buf,
						   size_t len)
{
	while (len--) {
		crc = crc_table[(crc ^ *buf++) & 0xff] ^ (crc >> 8);
	}
	return crc;
}

/**
 * Return the CRC of the bytes buf[0..len-1].
 *
 * On the first invocation seed should be set to 0xffffffff.
 */
static uint32_t crc(uint32_t seed, uint8_t *buf, size_t len)
{
	return update_crc(seed, buf, len) ^ 0xffffffffL;
}

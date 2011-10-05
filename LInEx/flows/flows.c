#include "flows.h"
#include "../ipfixlolib/msg.h"
#include "olsr.h"
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

static int parse_ipv4(capture_session *session, struct pktinfo *pkt);
static int parse_ipv6(capture_session *session, struct pktinfo *pkt);
static int parse_udp(capture_session *session, struct pktinfo *pkt, flow_key *flow);
static int parse_tcp(capture_session *session, struct pktinfo *pkt, flow_key *flow);

void capture_callback(int fd, capture_session *session);

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
  * Compiled BPF filter: tcpdump -dd "ip or ip6"
  */
static struct sock_filter ip_filter[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 1, 0, 0x00000800 },
    { 0x15, 0, 1, 0x000086dd },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};


int start_capture_session(capture_session *session, uint16_t export_timeout) {
    memset(session, 0, sizeof(capture_session));

    session->export_timeout = export_timeout;
    session->flow_database = kh_init(1);

	int i;
	for (i = 0; i < MAXIMUM_INTERFACE_COUNT; i++) {
#ifdef SUPPORT_PACKET_MMAP
		session->interface_ring_buffer[i].ring_buffer = NULL;
		session->interface_ring_buffer[i].current_frame_nr = 0;
		session->interface_ring_buffer[i].fd = -1;
#endif
	}

    return 0;
}

static int setup_interface(char *device_name, bool enable_promisc, int *if_index, int *if_mtu, struct sockaddr *hwaddr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        msg(MSG_ERROR, "Failed to retrieve interface info for interface %s (%s).", device_name, strerror(errno));
        return -1;
    }

    struct ifreq req;

    strncpy(req.ifr_name, device_name, sizeof(req.ifr_name));
    req.ifr_name[sizeof(req.ifr_name) - 1] = 0;

    if (ioctl(fd, SIOCGIFINDEX, &req)) {
        msg(MSG_ERROR, "Failed to retrieve interface index for interface %s (%s).", device_name, strerror(errno));
        close(fd);
        return -1;
    }

    *if_index = req.ifr_ifindex;

    if (ioctl(fd, SIOCGIFMTU, &req)) {
        msg(MSG_ERROR, "Failed to retrieve interface MTU for interface %s (%s).", device_name, strerror(errno));
        close(fd);
        return -1;
    }

    *if_mtu = req.ifr_mtu;

    if (ioctl(fd, SIOCGIFHWADDR, &req)) {
        msg(MSG_ERROR, "Failed to retrieve hardware adress for interface %s (%s).", device_name, strerror(errno));
        close(fd);
        return -1;
    }

    *hwaddr = req.ifr_hwaddr;

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

static struct sock_fprog build_filter(const struct sockaddr *hwaddr) {
    struct sock_fprog prog = { 0, NULL };


    if (hwaddr->sa_family == ARPHRD_ETHER) {
        struct sock_filter *filter = egress_filter;

        const char *macaddr = hwaddr->sa_data;

        // Last 32 bit of MAC address
        filter[1].k = ntohl(*((uint32_t *) macaddr + 2));
        // First 16 bit of MAC address
        filter[3].k = ntohs(*((uint16_t *) macaddr));

        prog.len = sizeof(egress_filter) / sizeof(struct sock_filter);
        prog.filter = filter;

    } else {
        prog.filter = ip_filter;
        prog.len = sizeof(ip_filter) / sizeof(struct sock_filter);
    }

    return prog;
}

/**
  * Adds the given interface to the capture list.
  */
int add_interface(capture_session *session, char *device_name, bool enable_promisc) {
	if (session->interface_count + 1 > MAXIMUM_INTERFACE_COUNT) {
		msg(MSG_ERROR, "This build supports at maximum %d interfaces per session.", session->interface_count);
		return -1;
	}
    int index, mtu;
    struct sockaddr hwaddr;

    if (setup_interface(device_name, enable_promisc, &index, &mtu, &hwaddr))
        return -1;

    // Use SOCK_RAW rather than SOCK_DGRAM - otherwise the BPF filters do not work
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fd == -1) {
        msg(MSG_ERROR, "Failed to open raw socket for interface %s.", device_name);

        return -1;
    }

#ifdef SUPPORT_PACKET_MMAP
	struct tpacket_req req = {
		PAGE_SIZE, // tp_block_size
		PACKET_MMAP_BLOCK_NR, // tp_block_nr:
		PACKET_MMAP_FRAME_SIZE, // tp_frame_size
		PACKET_MMAP_FRAME_NR // tp_frame_nr
	};

	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *) &req, sizeof(req))) {
		msg(MSG_ERROR, "Failed to setup PACKET_RX_RING: %s", strerror(errno));
		close(fd);
		return -1;
	}

	void *buffer = mmap(0, req.tp_block_size * req.tp_block_nr,
						PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (buffer == MAP_FAILED) {
		msg(MSG_ERROR, "mmap failed to allocate buffer: %s", strerror(errno));
		close(fd);
		return -1;
	}

	struct ring_buffer *iface_ring_buffer =
			&session->interface_ring_buffer[session->interface_count];
	iface_ring_buffer->ring_buffer = buffer;
	iface_ring_buffer->current_frame_nr = 0;
	iface_ring_buffer->fd = fd;
#else
	if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
		msg(MSG_ERROR, "Failed to put raw socket in non-blocking mode.");
		close(fd);
		return -1;
	}
#endif
    union {
        struct sockaddr_ll ll;
        struct sockaddr addr;
    } addr;

    memset(&addr, 0, sizeof(addr));

    addr.ll.sll_family = PF_PACKET;
    addr.ll.sll_ifindex = index;
    addr.ll.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, &addr.addr, sizeof(struct sockaddr_ll))) {
        msg(MSG_ERROR, "Failed to bind raw socket to interface %s (%s).", device_name, strerror(errno));

        close(fd);
        return -1;
    }

    struct sock_fprog filter = build_filter(&hwaddr);

    if (filter.filter != NULL) {
        if (setsockopt(fd, SOL_SOCKET,  SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1) {
            msg(MSG_ERROR, "Failed to attach filter to file descriptor (%s)", strerror(errno));
            close(fd);
            return -1;
        }
    }

#ifndef SUPPORT_PACKET_MMAP
    // Create or reallocate packet buffer
    if (session->packet_buffer == NULL || session->packet_buffer_size < mtu) {
        if (session->packet_buffer != NULL)
            free(session->packet_buffer);

        session->packet_buffer = (u_char *) malloc(mtu);

        if (session->packet_buffer == NULL) {
            msg(MSG_ERROR, "Failed to allocate packet buffer.");

            close(fd);
            return -1;
        }

        session->packet_buffer_size = mtu;
    }
#endif

	// Update pollfd list
	session->interface_count++;

	struct pollfd *entry = session->pollfd + (session->interface_count - 1);

	entry->fd = fd;
	entry->events = POLLIN;
	entry->revents = 0;

	event_loop_add_fd(fd, (void (*)(int, void *)) &capture_callback, session);

    return 0;
}



/**
  * Stops the given capture session. It is not possible to use this session from the
  * capture call afterwards.
  */
void stop_capture_session(capture_session *session) {
    if (session->pollfd != NULL) {
        int i;
        for (i = 0; i < session->interface_count; i++)
            close((session->pollfd + i)->fd);

        free(session->pollfd);

        session->interface_count = 0;
    }

#ifdef SUPPORT_PACKET_MMAP
	int i;
	for (i = 0; i < MAXIMUM_INTERFACE_COUNT; i++) {
		void *buffer = session->interface_ring_buffer[i].ring_buffer;
		munmap(buffer, PACKET_MMAP_BLOCK_NR * PAGE_SIZE);
	}
#else
    if (session->packet_buffer != NULL) {
        free(session->packet_buffer);

        session->packet_buffer = NULL;
        session->packet_buffer_size = 0;
    }
#endif

    khash_t(1) *flow_database = session->flow_database;

    if (flow_database != NULL) {
        khiter_t k;
        for (k = kh_begin(flow_database); k != kh_end(flow_database); ++k) {
            if (!kh_exist(flow_database, k))
                continue;
            flow_key *key = kh_key(flow_database, k);
            kh_del(1, flow_database, k);
            free(key);
        }
    }

    session->flow_database = NULL;
}


static int parse_ethernet(capture_session *session, struct pktinfo *pkt) {
    if (pkt->data + sizeof(struct ether_header) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid ethernet packet.");
        return -1;
    }

    const struct ether_header * const hdr = (const struct ether_header * const) pkt->data;

    pkt->data += sizeof(struct ether_header);

    switch (ntohs(hdr->ether_type)) {
    case ETHERTYPE_IP:
		return parse_ipv4(session, pkt);
    case ETHERTYPE_IPV6:
		return parse_ipv6(session, pkt);
    default:
		DPRINTF("Unsupported link layer protocol (%x).", ntohs(hdr->ether_type));
        return 0;
    }
}

/*

static int parse_ip(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data) {
    if (data + 1 > end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid IP packet.");
        return -1;
    }

    u_char version = (*data & 0xf0) >> 4;

    switch (version) {
    case 4:
        return parse_ipv4(session, pkthdr, data, end_data);
    case 6:
        return parse_ipv6(session, pkthdr, data, end_data);
    default:
        msg(MSG_ERROR, "Unknown IP header version (%d).", version);
        return -1;
    }
}
*/

static int parse_ipv4(capture_session *session, struct pktinfo *pkt) {
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

    ipv4_flow_key *key = (ipv4_flow_key *) calloc(1, sizeof(ipv4_flow_key));

    if (key == NULL) {
        msg(MSG_ERROR, "Failed to allocate memory for IPv4 flow key.");
        return -1;
    }

    switch (hdr->protocol) {
    case SOL_UDP:
        return parse_udp(session, pkt, (flow_key *) key);
        break;
    case SOL_TCP:
        return parse_tcp(session, pkt, (flow_key *) key);
    default:
        return 0;
    }
}

static int parse_ipv6(capture_session *session, struct pktinfo *pkt) {
    if (pkt->data + sizeof(struct ip6_hdr) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid IPv6 packet by %td bytes.", (pkt->data + sizeof(struct iphdr) - pkt->end_data));
        return -1;
    }

    // const struct ip6_hdr * const hdr = (const struct ip6_hdr * const) data;

    return 0;
}

static int parse_udp(capture_session *session, struct pktinfo *pkt, flow_key *flow) {
    if (pkt->data + sizeof(struct udphdr) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
        return -1;
    }

    const struct udphdr * const hdr = (const struct udphdr * const) pkt->data;

    flow->t_protocol = TRANSPORT_UDP;
    flow->src_port = hdr->source;
    flow->dst_port = hdr->dest;

    pkt->data += sizeof(struct udphdr);

    if (flow->dst_port == htons(OLSR_PORT)) {
        olsr_parse_packet(session, pkt, flow);
    }

    flow_info *info = NULL;
    khiter_t k;
    k = kh_get(1, session->flow_database, flow);

    if (k == kh_end(session->flow_database)) {
        int ret;

        info = (flow_info *) calloc(1, sizeof(flow_info));

        if (info == NULL) {
            msg(MSG_ERROR, "Failed to allocate memory for flow info structure.");
            return -1;
        }

        info->first_packet_timestamp = time(NULL);

        k = kh_put(1, session->flow_database, flow, &ret);
        kh_value(session->flow_database, k) = info;


    } else {
        info = (flow_info *) kh_value(session->flow_database, k);

        // Cleanup flow key - leaving it intact is only needed when inserting
        // into the database the first time.
        free(flow);
    }

    info->last_packet_timestamp = time(NULL);
    info->total_bytes += pkt->end_data - pkt->start_data;

    return 0;
}

static int parse_tcp(capture_session *session, struct pktinfo *pkt, flow_key *flow) {
    if (pkt->data + sizeof(struct tcphdr) > pkt->end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
        return -1;
    }

    const struct tcphdr * const hdr = (const struct tcphdr * const) pkt->data;

    flow->t_protocol = TRANSPORT_TCP;
    flow->src_port = hdr->source;
    flow->dst_port = hdr->dest;

    flow_info *info = NULL;
    khiter_t k;
    k = kh_get(1, session->flow_database, flow);

    if (k == kh_end(session->flow_database)) {
        int ret;

        if (!(hdr->syn == 1 && hdr->ack == 0)) {
            // This is not a new connection - ignore it
            free(flow);
            return -1;
        }

        info = (flow_info *) calloc(1, sizeof(flow_info));

        if (info == NULL) {
            msg(MSG_ERROR, "Failed to allocate memory for flow info structure.");
            return -1;
        }

        info->first_packet_timestamp = time(NULL);

        k = kh_put(1, session->flow_database, flow, &ret);
        kh_value(session->flow_database, k) = info;


    } else {
        info = (flow_info *) kh_value(session->flow_database, k);

        // Cleanup flow key - leaving it intact is only needed when inserting
        // into the database the first time.
        free(flow);
    }

    info->last_packet_timestamp = time(NULL);
    info->total_bytes += pkt->end_data - pkt->data;

    return 0;
}

void statistics_callback(capture_session *session) {
	size_t i;
	struct tpacket_stats kstats;

	for (i = 0; i < session->interface_count; i++) {
		socklen_t kstats_len = sizeof(kstats);
		if (getsockopt((session->pollfd + i)->fd, SOL_PACKET, PACKET_STATISTICS,
					   &kstats, &kstats_len))
			continue;

		msg(MSG_ERROR, "Interface %d: Total pending: %d Lost: %d",
			i,
			kstats.tp_packets,
			kstats.tp_drops);
	}
}

void capture_callback(int fd, capture_session *session) {
#ifdef SUPPORT_PACKET_MMAP
	struct ring_buffer *interface_ring_buffer = NULL;
	int i;

	for (i = 0; i < MAXIMUM_INTERFACE_COUNT; i++) {
		if (session->interface_ring_buffer[i].fd == fd) {
			interface_ring_buffer = &session->interface_ring_buffer[i];
			break;
		}
	}
#endif

	while (1) {
#ifdef SUPPORT_PACKET_MMAP
		uint8_t *buffer = (uint8_t *) interface_ring_buffer->ring_buffer;
		buffer += interface_ring_buffer->current_frame_nr * PACKET_MMAP_FRAME_SIZE;

		struct tpacket_hdr *hdr = (struct tpacket_hdr *) buffer;

		if (hdr->tp_status == 0)
			break;

		buffer += hdr->tp_mac;
		struct pktinfo pkt = { buffer, buffer + hdr->tp_len, buffer };

		session->interface_ring_buffer[0].current_frame_nr =
				(session->interface_ring_buffer[0].current_frame_nr + 1) % (PACKET_MMAP_FRAME_NR);
#else
		union {
			struct sockaddr_ll ll_addr;
			struct sockaddr addr;
		} addr;
		socklen_t addr_len = sizeof(struct sockaddr_ll);
		size_t len = recvfrom(fd, session->packet_buffer, session->packet_buffer_size, 0, (struct sockaddr *) &addr.addr, &addr_len);

		if (len == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				msg(MSG_ERROR, strerror(errno));
			return;
		} else if (len == 0)
			return;

		struct pktinfo pkt = { session->packet_buffer, session->packet_buffer + len, session->packet_buffer };
#endif
		parse_ethernet(session, &pkt);
#ifdef SUPPORT_PACKET_MMAP
		hdr->tp_status = 0;
#endif
	}
}

void flow_export_callback(capture_session *session) {
	// Export pending flows
	time_t now = time(NULL);

	khiter_t k;
	for (k = kh_begin(session->flow_database); k != kh_end(session->flow_database); ++k) {
		if (!kh_exist(session->flow_database, k))
			continue;

		flow_key *key = kh_key(session->flow_database, k);
		flow_info *info = kh_value(session->flow_database, k);

		if (now - info->last_packet_timestamp < session->export_timeout)
			continue;

		kh_del(1, session->flow_database, k);

		msg(MSG_INFO, "Going to export flow: %p\n", key);

		free(key);
		free(info);
	}
}

static uint32_t flow_key_hash_code_ipv4(ipv4_flow_key *key, uint32_t hashcode) {
    uint32_t addr1;
    uint32_t addr2;

    if (key->src_addr < key->dst_addr) {
        addr1 = key->src_addr;
        addr2 = key->dst_addr;
    } else {
        addr1 = key->dst_addr;
        addr2 = key->src_addr;
    }

    hashcode = hashcode * 23 + addr1;
    hashcode = hashcode * 23 + addr2;

    return hashcode;
}

static uint32_t flow_key_hash_code_ipv6(ipv6_flow_key *key, uint32_t hashcode) {
    uint8_t *addr1;
    uint8_t *addr2;

    if (memcmp(&key->src_addr, &key->dst_addr, sizeof(key->src_addr)) <= 0) {
        addr1 = (uint8_t *) key->src_addr.s6_addr;
        addr2 = (uint8_t *) key->dst_addr.s6_addr;
    } else {
        addr1 = (uint8_t *) key->dst_addr.s6_addr;
        addr2 = (uint8_t *) key->src_addr.s6_addr;
    }
    int i;

    for (i = 0; i < 4; i++) {
        hashcode = hashcode * 23 + *(addr1 + i);
        hashcode = hashcode * 23 + *(addr2 + i);
    }

    return hashcode;
}

uint32_t flow_key_hash_code(struct flow_key_t *key) {
    uint32_t hashcode = 17;

    uint16_t port1;
    uint16_t port2;

    if (key->src_port < key->dst_port) {
        port1 = key->src_port;
        port2 = key->dst_port;
    } else {
        port1 = key->dst_port;
        port2 = key->src_port;
    }

    hashcode = hashcode * 23 + ((port1 << 16) | port2);
    hashcode = hashcode * 23 + (((char) key->protocol) << 8 | (char) key->t_protocol);

    switch (key->protocol) {
    case IPv4:
        return flow_key_hash_code_ipv4((ipv4_flow_key *) key, hashcode);
    case IPv6:
        return flow_key_hash_code_ipv6((ipv6_flow_key *) key, hashcode);
    default:
        msg(MSG_ERROR, "Hashcode was called for unsupported flow key type.");
        return hashcode;
    }
}

static int flow_key_equals_ipv4(const ipv4_flow_key *a, const ipv4_flow_key *b) {
    return (a->src_addr == b->src_addr &&
            a->dst_addr == b->dst_addr &&
            a->key.src_port == b->key.src_port &&
            a->key.dst_port == b->key.dst_port)
            ||
            (a->src_addr == b->dst_addr &&
             a->dst_addr == b->src_addr &&
             a->key.src_port == b->key.dst_port &&
             a->key.dst_port == b->key.src_port);
}

static int flow_key_equals_ipv6(const ipv6_flow_key *a, const ipv6_flow_key *b) {
    return (memcmp(&a->src_addr, &b->src_addr, sizeof(a->src_addr)) == 0 &&
            memcmp(&a->dst_addr, &b->dst_addr, sizeof(a->dst_addr)) == 0 &&
            a->key.src_port == b->key.src_port &&
            a->key.dst_port == b->key.dst_port)
            ||
            (memcmp(&a->src_addr, &b->dst_addr, sizeof(a->src_addr)) == 0 &&
             memcmp(&a->dst_addr, &b->src_addr, sizeof(a->dst_addr)) == 0 &&
             a->key.src_port == b->key.dst_port &&
             a->key.dst_port == b->key.src_port);
}


int flow_key_equals(struct flow_key_t *a, struct flow_key_t *b) {
    if (a->protocol != b->protocol ||
            a->t_protocol != b->t_protocol) {
        return 0;
    }

    switch (a->protocol) {
    case IPv4:
        return flow_key_equals_ipv4((ipv4_flow_key *) a, (ipv4_flow_key *) b);
    case IPv6:
        return flow_key_equals_ipv6((ipv6_flow_key *) a, (ipv6_flow_key *) b);
    default:
        msg(MSG_ERROR, "Equals was called for unsupported flow key type.");
        return 0;
    }
}

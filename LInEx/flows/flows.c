#include "flows.h"
#include "../ipfixlolib/msg.h"
#include "olsr.h"

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

static int parse_ipv4(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data);
static int parse_ipv6(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data);
static int parse_udp(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data, flow_key *flow);
static int parse_tcp(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data, flow_key *flow);

int start_capture_session(capture_session *session, char *device_name, uint16_t export_timeout) {
    // Lookup the default device via PCAP if it was not specified by the user.
    if (device_name == NULL) {
        device_name = pcap_lookupdev(session->errbuf);
    }

    if (device_name == NULL) {
        return -1;
    }

    session->handle = pcap_open_live(device_name, CAPTURE_LENGTH, 0, 500, session->errbuf);

    if (session->handle == NULL) {
        return -1;
    }

    session->datalink_type = pcap_datalink(session->handle);
    session->export_timeout = export_timeout;
    session->flow_database = kh_init(1);

    return 0;
}

/**
  * Stops the given capture session. It is not possible to use this session from the
  * capture call afterwards.
  */
void stop_capture_session(capture_session *session) {
    if (session->handle != NULL) {
        pcap_close(session->handle);
        session->handle = NULL;
    }

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

static int parse_ethernet(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data) {
    if (data + sizeof(struct ether_header) > end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid ethernet packet.");
        return -1;
    }

    const struct ether_header * const hdr = (const struct ether_header * const) data;

    switch (ntohs(hdr->ether_type)) {
    case ETHERTYPE_IP:
        parse_ipv4(session, pkthdr, data + sizeof(struct ether_header), end_data);
    case ETHERTYPE_IPV6:
        parse_ipv6(session, pkthdr, data + sizeof(struct ether_header), end_data);
    default:
        return 0;
    }
}

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

static int parse_ipv4(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data) {
    if (data + sizeof(struct iphdr) > end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid IPv4 packet.");
        return -1;
    }

    const struct iphdr * const hdr = (const struct iphdr * const) data;

    // Determine start address of payload based on the IHL header.
    const u_char * payload_start = data + hdr->ihl * 4;

    if (payload_start > end_data) {
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
        return parse_udp(session, pkthdr, payload_start, end_data, (flow_key *) key);
        break;
    case SOL_TCP:
        return parse_tcp(session, pkthdr, payload_start, end_data, (flow_key *) key);
    default:
        return 0;
    }
}

static int parse_ipv6(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data) {
    if (data + sizeof(struct ip6_hdr) > end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid IPv4 packet.");
        return -1;
    }

    // const struct ip6_hdr * const hdr = (const struct ip6_hdr * const) data;

    return 0;
}

static int parse_udp(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data, flow_key *flow) {
    if (data + sizeof(struct udphdr) > end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
        return -1;
    }

    const struct udphdr * const hdr = (const struct udphdr * const) data;

    flow->t_protocol = TRANSPORT_UDP;
    flow->src_port = hdr->source;
    flow->dst_port = hdr->dest;

    if (flow->dst_port == htons(OLSR_PORT)) {
        olsr_parse_packet(session, pkthdr, data + sizeof(struct udphdr), end_data, flow);
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
    info->total_bytes += pkthdr->len;

    return 0;
}

static int parse_tcp(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char *const data, const u_char *const end_data, flow_key *flow) {
    if (data + sizeof(struct tcphdr) > end_data) {
        msg(MSG_ERROR, "Packet too short to be a valid UDP packet.");
        return -1;
    }

    const struct tcphdr * const hdr = (const struct tcphdr * const) data;

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
    info->total_bytes += pkthdr->len;

    return 0;
}

/**
  * Captures pending packets from the interface.
  *
  * Returns the number of packets captured or -1 on error.
  */
int capture(capture_session *session) {
    struct pcap_pkthdr *pkthdr = NULL;
    const u_char *data = NULL;
    ssize_t packets_captured = 0;
    int ret = 0;

    if (session->handle == NULL)
        return -1;

    while ((ret = pcap_next_ex(session->handle, &pkthdr, &data)) > 0) {
        switch (session->datalink_type) {
        case DLT_EN10MB:
            if (parse_ethernet(session, pkthdr, (u_char * const) data, (u_char * const) data + pkthdr->caplen) == 0) {
                packets_captured++;
            }
            break;
        case DLT_RAW:
            if (parse_ip(session, pkthdr, (u_char * const) data, (u_char * const) data + pkthdr->caplen) == 0) {
                packets_captured++;
            }
            break;
        default:
            msg(MSG_ERROR, "Unsupported data link type %d", session->datalink_type);
        }
    }

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

    return packets_captured;
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

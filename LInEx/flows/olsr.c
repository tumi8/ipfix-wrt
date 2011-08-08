#include "olsr.h"
#include "topology_set.h"
#include "olsr_protocol.h"
#include "../ipfixlolib/msg.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

khash_t(2) *tc_set = NULL;

static int olsr_parse_packet_header(const u_char **data, const u_char *const end_data, struct olsr_packet *packet_hdr);
static int olsr_parse_message(const u_char **data, const u_char *const end_data, const flow_key *const key, struct olsr_common *message);
static int olsr_handle_hello_message(const u_char **data, const flow_key * const key, struct olsr_hello_message *message);
static int olsr_handle_tc_message(const u_char **data, const flow_key * const key, struct olsr_tc_message *message);

/**
  * Attemps to parse an OLSR packet.
  *
  * Returns 0 if the packet could be parsed sucessfully or -1 if the packet was not a valid OLSR packet.
  */
int olsr_parse_packet(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char * data, const u_char *const end_data, const flow_key *const key) {
    if (tc_set == NULL) {
        tc_set = kh_init(2);

        if (tc_set == NULL) {
            msg(MSG_ERROR, "Failed to allocate memory for TC set.");
            return -1;
        }
    }

    struct olsr_packet packet;
    if (olsr_parse_packet_header(&data, end_data, &packet)) {
        return -1;
    }

    msg(MSG_ERROR, "Packet Info: Sequence Number %d, Size: %d", packet.seqno, packet.size);

    struct olsr_common message;
    while (data < end_data) {
        if (olsr_parse_message(&data, end_data, key, &message)) {
            return -1;
        }

        msg(MSG_ERROR, "Message Info: Type: %d Hops: %d Size: %d", message.type, message.hops, message.size);

        switch (message.type) {
        case HELLO_MESSAGE:
        case HELLO_LQ_MESSAGE: {
            struct olsr_hello_message hello_message = { message };
            if (olsr_handle_hello_message(&data, key, &hello_message))
                return -1;
            break;
        }
        case TC_MESSAGE:
        case TC_LQ_MESSAGE: {
            struct olsr_tc_message tc_message = { message };
            if (olsr_handle_tc_message(&data, key, &tc_message))
                return -1;
            break;
        }
        default:
            // Unsupported message type - ignore it
            break;
        }

        // Point to the end of the message
        data = message.end;
    }


    return 0;
}

/**
  * Attempts to find the topology set stored in the global topology control set
  * associated with the given network address.
  *
  * Returns a reference to the topology set (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
static struct topology_set *find_or_create_topology_set(union olsr_ip_addr *addr) {
    struct ip_addr_t originator_addr = { IPv4, *addr };
    khiter_t k;

    k = kh_get(2, tc_set, originator_addr);

    if (k == kh_end(tc_set)) {
        // Create new entry
        struct topology_set *ts = (struct topology_set *) calloc(1, sizeof(struct topology_set));

        int ret;
        k = kh_put(2, tc_set, originator_addr, &ret);
        kh_value(tc_set, k) = ts;

        return ts;
    }

    return kh_value(tc_set, k);
}

/**
  * Attempts to find the topology set entry stored in the given topology set which has
  * the given network address. This function will create a new entry in the topology
  * set if an existing one could not be found.
  *
  * Returns a reference to the topology set entry (which may be newly created) or NULL
  * if the dynamic memory allocation failed.
  */
static struct topology_set_entry *find_or_create_topology_set_entry(struct topology_set *ts, union olsr_ip_addr *addr) {
    struct topology_set_entry *ts_entry = ts->first;

    while (ts_entry != NULL) {
        if (ts->protocol == IPv4) {
            if (ts_entry->dest_addr.v4.s_addr == addr->v4.s_addr)
                break;
        } else {
            if (memcmp(&ts_entry->dest_addr.v6, &addr->v6, sizeof(addr->v6)))
                break;
        }

        ts_entry = ts_entry->next;
    }

    if (ts_entry == NULL) {
        ts_entry = (struct topology_set_entry *) calloc (1, sizeof(struct topology_set_entry));

        if (ts_entry == NULL)
            return NULL;

        ts_entry->dest_addr = *addr;
        if (ts->last != NULL)
            ts->last->next = ts_entry;
        ts->last = ts_entry;
    }

    return ts_entry;
}

/**
  * Attemps to parse a TC message.
  *
  * Returns 0 on success, -1 otherwise.
  */
static int olsr_handle_tc_message(const u_char **data, const flow_key *const key, struct olsr_tc_message *message) {
    if ((message->comm.type == TC_LQ_MESSAGE && *data + OLSR_TC_LQ_MESSAGE_HEADER_LEN > message->comm.end) ||
            (*data + OLSR_TC_MESSAGE_HEADER_LEN > message->comm.end)) {
        msg(MSG_ERROR, "Packet too short to be a valid OLSR TC packet.");

        return -1;
    }

    pkt_get_u16(data, &message->ansn); // ANSN
    pkt_ignore_u16(data); // Reserved

    if (message->comm.type == TC_LQ_MESSAGE) {
        pkt_get_u8(data, &message->lower_border);
        pkt_get_u8(data, &message->upper_border);
    }

    struct topology_set *ts = find_or_create_topology_set(&message->comm.orig);

    if (ts == NULL) {
        msg(MSG_ERROR, "Failed to allocate memory for topology set.");

        return -1;
    }

    // Check if the packet is valid
    struct topology_set_entry *ts_entry = ts->first;

    while (ts_entry != NULL) {
        if (!SEQNO_GREATER_THAN(message->ansn, ts_entry->seq)) {
            msg(MSG_INFO, "Stored sequence number is larger than received packet. Ignoring TC message.");

            return 0;
        }

        ts_entry = ts_entry->next;
    }

    while (*data < message->comm.end) {
        union olsr_ip_addr addr;

        pkt_get_ip_address(data, &addr, key->protocol);

        if (message->comm.type == TC_LQ_MESSAGE) {
            pkt_ignore_u32(data);
        }

        ts_entry = find_or_create_topology_set_entry(ts, &addr);
        if (ts_entry == NULL) {
            msg(MSG_ERROR, "Failed to allocate memory for topology set entry.");

            return -1;
        }

        ts_entry->seq = message->ansn;
        ts_entry->time = time(NULL) + message->comm.vtime / 10e6;
    }

    return 0;
}


/**
  * Attempts to parse an OLSR HELLO message.
  *
  */
static int olsr_handle_hello_message(const u_char **data, const flow_key *const key, struct olsr_hello_message *message) {
    if (*data + OLSR_HELLO_MESSAGE_HEADER_LEN > message->comm.end) {
        msg(MSG_ERROR, "Packet too short to be a valid OLSR HELLO packet.");

        return -1;
    }

    pkt_ignore_u16(data); // Reserved
    pkt_get_reltime(data, &message->htime);
    pkt_get_u8(data, &message->will);

    uint32_t neighbor_entry_len = ip_addr_len(key->protocol);
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

            pkt_get_ip_address(data, &addr, key->protocol);
            if (message->comm.type == HELLO_LQ_MESSAGE)
                pkt_ignore_u32(data);
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
static int olsr_parse_message(const u_char **data, const u_char *const end_data, const flow_key *const key, struct olsr_common *message) {
    if (*data + OLSR_MESSAGE_HEADER_LEN + ip_addr_len(key->protocol) >= end_data) {
        msg(MSG_ERROR, "Packet too short to contain OLSR message header.");

        return -1;
    }

    const u_char *start = *data;

    pkt_get_u8(data, &message->type);
    pkt_get_reltime(data, &message->vtime);
    pkt_get_u16(data, &message->size);
    pkt_get_ip_address(data, &message->orig, key->protocol);
    pkt_get_u8(data, &message->ttl);
    pkt_get_u8(data, &message->hops);
    pkt_get_u16(data, &message->seqno);

    if (start + message->size > end_data) {
        msg(MSG_ERROR, "Message end points beyond input buffer by %t bytes.", (start + message->size) - end_data);

        return -1;
    }

    message->end = start + message->size;

    return 0;
}

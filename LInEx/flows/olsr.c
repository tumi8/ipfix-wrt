#include "olsr.h"
#include "topology_set.h"
#include "hello_set.h"
#include "olsr_protocol.h"
#include "../ipfixlolib/msg.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

tc_set_hash *tc_set = NULL;
hello_set_hash *hello_set = NULL;

static int olsr_parse_packet_header(const u_char **data, const u_char *const end_data, struct olsr_packet *packet_hdr);
static int olsr_parse_message(const u_char **data, const u_char *const end_data, const flow_key *const key, struct olsr_common *message);
static int olsr_handle_hello_message(const u_char **data, const flow_key * const key, struct olsr_hello_message *message);
static int olsr_handle_tc_message(const u_char **data, const flow_key * const key, struct olsr_tc_message *message);

/**
  * Attemps to parse an OLSR packet.
  *
  * Returns 0 if the packet could be parsed sucessfully or -1 if the packet was not a valid OLSR packet.
  */
int olsr_parse_packet(capture_session *session, struct pktinfo *pkt, const flow_key *const key) {
	if (hello_set == NULL) {
		hello_set = kh_init(3);

		if (hello_set == NULL) {
			msg(MSG_ERROR, "Failed to allocate memory for Hello set.");
			return -1;
		}
	}

    struct olsr_packet packet;
    if (olsr_parse_packet_header(&pkt->data, pkt->end_data, &packet)) {
        return -1;
    }

    DPRINTF("Packet Info: Sequence Number %d, Size: %d", packet.seqno, packet.size);

    struct olsr_common message;
    while (pkt->data < pkt->end_data) {
        if (olsr_parse_message(&pkt->data, pkt->end_data, key, &message)) {
            return -1;
        }

        DPRINTF("Message Info: Type: %d Hops: %d Size: %d", message.type, message.hops, message.size);

        switch (message.type) {
        case HELLO_MESSAGE:
        case HELLO_LQ_MESSAGE: {
            struct olsr_hello_message hello_message = { message };
            if (olsr_handle_hello_message(&pkt->data, key, &hello_message))
                return -1;
            break;
        }
        case TC_MESSAGE:
        case TC_LQ_MESSAGE: {
            struct olsr_tc_message tc_message = { message };
            if (olsr_handle_tc_message(&pkt->data, key, &tc_message))
                return -1;
            break;
        }
        default:
            // Unsupported message type - ignore it
            break;
        }

        // Point to the end of the message
        pkt->data = message.end;
    }


    return 0;
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

	struct topology_set *ts = find_or_create_topology_set(tc_set, &message->comm.orig);

    if (ts == NULL) {
        msg(MSG_ERROR, "Failed to allocate memory for topology set.");

        return -1;
    }

    // Check if the packet is valid
    struct topology_set_entry *ts_entry = ts->first;

    while (ts_entry != NULL) {
        if (SEQNO_GREATER_THAN(ts_entry->seq, message->ansn)) {
            msg(MSG_INFO, "Stored sequence number is larger than received packet. Ignoring TC message.");

            return 0;
        }

        ts_entry = ts_entry->next;
    }

    while (*data < message->comm.end) {
		union olsr_ip_addr addr;

		pkt_get_ip_address(data, &addr, key->protocol);

		ts_entry = find_or_create_topology_set_entry(ts, &addr);
		if (ts_entry == NULL) {
			msg(MSG_ERROR, "Failed to allocate memory for topology set entry.");

			return -1;
		}

		ts_entry->seq = message->ansn;
		ts_entry->time = time(NULL) + message->comm.vtime / 10e6;

        if (message->comm.type == TC_LQ_MESSAGE) {
			// The LQ value depends on the utilized LQ plugin hence we read the whole 32 bits here so they can
			// be exported as-is.


			pkt_get_u32(data, &ts_entry->lq_parameters);
		}
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

	time_t now = time(NULL);

	struct hello_set *hs = find_or_create_hello_set(hello_set, &message->comm.orig);

	if (hs == NULL) {
		msg(MSG_ERROR, "Failed to allocate memory for hello set.");

		return -1;
	}

    pkt_ignore_u16(data); // Reserved
    pkt_get_reltime(data, &message->htime);
    pkt_get_u8(data, &message->will);

	hs->htime = now + message->htime;

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

			struct hello_set_entry *hs_entry = find_or_create_hello_set_entry(hs, &addr);

			if (hs_entry == NULL) {
				msg(MSG_ERROR, "Failed to allocate memory for hello_set_entry.");
				return -1;
			}

			hs_entry->link_code = info.link_code.val;
			hs_entry->vtime = now + message->comm.vtime;

			if (message->comm.type == HELLO_LQ_MESSAGE) {
				pkt_get_u32(data, &hs_entry->lq_parameters);
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

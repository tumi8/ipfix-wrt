#include "ip_helper.h"

/**
  * Extracts the transport protocol from the given IPv6 packet. \a pktdata
  * should point to the beginning of the IPv6 header. After this function
  * completes successfully the data member of pktdata will point to the
  * beginning of the transport protocol's payload or to an undefined memory
  * location if it failed.
  *
  * \return The transport protocol identifier as assigned by IANA
  *         (http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml)
  *         or -1 if the IPv6 packet was invalid.
  */
int ipv6_extract_transport_protocol(struct pktinfo *pkt) {
	if (pkt->data + sizeof(struct ip6_hdr) > pkt->end_data) {
		DPRINTF("Packet too short to contain IPv6 header.");
		return -1;
	}

	const struct ip6_hdr * const hdr = (const struct ip6_hdr * const) pkt->data;
	pkt->data += sizeof(struct ip6_hdr);

	uint8_t nxt_hdr = hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	while (1) {
		switch (nxt_hdr) {
		case 0: // Hop-by-hop
		case 43: // Routing header
		case 60: // Destination options
			if (pkt->data + sizeof(struct ip6_ext) > pkt->end_data) {
				DPRINTF("Packet too short to contain IPv6 extension header.");
				return -1;
			}
			struct ip6_ext *ext = (struct ip6_ext *) pkt->data;
			pkt->data += sizeof(struct ip6_ext);
			if (pkt->data + ext->ip6e_len > pkt->end_data) {
				DPRINTF("Packet too short to contain next IPv6 extension header.");
				return -1;
			}

			pkt->data += ext->ip6e_len;
			nxt_hdr = ext->ip6e_nxt;
			break;
		case 44: // Fragment header
			if (pkt->data + sizeof(struct ip6_frag) > pkt->end_data) {
				DPRINTF("Packet too short to contain IPv6 fragment header.");
				return -1;
			}
			struct ip6_frag *fext = (struct ip6_frag *) pkt->data;
			nxt_hdr = fext->ip6f_nxt;
			pkt->data += sizeof(struct ip6_frag);
			break;
		case 51: // Authentication Header
		{
			if (pkt->data + 2 * sizeof(uint8_t) > pkt->end_data) {
				DPRINTF("Packet too short to contain authentication header.");
				return -1;
			}
			uint8_t nxt_len;
			pkt_get_u8(&pkt->data, &nxt_hdr);
			pkt_get_u8(&pkt->data, &nxt_len);

			if (pkt->data + 4 * nxt_len > pkt->end_data) {
				DPRINTF("Packet too short to contain next extension header.");
				return -1;
			}
			pkt->data += 4 * nxt_len;
			break;
		}
		case 6: // TCP
			return 6;
		case 17: // UDP
			return 17;
		default:
			// ESP (Type 50) is also ignored as we cannot determine the
			// underlying protocol.
			DPRINTF("Unsupported IPv6 extension header (%d)", nxt_hdr);
			return -1;
		}
	}
}

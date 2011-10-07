/**
  * Data structures and helpers for the OLSR protocol. Heavily based on the definitions from
  * the OLSRd project.
  *
  */
#ifndef OLSR_PROTOCOL_H_
#define OLSR_PROTOCOL_H_

#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../ipfixlolib/msg.h"
#include "mantissa.h"
#include "ip_helper.h"

#define OLSR_PACKET_HEADER_LEN 4
// Message header len without the originator address
#define OLSR_MESSAGE_HEADER_LEN 8

#define OLSR_TC_MESSAGE_HEADER_LEN 4
#define OLSR_TC_LQ_MESSAGE_HEADER_LEN OLSR_TC_MESSAGE_HEADER_LEN + 2

#define OLSR_HELLO_MESSAGE_HEADER_LEN 4

#define OLSR_HELLO_INFO_HEADER_LEN 4

/* Seqnos are 16 bit values */

#define MAXVALUE 0xFFFF

/* Macro for checking seqnos "wraparound" */
#define SEQNO_GREATER_THAN(s1, s2)                \
    (((s1 > s2) && (s1 - s2 <= (MAXVALUE/2))) \
    || ((s2 > s1) && (s2 - s1 > (MAXVALUE/2))))

enum olsr_message_type {
    HELLO_MESSAGE=1,
    TC_MESSAGE=2,
    HELLO_LQ_MESSAGE=201,
    TC_LQ_MESSAGE=202
};

/**
  * Definitions from OLSRd sources.
  */

/* deserialized OLSR packet header */

struct olsr_packet {
    uint16_t size;
    uint16_t seqno;
};

/* deserialized OLSR header */

struct olsr_common {
    uint8_t type;
    olsr_reltime vtime;
    uint16_t size;
    union olsr_ip_addr orig;
    uint8_t ttl;
    uint8_t hops;
    uint16_t seqno;

    /**
    * Pointer to the end of the message.
    */
    const u_char *end;
};

/* deserialized LQ_HELLO */

struct olsr_hello_message {
    struct olsr_common comm;
    olsr_reltime htime;
    uint8_t will;
    struct lq_hello_neighbor *neigh;
};

/* serialized LQ_HELLO */
struct olsr_hello_message_info {
    union {
        uint8_t link_type:2;
        uint8_t neigh_type:2;
        uint8_t val;
    } link_code;
    uint16_t size;
};

/* deserialized LQ_TC */
struct olsr_tc_message {
    struct olsr_common comm;
    uint16_t ansn;
    uint8_t lower_border;
    uint8_t upper_border;
};

static inline void
pkt_get_reltime(const uint8_t ** p, olsr_reltime * var)
{
	*var = me_to_reltime(**p);
	*p += sizeof(uint8_t);
}
#endif

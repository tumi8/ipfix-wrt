#ifndef FLOWS_H_
#define FLOWS_H_

#include <netinet/in.h>

#include <time.h>
#include <poll.h>

#include <stdbool.h>

#include "khash.h"
#include "capture.h"
#include "olsr_protocol.h"

#ifndef ETHERTYPE_IPV6
// Define it here as some platforms do not define it.
#define ETHERTYPE_IPV6 0x86dd
#endif

#ifdef SUPPORT_ANONYMIZATION
#include "anonymize/cryptopan.h"
#endif

struct flow_key_t;
struct flow_info_t;

uint32_t flow_key_hash_code(struct flow_key_t *key);
int flow_key_equals(struct flow_key_t *a, struct flow_key_t *b);

#define hash_code(key) flow_key_hash_code(key)
#define hash_eq(a, b) flow_key_equals(a, b)

KHASH_INIT(1, struct flow_key_t *, struct flow_info_t *, 1, hash_code, hash_eq)

typedef struct flow_capture_session_t {
    /**
	  * Hash table containing the currently active IPv4 flows.
      */
	khash_t(1) *ipv4_flow_database;

#ifdef SUPPORT_IPV6
	/**
	  * Hash table containing the currently active IPv6 flows.
	  */
	khash_t(1) *ipv6_flow_database;
#endif

#ifdef SUPPORT_ANONYMIZATION
	/**
	  * State for CryptoPAN.
	  */
	struct cryptopan cryptopan;
#endif
    /**
      * The timeout in seconds after which a flow is regarded as inactive and
      * will be exported.
      *
      * Note: A flow may be exported before the timeout expires (e.g. due to
      * protocol semantics such as a TCP FIN or RST).
      */
    uint16_t export_timeout;

	/**
	  * The associated capture session.
	  */
	struct capture_session *capture_session;
} flow_capture_session;

typedef struct flow_key_t {
    /**
	  * Stores the network protocol of this flow.
	  */
    network_protocol protocol;
    /**
	  * Stores the transport protocol of this flow.
	  */
    transport_protocol t_protocol;
    /**
	  * Source port of the flow.
	  * NOTE: This value is in network by order.
	  */
    uint16_t src_port;
    /**
	  * Destination port of the flow.
	  * NOTE: This value is in network by order.
	  */
    uint16_t dst_port;
	/**
	  * Source address of flow.
	  */
	union olsr_ip_addr src_addr;
	/**
	  * Destination address of flow.
	  */
	union olsr_ip_addr dst_addr;
} flow_key;

/**
  * Structure holding general information about the flow.
  */
typedef struct flow_info_t {
    /**
   * Timestamp at which the first packet belonging to this flow was seen.
   */
    time_t first_packet_timestamp;

    /**
   * Timestamp at which the last packet belonging to this flow was seen.
   */
    time_t last_packet_timestamp;

    /**
   * The total number of bytes which have been transferred.
   */
	uint64_t total_bytes;
} flow_info;

int start_flow_capture_session(flow_capture_session *session, uint16_t export_timeout);
void stop_flow_capture_session(flow_capture_session *session);

int add_interface(flow_capture_session *session, char *device_name, bool enable_promisc);

#endif

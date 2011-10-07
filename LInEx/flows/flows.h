#ifndef FLOWS_H_
#define FLOWS_H_

#include <netinet/in.h>

#include <time.h>
#include <poll.h>

#include <stdbool.h>

#include "khash.h"
#include "capture.h"
#include "olsr_protocol.h"

// The maximum number of interfaces which can be added to one capture session
#define MAXIMUM_INTERFACE_COUNT 1

#ifndef ETHERTYPE_IPV6
// Define it here as some platforms do not define it.
#define ETHERTYPE_IPV6 0x86dd
#endif

struct flow_key_t;
struct flow_info_t;

uint32_t flow_key_hash_code(struct flow_key_t *key);
int flow_key_equals(struct flow_key_t *a, struct flow_key_t *b);

#define hash_code(key) flow_key_hash_code(key)
#define hash_eq(a, b) flow_key_equals(a, b)

KHASH_INIT(1, struct flow_key_t *, struct flow_info_t *, 1, hash_code, hash_eq)

typedef struct capture_session_t {
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

    /**
      * The timeout in seconds after which a flow is regarded as inactive and
      * will be exported.
      *
      * Note: A flow may be exported before the timeout expires (e.g. due to
      * protocol semantics such as a TCP FIN or RST).
      */
    uint16_t export_timeout;

	/**
	  * Total number of interfaces added to this session.
	  */
	size_t interface_count;
	/**
	  * Capture information for each interface added to this session.
	  */
	struct capture_info *interfaces[MAXIMUM_INTERFACE_COUNT];
} capture_session;

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
	  */
    uint16_t src_port;
    /**
	  * Destination port of the flow.
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

int start_capture_session(capture_session *session, uint16_t export_timeout);
void stop_capture_session(capture_session *session);

void statistics_callback(capture_session *session);
int add_interface(capture_session *session, char *device_name, bool enable_promisc);

#endif

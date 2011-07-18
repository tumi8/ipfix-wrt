#ifndef FLOWS_H_
#define FLOWS_H_

#include <pcap.h>
#include <netinet/in.h>

#include <time.h>

#include "khash.h"

// The number of bytes to capture
#define CAPTURE_LENGTH 128

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
	* PCAP handle - only set if capturing is active.
	*/
	pcap_t *handle;
	/**
	  * Error buffer for PCAP errors.
	  */
	char errbuf[PCAP_ERRBUF_SIZE];
	/**
	  * The data link type of the attached interface.
	  */
	int datalink_type;
	/**
	  * Hash table containing the currently active flows.
	  */
	khash_t(1) *flow_database;
	/**
	  * The timeout in seconds after which a flow is regarded as inactive and
	  * will be exported.
	  *
	  * Note: A flow may be exported before the timeout expires (e.g. due to
	  * protocol semantics such as a TCP FIN or RST).
	  */
	uint16_t export_timeout;
} capture_session;

typedef enum transport_protocol_t {
	TRANSPORT_TCP,
	TRANSPORT_UDP
} transport_protocol;

typedef enum network_protocol_t {
	IPv4,
	IPv6
} network_protocol;

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

	union {

	};
} flow_key;

typedef struct ipv4_flow_key_t {
	flow_key key;
	/**
	  * Source IPv4 address of this flow.
	  */
	uint32_t src_addr;
	/**
	  * Destination IPv4 address of this flow.
	  */
	uint32_t dst_addr;
} ipv4_flow_key;

typedef struct ipv6_flow_key_t {
	flow_key key;
	/**
	  * Source IPv6 address of this flow.
	  */
	struct in6_addr src_addr;
	/**
	  * Destination IPv6 address of this flow.
	  */
	struct in6_addr dst_addr;
} ipv6_flow_key;

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
	uint32_t total_bytes;
} flow_info;

int start_capture_session(capture_session *session, char *device_name, uint16_t export_timeout);
void stop_capture_session(capture_session *session);
int capture(capture_session *session);

#endif

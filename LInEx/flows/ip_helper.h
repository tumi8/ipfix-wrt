#ifndef IP_HELPER_H_
#define IP_HELPER_H_
#include "../ipfixlolib/msg.h"
#include <stdlib.h>
#include <string.h>
#include <byteswap.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

struct pktinfo {
	const uint8_t *const start_data;
	const uint8_t *const end_data;
	const uint8_t *data;
	const uint16_t orig_len;
	const struct timeval *tv;
};

typedef enum transport_protocol_t {
	TRANSPORT_TCP,
	TRANSPORT_UDP
} transport_protocol;

typedef enum network_protocol_t {
	IPv4,
#ifdef SUPPORT_IPV6
	IPv6
#endif
} network_protocol;

union olsr_ip_addr {
	struct in_addr v4;
#ifdef SUPPORT_IPV6
	struct in6_addr v6;
#endif
};

typedef struct ip_addr_t {
	network_protocol protocol;
	union olsr_ip_addr addr;
} ip_addr;

/**
  * Returns the length (in bytes) of the given network address.
  */
static inline uint16_t ip_addr_len(enum network_protocol_t type) {
	switch (type) {
	case IPv4:
		return sizeof(struct in_addr);
#ifdef SUPPORT_IPV6
	case IPv6:
		return sizeof(struct in6_addr);
#endif
	default:
		THROWEXCEPTION("Unsupported IP address type %d", type);
	}
}

static inline void
pkt_get_u8(const uint8_t ** p, uint8_t * var)
{
	*var = *(const uint8_t *)(*p);
	*p += sizeof(uint8_t);
}
static inline void
pkt_get_u16(const uint8_t ** p, uint16_t * var)
{
	*var = ntohs(**((const uint16_t **)p));
	*p += sizeof(uint16_t);
}
static inline void
pkt_get_u32(const uint8_t ** p, uint32_t * var)
{
	*var = ntohl(**((const uint32_t **)p));
	*p += sizeof(uint32_t);
}
static inline void
pkt_get_s8(const uint8_t ** p, int8_t * var)
{
	*var = *(const int8_t *)(*p);
	*p += sizeof(int8_t);
}
static inline void
pkt_get_s16(const uint8_t ** p, int16_t * var)
{
	*var = ntohs(**((const int16_t **)p));
	*p += sizeof(int16_t);
}
static inline void
pkt_get_s32(const uint8_t ** p, int32_t * var)
{
	*var = ntohl(**((const int32_t **)p));
	*p += sizeof(int32_t);
}

static inline void
pkt_get_ip_address(const uint8_t ** p, union olsr_ip_addr * var,
				   enum network_protocol_t type) {
	if (type == IPv4) {
		var->v4.s_addr = *((uint32_t *) *p);
		*p += sizeof(uint32_t);
	} else {
#ifdef SUPPORT_IPV6
		memcpy(&var->v6.s6_addr, *p, sizeof(var->v6));
		*p += sizeof(var->v6);
#endif
	}
}

static inline void
pkt_ignore_u8(const uint8_t ** p)
{
	*p += sizeof(uint8_t);
}
static inline void
pkt_ignore_u16(const uint8_t ** p)
{
	*p += sizeof(uint16_t);
}
static inline void
pkt_ignore_u32(const uint8_t ** p)
{
	*p += sizeof(uint32_t);
}
static inline void
pkt_ignore_s8(const uint8_t ** p)
{
	*p += sizeof(int8_t);
}
static inline void
pkt_ignore_s16(const uint8_t ** p)
{
	*p += sizeof(int16_t);
}
static inline void
pkt_ignore_s32(const uint8_t ** p)
{
	*p += sizeof(int32_t);
}

static inline void
pkt_put_u8(uint8_t ** p, uint8_t var)
{
	**((uint8_t **)p) = var;
	*p += sizeof(uint8_t);
}
static inline void
pkt_put_u16(uint8_t ** p, uint16_t var)
{
	**((uint16_t **)p) = htons(var);
	*p += sizeof(uint16_t);
}
static inline void
pkt_put_u32(uint8_t ** p, uint32_t var)
{
	**((uint32_t **)p) = htonl(var);
	*p += sizeof(uint32_t);
}
static inline void
pkt_put_u64(uint8_t ** p, uint64_t var)
{
#if BYTE_ORDER == LITTLE_ENDIAN
	var = bswap_64(var);
#endif
	**((uint64_t **)p) = var;
	*p += sizeof(uint64_t);
}
static inline void
pkt_put_s8(uint8_t ** p, int8_t var)
{
	**((int8_t **)p) = var;
	*p += sizeof(int8_t);
}
static inline void
pkt_put_s16(uint8_t ** p, int16_t var)
{
	**((int16_t **)p) = htons(var);
	*p += sizeof(int16_t);
}
static inline void
pkt_put_s32(uint8_t ** p, int32_t var)
{
	**((int32_t **)p) = htonl(var);
	*p += sizeof(int32_t);
}

static inline void
pkt_put_ipaddress(uint8_t ** p, const union olsr_ip_addr *var, network_protocol proto)
{
	memcpy(*p, var, ip_addr_len(proto));
	*p += ip_addr_len(proto);
}


#ifdef SUPPORT_IPV6
int ipv6_extract_transport_protocol(struct pktinfo *pkt);
#endif

#endif

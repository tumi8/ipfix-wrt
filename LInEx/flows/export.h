#ifndef EXPORT_H_
#define EXPORT_H_

#include "topology_set.h"
#include "../ipfixlolib/ipfixlolib.h"

#define ENTERPRISE_ID 8889
enum olsr_ipfix_type {
    SequenceNumberType=1, // uint16
    GatewayIPv4AddressType=2, // ipv4Address
    HNAIPv4AddressType=3, // ipv4Address
    HNAIPv4AddressPrefixLength=4, // uint8
    TargetHostIPv4Type=5, // ipv4Address
    OLSRSequenceNumberType=6, // uint16
    TargetHostIPv6Type=7, // ipv6Address
    GatewayIPv6AddressType=8 // ipv6Address
};

#define FULL_BASE_TEMPLATE_ID 888
#define HOST_INFO_IPV4_TEMPLATE_ID 889
#define FULL_HNA4_TEMPLATE_ID 890
#define TARGET_HOST_IPV4_TEMPLATE_ID 891
#define HOST_INFO_IPV6_TEMPLATE_ID 892
#define TARGET_HOST_IPV6_TEMPLATE_ID 893

int declare_templates(ipfix_exporter *exporter);
int export_full(ipfix_exporter *exporter, khash_t(2) *tc_set);
#endif

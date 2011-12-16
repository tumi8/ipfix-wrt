#ifndef EXPORT_H_
#define EXPORT_H_

#include "node_set.h"
#include "../ipfixlolib/ipfixlolib.h"

#define ENTERPRISE_ID 8889
enum olsr_ipfix_type {
	ExportTimestamp=1, // dateTimeSeconds
	NodeAddressIPv4Type=2, // ipv4Address
	NodeAddressIPv6Type=3, // ipv6Address
	OLSRSequenceNumberType=4, // uint16
	TargetHostIPv4Type=5, // ipv4Address
	TargetHostIPv6Type=6, // ipv6Address
	NeighborHostIPv4Type=7, // ipv4Address
	NeighborHostIPv6Type=8, // ipv6Address
	NeighborLinkCodeType=9, // uint8
	NeighborLQType=10, // uint32
	CaptureInterfaceType=11, // uint8 (0 = Flow, 1 = OLSR)
	CaptureInterfaceIndex=12, // uint8
	CaptureStatisticsTotalPackets=13, // uint32
	CaptureStatisticsDroppedPackets=14, // uint32
	CaptureStatisticsTimestamp=15, // dateTimeSeconds
	HNANetworkIPv4=16, // ipv4Address
	HNANetworkPrefixLength=17, // uint8_t
	HNANetworkIPv6=18, // ipv6Address
	MIDAddressIPv4=19, // ipv4Address
	MIDAddressIPv6=20, // ipv6Address
	HTimeType=21, // uint8_t
	TargetHostLQType=22 // uint32_t
};

enum olsr_template_id {
	BaseTemplate=256,
	NodeTemplateIPv4=257,
	TargetHostTemplateIPv4=258,
	NeighborHostTemplateIPv4=259,
	HNATemplateIPv4=260,
	MIDTemplateIPv4=261,
#ifdef SUPPORT_IPV6
	NodeTemplateIPv6=262,
	TargetHostTemplateIPv6=263,
	NeighborHostTemplateIPv6=264,
	HNATemplateIPv6=265,
	MIDTemplateIPv6=266,
	FlowTemplateIPv6=267,
#endif
	FlowTemplateIPv4=268,
	CaptureStatisticsTemplate=269,
};

struct olsr_template_field {
	uint16_t ie_id;
	uint16_t ie_enterprise_id;
	uint16_t field_length;
};

struct olsr_template_info {
	enum olsr_template_id template_id;
	struct olsr_template_field *fields;
};

struct export_parameters {
	ipfix_exporter *exporter;
	node_set_hash *node_set;
};

struct export_flow_parameter {
	ipfix_exporter *exporter;
	flow_capture_session *session;
};

struct export_capture_parameter {
	ipfix_exporter *exporter;
	struct capture_session *flow_session;
	struct capture_session *olsr_session;
};

int declare_templates(ipfix_exporter *exporter);
void export_full(struct export_parameters *params);
void export_flows(struct export_flow_parameter *param);
void export_capture_statistics(struct export_capture_parameter *param);
#endif

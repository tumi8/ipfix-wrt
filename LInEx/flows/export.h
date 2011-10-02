#ifndef EXPORT_H_
#define EXPORT_H_

#include "node_set.h"
#include "../ipfixlolib/ipfixlolib.h"

#define ENTERPRISE_ID 8889
enum olsr_ipfix_type {
    SequenceNumberType=1, // uint16
	NodeAddressIPv4Type=2, // ipv4Address
	NodeAddressIPv6Type=3, // ipv6Address
	OLSRSequenceNumberType=4, // uint16
	TargetHostIPv4Type=5, // ipv4Address
	TargetHostIPv6Type=6, // ipv6Address
	NeighborHostIPv4Type=7, // ipv4Address
	NeighborHostIPv6Type=8, // ipv6Address
	NeighborLinkCodeType=9, // uint8
	NeighborLQType=10 // uint32
};

enum olsr_template_id {
	BaseTemplate = 888,
	NodeTemplateIPv4,
	NodeTemplateIPv6,
	TargetHostTemplateIPv4,
	TargetHostTemplateIPv6,
	NeighborHostTemplateIPv4,
	NeighborHostTemplateIPv6
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

int declare_templates(ipfix_exporter *exporter);
void export_full(struct export_parameters *params);
#endif

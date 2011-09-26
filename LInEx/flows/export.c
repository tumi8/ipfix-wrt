#include "export.h"
#include "topology_set.h"
#include "../ipfixlolib/msg.h"

struct buffer_info {
	uint8_t *pos;
	uint8_t *const start;
	uint8_t *const end;
};

struct export_status {
	khiter_t current_entry;
	struct topology_set_entry *ts_entry;
};

static u_char message_buffer[IPFIX_MAX_PACKETSIZE];

struct olsr_template_info templates[] = {
{ FullBaseTemplate,
	(struct olsr_template_field []) {
		{SequenceNumberType, ENTERPRISE_ID, sizeof(uint16_t)},
		{ 292, 0, 0xffff },
		{ 0 }
	}
},
{ TopologyControlTemplateIPv4,
	(struct olsr_template_field []) {
		{GatewayAddressIPv4Type, ENTERPRISE_ID, sizeof(uint32_t)},
		{ 292, 0, 0xffff },
		{ 0 }
	}
},
{ TopologyControlTemplateIPv6,
	(struct olsr_template_field []) {
		{GatewayAddressIPv6Type, ENTERPRISE_ID, sizeof(struct in6_addr)},
		{ 292, 0, 0xffff },
		{ 0 }
	}
},
{ TargetHostTemplateIPv4,
	(struct olsr_template_field []) {
		{TargetHostIPv4Type, ENTERPRISE_ID, sizeof(uint32_t)},
		{OLSRSequenceNumberType, ENTERPRISE_ID, sizeof(uint16_t) },
		{ 0 }
	}
},
{ TargetHostTemplateIPv6,
	(struct olsr_template_field []) {
		{TargetHostIPv6Type, ENTERPRISE_ID, sizeof(struct in6_addr)},
		{OLSRSequenceNumberType, ENTERPRISE_ID, sizeof(uint16_t) },
		{ 0 }
	}
}
};

static size_t target_host_len(const struct topology_set *ts);
static void target_host_encode(const struct topology_set *ts, const struct topology_set_entry *entry, struct buffer_info *buffer);

static size_t target_host_list_len(const struct ip_addr_t *addr, const struct topology_set *ts);
static size_t target_host_list_encode(const struct ip_addr_t *addr, const struct topology_set *ts, struct buffer_info *buffer, struct export_status *status);

static size_t topology_control_len(const struct ip_addr_t *addr, const struct topology_set *ts);
static size_t topology_control_encode(const struct ip_addr_t *addr, const struct topology_set *ts, struct buffer_info *buffer, struct export_status *status);

static size_t topology_control_list_len(network_protocol proto, const tc_set_hash *tc_set);
static size_t topology_control_list_encode(network_protocol proto, const tc_set_hash *tc_set, struct buffer_info *buffer, struct export_status *status);

static size_t full_base_encode(uint16_t sequence_number, const tc_set_hash *tc_set, struct buffer_info *buffer, struct export_status *status);

inline uint8_t *pkt_put_variable_length(uint8_t **buffer) {
	pkt_put_u8(buffer, 0xff);
	*buffer += sizeof(uint16_t);

	return *buffer - 2;
}


static size_t count_fields(const struct olsr_template_info *template_info) {
	size_t field_count = 0;
	struct olsr_template_field *template_field = template_info->fields;

	while (template_field->ie_id != 0) {
		field_count++;
		template_field++;
	}

	return field_count;
}

static int declare_template(ipfix_exporter *exporter, const struct olsr_template_info *template_info) {
	if (ipfix_start_template(exporter, template_info->template_id, count_fields(template_info)))
		return -1;

	struct olsr_template_field *template_field = template_info->fields;

	while (template_field->ie_id != 0) {
		if (ipfix_put_template_field(exporter, template_info->template_id, template_field->ie_id, template_field->field_length, template_field->ie_enterprise_id))
			return -1;

		template_field++;
	}

	if (ipfix_end_template(exporter, template_info->template_id))
		return -1;

	return 0;
}

/**
  * Declares the IPFIX templates needed.
  *
  * Returns 0 on success, -1 on failure.
  */
int declare_templates(ipfix_exporter *exporter) {
	size_t i, r;

	for (i = 0; i < sizeof(templates) / sizeof(struct olsr_template_info); i++) {
		if (declare_template(exporter, &templates[i])) {
			for (r = (i - 1); r >= 0; r--) {
				ipfix_remove_template(exporter, templates[r].template_id);
			}

			return -1;
		}
	}

    return 0;
}

static size_t full_base_encode(uint16_t sequence_number, const tc_set_hash *tc_set, struct buffer_info *buffer, struct export_status *status) {
	uint8_t *const buffer_start = buffer->pos;

	pkt_put_u16(&buffer->pos, sequence_number);

	uint8_t *len_ptr = pkt_put_variable_length(&buffer->pos);
	size_t len = topology_control_list_encode(IPv4, tc_set, buffer, status);

	pkt_put_u16(&len_ptr, len);

	DPRINTF("Topology control list length: %d", len);

	return (buffer->pos - buffer_start);
}

static size_t topology_control_list_len(network_protocol proto, const tc_set_hash *tc_set) {
	size_t len = sizeof(uint8_t) + sizeof(uint16_t); // List header

	len += sizeof(uint8_t) + sizeof(uint16_t); // Variable length encoding of contained list

	return len;
}

static size_t topology_control_list_encode(network_protocol proto, const tc_set_hash *tc_set, struct buffer_info *buffer, struct export_status *status) {
	uint8_t *const buffer_start = buffer->pos;

	pkt_put_u8(&buffer->pos, 0x03); // allOf semantic

	switch(proto) {
	case IPv4:
		pkt_put_u16(&buffer->pos, TopologyControlTemplateIPv4);
		break;
	case IPv6:
		pkt_put_u16(&buffer->pos, TopologyControlTemplateIPv6);
		break;
	default:
		THROWEXCEPTION("Invalid address type %d", proto);
		break;
	}

	for (; status->current_entry != kh_end(tc_set); ++(status->current_entry)) {
		if (!kh_exist(tc_set, status->current_entry))
			continue;

		status->ts_entry = NULL;

		struct ip_addr_t addr = kh_key(tc_set, status->current_entry);
		struct topology_set *ts = kh_value(tc_set, status->current_entry);

		if (buffer->pos + topology_control_len(&addr, ts) > buffer->end)
			break;

		topology_control_encode(&addr, ts, buffer, status);
	}

	return (buffer->pos - buffer_start);
}

/**
  * Returns the minimum length of a topology control template record.
  */
static size_t topology_control_len(const struct ip_addr_t *addr, const struct topology_set *ts) {
	size_t len = ip_addr_len(addr->protocol);

	len += sizeof(uint8_t) + sizeof(uint16_t); // Variable length of list
	len += target_host_list_len(addr, ts);

	return len;
}

static size_t topology_control_encode(const struct ip_addr_t *addr, const struct topology_set *ts, struct buffer_info *buffer, struct export_status *status) {
	uint8_t *const buffer_start = buffer->pos;

	pkt_put_ipaddress(&buffer->pos, &addr->addr, addr->protocol); // Gateway IP address

	uint8_t *len_ptr = pkt_put_variable_length(&buffer->pos);
	size_t list_len = target_host_list_encode(addr, ts, buffer, status);

	pkt_put_u16(&len_ptr, list_len);

	return (buffer->pos - buffer_start);
}

/**
  * Returns the minimum size of a target host list.
  */
static size_t target_host_list_len(const struct ip_addr_t *addr, const struct topology_set *ts) {
	return sizeof(uint8_t) + sizeof(uint16_t); // List header
}

static size_t target_host_list_encode(const struct ip_addr_t *addr, const struct topology_set *ts, struct buffer_info *buffer, struct export_status *status) {
	uint8_t *const buffer_start = buffer->pos;

	pkt_put_u8(&buffer->pos, 0x03); // allOf semantic

	switch(addr->protocol) {
	case IPv4:
		pkt_put_u16(&buffer->pos, TargetHostTemplateIPv4);
		break;
	case IPv6:
		pkt_put_u16(&buffer->pos, TargetHostTemplateIPv6);
		break;
	default:
		THROWEXCEPTION("Invalid address type %d", addr->protocol);
		break;
	}

	// Add topology set entries
	if (status->ts_entry == NULL)
		status->ts_entry = ts->first;

	while (status->ts_entry != NULL) {
		if (buffer->pos + target_host_len(ts) > buffer->end)
			break;

		target_host_encode(ts, status->ts_entry, buffer);

		status->ts_entry = status->ts_entry->next;
	}

	return (buffer->pos - buffer_start);
}

/**
  * Returns the minium size of a target host data record.
  */
static size_t target_host_len(const struct topology_set *ts) {
	return sizeof(uint16_t) + ip_addr_len(ts->protocol);
}

static void target_host_encode(const struct topology_set *ts, const struct topology_set_entry *entry, struct buffer_info *buffer) {
	DPRINTF("Encoding: %d %d", entry->dest_addr.v4, ts->protocol);
	pkt_put_ipaddress(&buffer->pos, &entry->dest_addr, ts->protocol);
	pkt_put_u16(&buffer->pos, entry->seq);
}

/**
  * Performs a full export.
  */
void export_full(struct export_parameters *params) {
	ipfix_exporter *exporter = params->exporter;
	khash_t(2) *tc_set = params->tc_set;

    if (tc_set == NULL || exporter == NULL)
		return;

	msg(MSG_INFO, "Exporting OLSR data");

	// Expire old entries
	expire_topology_set_entries(tc_set);

	struct export_status status;

	status.ts_entry = NULL;
	status.current_entry = kh_begin(tc_set);

	while (status.current_entry != kh_end(tc_set)) {
		if (ipfix_start_data_set(exporter, htons(FullBaseTemplate))) {
			msg(MSG_ERROR, "Failed to start data set.");

			return;
		}

		struct buffer_info info = { message_buffer, message_buffer, message_buffer + 30 };
		size_t buffer_len = full_base_encode(0, tc_set, &info, &status);

		DPRINTF("Status at %p %d", status.ts_entry, status.current_entry);

		if (ipfix_put_data_field(exporter, message_buffer, buffer_len)) {
			msg(MSG_ERROR, "Failed to add data record.");
			return;
		}

		if (ipfix_end_data_set(exporter, 1)) {
			msg(MSG_ERROR, "Failed to end data set.");
			return;
		}

		if (ipfix_send(exporter)) {
			msg(MSG_ERROR, "Failed to send IPFIX message.");
			return;
		}
	}
}




#include "export.h"
#include "topology_set.h"
#include "hello_set.h"
#include "../ipfixlolib/msg.h"
#include "../ipfixlolib/ipfix.h"

#define SUBTEMPLATE_MULTILIST_HDR_LEN (sizeof(uint16_t) + sizeof(uint16_t))
#define SUBTEMPLATE_LIST_HDR_LEN (sizeof(uint16_t) + sizeof(uint8_t))

struct buffer_info {
	uint8_t *pos;
	uint8_t *const start;
	uint8_t *const end;
};

/**
  * Stores the export status (i.e. how much data of a host was exported
  * until now). This allows fragmenting the information over multiple
  * IPFIX packets.
  */
struct export_status {
	/**
   * The current host which is being exported. Set this to kh_begin(hash)
   * when you want to start from the beginning of the host list.
   */
	khiter_t current_entry;

	/**
   * The topology set entry of the host which still needs to be exported.
   *
   * This value should be NULL if there are no more topology set entries
   * which should be exported.
   */
	struct topology_set_entry *ts_entry;

	/**
   * The hello set entry of the host which still needs to be exported.
   *
   * This value should be NULL if there are no more hello set entries
   * which should be exported.
   */
	struct hello_set_entry *hs_entry;
};

static u_char message_buffer[IPFIX_MAX_PACKETSIZE];

struct olsr_template_info templates[] = {
{ BaseTemplate,
	(struct olsr_template_field []) {
		{SequenceNumberType, ENTERPRISE_ID, sizeof(uint16_t)},
		{ 292, 0, 0xffff },
		{ 0 }
	}
},
{ NodeTemplateIPv4,
	(struct olsr_template_field []) {
		{NodeAddressIPv4Type, ENTERPRISE_ID, sizeof(uint32_t)},
		{ 293, 0, 0xffff },
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
{ NeighborHostTemplateIPv4,
	(struct olsr_template_field []) {
		{NeighborHostIPv4Type, ENTERPRISE_ID, sizeof(uint32_t)},
		{NeighborLinkCodeType, ENTERPRISE_ID, sizeof(uint8_t) },
		{NeighborLQType, ENTERPRISE_ID, sizeof(uint32_t) },
		{ 0 }
	}
},
{ FlowTemplateIPv4,
	(struct olsr_template_field []) {
		{IPFIX_TYPEID_sourceIPv4Address, 0, sizeof(uint32_t)},
		{IPFIX_TYPEID_destinationIPv4Address, 0, sizeof(uint32_t) },
		{IPFIX_TYPEID_protocolIdentifier, 0, sizeof(uint8_t) },
		{IPFIX_TYPEID_sourceTransportPort, 0, sizeof(uint16_t) },
		{IPFIX_TYPEID_destinationTransportPort, 0, sizeof(uint16_t) },
		{IPFIX_TYPEID_octetTotalCount, 0, sizeof(uint64_t) },
		{IPFIX_TYPEID_flowStartSeconds, 0, sizeof(uint32_t) },
		{IPFIX_TYPEID_flowEndSeconds, 0, sizeof(uint32_t) },
		{ 0 }
	}
},
#ifdef SUPPORT_IPV6
{ NodeTemplateIPv6,
	(struct olsr_template_field []) {
		{NodeAddressIPv6Type, ENTERPRISE_ID, sizeof(struct in6_addr)},
		{ 293, 0, 0xffff },
		{ 0 }
	}
},
{ TargetHostTemplateIPv6,
	(struct olsr_template_field []) {
		{TargetHostIPv6Type, ENTERPRISE_ID, sizeof(struct in6_addr)},
		{OLSRSequenceNumberType, ENTERPRISE_ID, sizeof(uint16_t) },
		{ 0 }
	}
},
{ NeighborHostTemplateIPv6,
	(struct olsr_template_field []) {
		{NeighborHostIPv6Type, ENTERPRISE_ID, sizeof(struct in6_addr)},
		{NeighborLinkCodeType, ENTERPRISE_ID, sizeof(uint8_t) },
		{NeighborLQType, ENTERPRISE_ID, sizeof(uint32_t) },
		{ 0 }
	}
},
{ FlowTemplateIPv6,
	(struct olsr_template_field []) {
		{IPFIX_TYPEID_sourceIPv6Address, 0, sizeof(struct in6_addr)},
		{IPFIX_TYPEID_destinationIPv6Address, 0, sizeof(struct in6_addr) },
		{IPFIX_TYPEID_protocolIdentifier, 0, sizeof(uint8_t) },
		{IPFIX_TYPEID_sourceTransportPort, 0, sizeof(uint16_t) },
		{IPFIX_TYPEID_destinationTransportPort, 0, sizeof(uint16_t) },
		{IPFIX_TYPEID_octetTotalCount, 0, sizeof(uint64_t) },
		{IPFIX_TYPEID_flowStartSeconds, 0, sizeof(uint32_t) },
		{IPFIX_TYPEID_flowEndSeconds, 0, sizeof(uint32_t) },
		{ 0 }
	}
},
#endif
};

#define FLOW_TEMPLATE_LEN (sizeof(uint8_t) + 2 * sizeof(uint16_t) + sizeof(uint64_t) + 2 * sizeof(uint32_t))
#define FLOW_TEMPLATE_IPV4_LEN (FLOW_TEMPLATE_LEN + 2 * sizeof(uint32_t))
#define FLOW_TEMPLATE_IPV6_LEN (FLOW_TEMPLATE_LEN + 2 * sizeof(struct in6_addr))

static size_t target_host_len(const struct topology_set *ts);
static void target_host_encode(const struct topology_set *ts,
							   const struct topology_set_entry *entry,
							   struct buffer_info *buffer);

static size_t target_host_list_len(const struct ip_addr_t *addr,
								   const struct topology_set *ts);
static size_t target_host_list_encode(const struct ip_addr_t *addr,
									  const struct topology_set *ts,
									  struct buffer_info *buffer,
									  struct export_status *status);

static size_t node_len(const struct ip_addr_t *addr,
					   const struct node_entry *node);
static size_t node_encode(const struct ip_addr_t *addr,
						  const struct node_entry *node,
						  struct buffer_info *buffer,
						  struct export_status *status);

static size_t node_list_len(network_protocol proto,
							const node_set_hash *node_set);
static size_t node_list_encode(network_protocol proto,
							   const node_set_hash *node_set,
							   struct buffer_info *buffer,
							   struct export_status *status);

static size_t base_encode(uint16_t sequence_number,
						  const node_set_hash *node_set,
						  struct buffer_info *buffer,
						  struct export_status *status);


static size_t neighbor_host_len(const struct hello_set *hs);
static size_t neighbor_host_encode(const struct hello_set *hs,
								   const struct hello_set_entry *entry,
								   struct buffer_info *buffer);

static size_t neighbor_host_list_len(const struct ip_addr_t *addr,
									 const struct hello_set *neighbor_set);
static size_t neighbor_host_list_encode(const struct ip_addr_t *addr,
										const struct hello_set *neighbor_set,
										struct buffer_info *buffer,
										struct export_status *status);

static void export_flow_database(khash_t(1) *flow_database,
								 ipfix_exporter *exporter,
								 capture_session *session,
								 uint16_t template_id,
								 size_t template_len);

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

static int declare_template(ipfix_exporter *exporter,
							const struct olsr_template_info *template_info) {
	if (ipfix_start_template(exporter, template_info->template_id, count_fields(template_info)))
		return -1;

	struct olsr_template_field *template_field = template_info->fields;

	while (template_field->ie_id != 0) {
		if (ipfix_put_template_field(exporter,
									 template_info->template_id,
									 template_field->ie_id,
									 template_field->field_length,
									 template_field->ie_enterprise_id))
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

static size_t neighbor_host_len(const struct hello_set *hs) {
	return ip_addr_len(hs->protocol) + sizeof(uint8_t) + sizeof(uint32_t);
}

static size_t neighbor_host_encode(const struct hello_set *hs,
								   const struct hello_set_entry *entry,
								   struct buffer_info *buffer) {
	uint8_t *const start = buffer->pos;

	pkt_put_ipaddress(&buffer->pos, &entry->neighbor_addr, hs->protocol);
	pkt_put_u8(&buffer->pos, entry->link_code);
	pkt_put_u32(&buffer->pos, entry->lq_parameters);

	return (buffer->pos - start);
}

static size_t neighbor_host_list_len(const struct ip_addr_t *addr,
									 const struct hello_set *neighbor_set) {
	if (!neighbor_set)
		return 0;

	return SUBTEMPLATE_MULTILIST_HDR_LEN;
}

static size_t neighbor_host_list_encode(const struct ip_addr_t *addr,
										const struct hello_set *neighbor_set,
										struct buffer_info *buffer,
										struct export_status *status) {
	if (!neighbor_set)
		return 0;

	uint8_t *const buffer_start = buffer->pos;

	switch(addr->protocol) {
	case IPv4:
		pkt_put_u16(&buffer->pos, NeighborHostTemplateIPv4);
		break;
#ifdef SUPPORT_IPV6
	case IPv6:
		pkt_put_u16(&buffer->pos, NeighborHostTemplateIPv6);
		break;
#endif
	default:
		THROWEXCEPTION("Invalid address type %d", addr->protocol);
		break;
	}

	uint8_t *list_length = buffer->pos;
	pkt_put_u16(&buffer->pos, 0);

	uint8_t *const list_begin = buffer->pos;
	// Add topology set entries
	if (status->hs_entry == NULL)
		status->hs_entry = neighbor_set->first;

	while (status->hs_entry != NULL) {
		if (buffer->pos + neighbor_host_len(neighbor_set) > buffer->end)
			break;

		neighbor_host_encode(neighbor_set, status->hs_entry, buffer);

		status->hs_entry = status->hs_entry->next;
	}
	// Put the length of the written data
	pkt_put_u16(&list_length, (uint16_t) (buffer->pos - list_begin));

	return (buffer->pos - buffer_start);
}

static size_t base_encode(uint16_t sequence_number,
						  const node_set_hash *node_set,
						  struct buffer_info *buffer,
						  struct export_status *status) {
	uint8_t *const buffer_start = buffer->pos;

	pkt_put_u16(&buffer->pos, sequence_number);

	uint8_t *len_ptr = pkt_put_variable_length(&buffer->pos);
	size_t len = node_list_encode(IPv4, node_set, buffer, status);

	pkt_put_u16(&len_ptr, len);

	DPRINTF("Topology control list length: %d", len);

	return (buffer->pos - buffer_start);
}

static size_t node_list_len(network_protocol proto,
							const node_set_hash *node_set) {
	size_t len = SUBTEMPLATE_LIST_HDR_LEN; // List header

	len += sizeof(uint8_t) + sizeof(uint16_t); // Variable length encoding of contained list

	return len;
}

static size_t node_list_encode(network_protocol proto,
							   const node_set_hash *node_set,
							   struct buffer_info *buffer,
							   struct export_status *status) {
	uint8_t *const buffer_start = buffer->pos;

	pkt_put_u8(&buffer->pos, 0x03); // allOf semantic

	switch(proto) {
	case IPv4:
		pkt_put_u16(&buffer->pos, NodeTemplateIPv4);
		break;
#ifdef SUPPORT_IPV6
	case IPv6:
		pkt_put_u16(&buffer->pos, NodeTemplateIPv6);
		break;
#endif
	default:
		THROWEXCEPTION("Invalid address type %d", proto);
		break;
	}

	for (; status->current_entry != kh_end(node_set); ++(status->current_entry)) {
		if (!kh_exist(node_set, status->current_entry))
			continue;

		struct ip_addr_t addr = kh_key(node_set, status->current_entry);
		struct node_entry *node = kh_value(node_set, status->current_entry);

		if (buffer->pos + node_len(&addr, node) > buffer->end)
			break;

		node_encode(&addr, node, buffer, status);

		status->ts_entry = NULL;
		status->hs_entry = NULL;
	}

	return (buffer->pos - buffer_start);
}

/**
  * Returns the minimum length of a topology control template record.
  */
static size_t node_len(const struct ip_addr_t *addr,
					   const struct node_entry *node) {
	size_t len = ip_addr_len(addr->protocol);

	len += sizeof(uint8_t) + sizeof(uint16_t); // Variable length of list
	len += sizeof(uint8_t); // Length of subTemplateMultiList header (Semantics field)

	len += target_host_list_len(addr, node->topology_set);
	len += neighbor_host_list_len(addr, node->hello_set);

	return len;
}

static size_t node_encode(const struct ip_addr_t *addr,
						  const struct node_entry *node,
						  struct buffer_info *buffer,
						  struct export_status *status) {
	uint8_t *const buffer_start = buffer->pos;

	pkt_put_ipaddress(&buffer->pos, &addr->addr, addr->protocol); // Node IP address

	uint8_t *len_ptr = pkt_put_variable_length(&buffer->pos);

	size_t list_len = sizeof(uint8_t);

	pkt_put_u8(&buffer->pos, 0x3); // allOf semantics for subTemplateMultiList

	if (status->ts_entry || (!status->ts_entry && !status->hs_entry)) {
		// Only export target host list if there are unexported entries or
		// if there are no pending neighbor entries.
		list_len += target_host_list_encode(addr,
											node->topology_set,
											buffer,
											status);
	}

	list_len += neighbor_host_list_encode(addr,
										  node->hello_set,
										  buffer,
										  status);
	pkt_put_u16(&len_ptr, list_len);

	return (buffer->pos - buffer_start);
}

/**
  * Returns the minimum size of a target host list.
  */
static size_t target_host_list_len(const struct ip_addr_t *addr,
								   const struct topology_set *ts) {
	if (!ts)
		return 0;

	return SUBTEMPLATE_MULTILIST_HDR_LEN;
}

static size_t target_host_list_encode(const struct ip_addr_t *addr,
									  const struct topology_set *ts,
									  struct buffer_info *buffer,
									  struct export_status *status) {
	if (!ts)
		return 0;

	uint8_t *const buffer_start = buffer->pos;

	switch(addr->protocol) {
	case IPv4:
		pkt_put_u16(&buffer->pos, TargetHostTemplateIPv4);
		break;
#ifdef SUPPORT_IPV6
	case IPv6:
		pkt_put_u16(&buffer->pos, TargetHostTemplateIPv6);
		break;
#endif
	default:
		THROWEXCEPTION("Invalid address type %d", addr->protocol);
		break;
	}

	uint8_t *list_length = buffer->pos;
	pkt_put_u16(&buffer->pos, 0);

	uint8_t *const list_begin = buffer->pos;

	// Add topology set entries
	if (status->ts_entry == NULL)
		status->ts_entry = ts->first;

	while (status->ts_entry != NULL) {
		if (buffer->pos + target_host_len(ts) > buffer->end)
			break;

		target_host_encode(ts, status->ts_entry, buffer);

		status->ts_entry = status->ts_entry->next;
	}

	pkt_put_u16(&list_length, (buffer->pos - list_begin));

	return (buffer->pos - buffer_start);
}

/**
  * Returns the minium size of a target host data record.
  */
static size_t target_host_len(const struct topology_set *ts) {
	return sizeof(uint16_t) + ip_addr_len(ts->protocol);
}

static void target_host_encode(const struct topology_set *ts,
							   const struct topology_set_entry *entry,
							   struct buffer_info *buffer) {
	pkt_put_ipaddress(&buffer->pos, &entry->dest_addr, ts->protocol);
	pkt_put_u16(&buffer->pos, entry->seq);
}

/**
  * Performs a full export.
  */
void export_full(struct export_parameters *params) {
	ipfix_exporter *exporter = params->exporter;
	khash_t(2) *node_set = params->node_set;

	if (node_set == NULL || exporter == NULL)
		return;

	msg(MSG_INFO, "Exporting OLSR data");

	// Expire old entries
	expire_node_set_entries(node_set);

	struct export_status status;

	status.ts_entry = NULL;
	status.hs_entry = NULL;
	status.current_entry = kh_begin(node_set);

	while (status.current_entry != kh_end(node_set)) {
		if (ipfix_start_data_set(exporter, htons(BaseTemplate))) {
			msg(MSG_ERROR, "Failed to start data set.");

			return;
		}

		struct buffer_info info = { message_buffer, message_buffer, message_buffer + ipfix_get_remaining_space(exporter) };
		size_t buffer_len = base_encode(0, node_set, &info, &status);

		DPRINTF("Status at %p %p %d %d", status.ts_entry, status.hs_entry, status.current_entry, kh_end(node_set));

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

void export_flows(struct export_flow_parameter *param) {
	capture_session *session = param->session;
	ipfix_exporter *exporter = param->exporter;

	export_flow_database(session->ipv4_flow_database,
						 exporter,
						 session,
						 FlowTemplateIPv4,
						 FLOW_TEMPLATE_IPV4_LEN);
#ifdef SUPPORT_IPV6
	export_flow_database(session->ipv6_flow_database,
						 exporter,
						 session,
						 FlowTemplateIPv6,
						 FLOW_TEMPLATE_IPV6_LEN);
#endif
}

static void export_flow_database(khash_t(1) *flow_database,
								 ipfix_exporter *exporter,
								 capture_session *session,
								 uint16_t template_id,
								 size_t template_len) {
	time_t now = time(NULL);
	uint8_t *buffer = NULL;
	uint8_t *buffer_end = NULL;
	khiter_t k;

	for (k = kh_begin(flow_database); k != kh_end(flow_database); ++k) {
		if (!kh_exist(flow_database, k))
			continue;

		flow_key *key = kh_key(flow_database, k);
		flow_info *info = kh_value(flow_database, k);

		if (now - info->last_packet_timestamp < session->export_timeout)
			continue;

		kh_del(1, flow_database, k);

		if (buffer == NULL || (buffer + template_len) > buffer_end) {
			if (buffer != NULL) {
				if (ipfix_put_data_field(exporter,
										 message_buffer,
										 buffer - message_buffer)) {
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

			if (ipfix_start_data_set(exporter, htons(template_id))) {
				msg(MSG_ERROR, "Failed to start flow data set.");
				return;
			}

			buffer = message_buffer;
			buffer_end = message_buffer + ipfix_get_remaining_space(exporter);
		}

		pkt_put_ipaddress(&buffer, &key->src_addr, key->protocol);
		pkt_put_ipaddress(&buffer, &key->dst_addr, key->protocol);
		switch (key->t_protocol) {
		case TRANSPORT_UDP:
			pkt_put_u8(&buffer, 17);
			break;
		case TRANSPORT_TCP:
			pkt_put_u8(&buffer, 6);
			break;
		default:
			pkt_put_u8(&buffer, 255);
			break;
		}

		pkt_put_u16(&buffer, key->src_port);
		pkt_put_u16(&buffer, key->dst_port);
		pkt_put_u64(&buffer, info->total_bytes);
		pkt_put_u32(&buffer, info->first_packet_timestamp);
		pkt_put_u32(&buffer, info->last_packet_timestamp);

		free(key);
		free(info);
	}

	if (buffer != NULL && buffer != message_buffer) {
		if (ipfix_put_data_field(exporter,
								 message_buffer,
								 buffer - message_buffer)) {
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

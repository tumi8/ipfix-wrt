#include "export.h"
#include "topology_set.h"
#include "../ipfixlolib/msg.h"

typedef int (*template_declaration_function) (ipfix_exporter *);

struct template_declaration {
    template_declaration_function func;
    uint16_t template_id;
};

/**
  * Declares the base full template. It has the following layout:
  *
  * - sequenceNumber (uint16)
  * - subtemplateList (list of entries)
  */
static int declare_base_full_template(ipfix_exporter *exporter) {
    if (ipfix_start_template(exporter, FULL_BASE_TEMPLATE_ID, 2))
        return -1;

    if (ipfix_put_template_field(exporter, FULL_BASE_TEMPLATE_ID, SequenceNumberType, 2, ENTERPRISE_ID))
        return -1;

    if (ipfix_put_template_field(exporter, FULL_BASE_TEMPLATE_ID, 292, 0xffff, 0)) // subtemplateList
        return -1;

    if (ipfix_end_template(exporter, FULL_BASE_TEMPLATE_ID))
        return -1;

    return 0;
}

/**
  * Declares the host info template for IPv4 hosts. This template is
  * used in the subtemplateList of the base full template.
  *
  * Layout:
  * - gatewayIPv4Address (ipv4Address)
  * - subTemplateList<targetHostIPv4Template>
  *
  */
static int declare_base_host_info4_template(ipfix_exporter *exporter) {
    if (ipfix_start_template(exporter, HOST_INFO_IPV4_TEMPLATE_ID, 2))
        return -1;

    if (ipfix_put_template_field(exporter, HOST_INFO_IPV4_TEMPLATE_ID, GatewayIPv4AddressType, 4, ENTERPRISE_ID))
        return -1;

    if (ipfix_put_template_field(exporter, HOST_INFO_IPV4_TEMPLATE_ID, 292, 0xffff, 0)) // subtemplateList
        return -1;

    if (ipfix_end_template(exporter, HOST_INFO_IPV4_TEMPLATE_ID))
        return -1;

    return 0;
}

static int declare_target_host_ipv4_template(ipfix_exporter *exporter) {
    if (ipfix_start_template(exporter, TARGET_HOST_IPV4_TEMPLATE_ID, 2))
        return -1;

    if (ipfix_put_template_field(exporter, TARGET_HOST_IPV4_TEMPLATE_ID, TargetHostIPv4Type, 4, ENTERPRISE_ID))
        return -1;

    if (ipfix_put_template_field(exporter, TARGET_HOST_IPV4_TEMPLATE_ID, OLSRSequenceNumberType, 2, ENTERPRISE_ID))
        return -1;

    if (ipfix_end_template(exporter, TARGET_HOST_IPV4_TEMPLATE_ID))
        return -1;

    return 0;
}

static int declare_base_host_info6_template(ipfix_exporter *exporter) {
    if (ipfix_start_template(exporter, HOST_INFO_IPV6_TEMPLATE_ID, 2))
        return -1;

    if (ipfix_put_template_field(exporter, HOST_INFO_IPV6_TEMPLATE_ID, GatewayIPv6AddressType, 4, ENTERPRISE_ID))
        return -1;

    if (ipfix_put_template_field(exporter, HOST_INFO_IPV6_TEMPLATE_ID, 292, 0xffff, 0)) // subtemplateList
        return -1;

    if (ipfix_end_template(exporter, HOST_INFO_IPV6_TEMPLATE_ID))
        return -1;

    return 0;
}

static int declare_target_host_ipv6_template(ipfix_exporter *exporter) {
    if (ipfix_start_template(exporter, TARGET_HOST_IPV6_TEMPLATE_ID, 2))
        return -1;

    if (ipfix_put_template_field(exporter, TARGET_HOST_IPV6_TEMPLATE_ID, TargetHostIPv6Type, 16, ENTERPRISE_ID))
        return -1;

    if (ipfix_put_template_field(exporter, TARGET_HOST_IPV6_TEMPLATE_ID, OLSRSequenceNumberType, 2, ENTERPRISE_ID))
        return -1;

    if (ipfix_end_template(exporter, TARGET_HOST_IPV6_TEMPLATE_ID))
        return -1;

    return 0;
}

/**
  * Declares the HNA IPv4 template used by the Host Info IPv4 template.
  *
  * Layout:
  * - hnaIpv4Prefix (ipv4Address)
  * - hnaIpv4PrefixLength (uint8)
  */
static int declare_base_hna4_template(ipfix_exporter *exporter) {
    if (ipfix_start_template(exporter, FULL_HNA4_TEMPLATE_ID, 2))
        return -1;

    if (ipfix_put_template_field(exporter, FULL_HNA4_TEMPLATE_ID, HNAIPv4AddressType, 4, ENTERPRISE_ID))
        return -1;

    if (ipfix_put_template_field(exporter, FULL_HNA4_TEMPLATE_ID, HNAIPv4AddressPrefixLength, 1, ENTERPRISE_ID))
        return -1;

    if (ipfix_end_template(exporter, FULL_HNA4_TEMPLATE_ID))
        return -1;

    return 0;
}

/**
  * Declares the IPFIX templates needed.
  *
  * Returns 0 on success, -1 on failure.
  */
int declare_templates(ipfix_exporter *exporter) {
    struct template_declaration funcs[] = {
        {&declare_base_full_template, FULL_BASE_TEMPLATE_ID},
        {&declare_base_host_info4_template, HOST_INFO_IPV4_TEMPLATE_ID},
        {&declare_base_hna4_template, FULL_HNA4_TEMPLATE_ID},
        {&declare_target_host_ipv4_template, TARGET_HOST_IPV4_TEMPLATE_ID},
        {&declare_base_host_info6_template, HOST_INFO_IPV6_TEMPLATE_ID},
        {&declare_target_host_ipv6_template, TARGET_HOST_IPV6_TEMPLATE_ID},
        {NULL, 0}
    };

    struct template_declaration *func = funcs;

    while (func->func != NULL) {
        if ((*func->func)(exporter)) {
            // Declaration failed - cleanup
            struct template_declaration *func2 = funcs;
            while (func2 != func) {
                ipfix_remove_template(exporter, func2->template_id);
                func2++;
            }
            return -1;
        }

        func++;
    }

    return 0;
}

/**
  * Calculates the length of the given topology set if it is encoded
  * into a subtemplateList. This function supports all network
  * protocols.
  *
  * It DOES NOT include the 3 bytes needed to encode the length
  * of the subtemplateList.
  *
  */
static size_t topology_set_length(const struct topology_set *ts) {
    uint16_t addr_len = ip_addr_len(ts->protocol);
    size_t len = 0;

    // Add subtemplateList header
    len += sizeof(uint8_t) + sizeof(uint16_t);

    struct topology_set_entry *entry = ts->first;
    while (entry != NULL) {
        len += addr_len;
        len += sizeof(entry->seq);

        entry = entry->next;
    }

    return len;
}

/**
  * Builds an IPFix data record encapsulating the host info template.
  *
  * The result is written into the specified buffer (beginning at position 0). After
  * this function has finished buffer points one byte after the end of the record.
  *
  * If the resulting encoding of the host info would exceed buffer_len -1 is returned
  * and nothing is written to the buffer. On success the length of the added record
  * is returned.
  */
static size_t add_host_info(const struct ip_addr_t *addr, const struct topology_set *ts, u_char **buffer, size_t buffer_len) {
    size_t topology_set_len = topology_set_length(ts);
    size_t host_info_len = topology_set_len + 3 * sizeof(uint8_t) + ip_addr_len(addr->protocol);

    if (host_info_len > buffer_len) {
        // Buffer too short to hold this host info record.
        return -1;
    }

    // Add gateway IP address
    pkt_put_ipaddress(buffer, &addr->addr, addr->protocol);

    // Add reachable nodes from gateway:
    // Add subtemplateList header
    pkt_put_u8(buffer, 0xff);
    pkt_put_u16(buffer, topology_set_len);
    pkt_put_u8(buffer, 0x03); // allOf semantic

    switch(addr->protocol) {
    case IPv4:
        pkt_put_u16(buffer, TARGET_HOST_IPV4_TEMPLATE_ID);
        break;
    case IPv6:
        pkt_put_u16(buffer, TARGET_HOST_IPV6_TEMPLATE_ID);
        break;
    default:
        msg(MSG_ERROR, "Unsupported network protocol.");

        return -1;
    }

    // Add topology set entries
    struct topology_set_entry *entry = ts->first;
    while (entry != NULL) {
        pkt_put_ipaddress(buffer, &entry->dest_addr, ts->protocol);
        pkt_put_u16(buffer, entry->seq);

        entry = entry->next;
    }

    return host_info_len;
}

/**
  * Convenience method which adds the given buffer as a data record to a started
  * data set, ends the data set and transmits it.
  *
  * If a failure occurs -1 is returned and the buffer is free'd. Otherwise 0
  * is returned.
  *
  */
static int add_data_record_and_send(ipfix_exporter *exporter, u_char *buffer, size_t buffer_len) {
    if (ipfix_put_data_field(exporter, buffer, buffer_len)) {
        msg(MSG_ERROR, "Failed to add data record.");
        free(buffer);
        return -1;
    }

    if (ipfix_end_data_set(exporter, 1)) {
        msg(MSG_ERROR, "Failed to end data set.");
        free(buffer);
        return -1;
    }

    if (ipfix_send(exporter)) {
        msg(MSG_ERROR, "Failed to send IPFIX message.");
        free(buffer);
        return -1;
    }

    return 0;
}

/**
  * Performs a full export.
  */
void export_full(struct export_parameters *params) {
	ipfix_exporter *exporter = params->exporter;
	khash_t(2) *tc_set = params->tc_set;

    if (tc_set == NULL || exporter == NULL)
		return;

    khiter_t k;

    u_char *buffer = NULL;
    u_char *buffer_end = NULL;
    u_char *buffer_pos = NULL;
    u_char *len_ptr = NULL;
    size_t total_host_info_length;

    for (k = kh_begin(tc_set); k != kh_end(tc_set); ++k) {
        if (!kh_exist(tc_set, k))
            continue;

        struct ip_addr_t addr = kh_key(tc_set, k);
        struct topology_set *ts = kh_value(tc_set, k);

        if (buffer == NULL) {
            if (ipfix_start_data_set(exporter, htons(FULL_BASE_TEMPLATE_ID))) {
                msg(MSG_ERROR, "Failed to start data set.");

				return;
            }

            uint16_t total_space = ipfix_get_remaining_space(exporter);
            buffer = (u_char *) malloc (total_space * sizeof(u_char));

            if (buffer == NULL) {
                msg(MSG_ERROR, "Failed to allocate memory for IPFIX data record.");

                ipfix_cancel_data_set(exporter);
				return;
            }

            buffer_pos = buffer;
            buffer_end = buffer + total_space;
            total_host_info_length = sizeof(uint8_t) + sizeof(uint16_t); // Start with subtemplateList header

            if (total_space < sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint16_t)) {
                msg(MSG_ERROR, "IPFIX remaining space not enough to even add record header.");

                ipfix_cancel_data_set(exporter);
				return;
            }

            pkt_put_u16(&buffer_pos, 0x0); // TODO - Fill sequence number
            pkt_put_u8(&buffer_pos, 0xff); // Record length - indicate that it uses 3 byte encoding
            len_ptr = buffer_pos;
            buffer_pos += sizeof(uint16_t); // The actual record length will be added before transmission
            pkt_put_u8(&buffer_pos, 0x03); // allOf semantics

            switch(addr.protocol) {
            case IPv4:
                pkt_put_u16(&buffer_pos, HOST_INFO_IPV4_TEMPLATE_ID);
                break;
            case IPv6:
                pkt_put_u16(&buffer_pos, HOST_INFO_IPV6_TEMPLATE_ID);
                break;
            default:
                msg(MSG_ERROR, "Unsupported network protocol.");

				return;
            }
        }

        size_t host_info_len = add_host_info(&addr, ts, &buffer_pos, buffer_end - buffer_pos);
        if (host_info_len == -1) {
            // Host info record is too large for remaining buffer - transmit
            // record and try again.

            pkt_put_u16(&len_ptr, (uint16_t) total_host_info_length);

            if (add_data_record_and_send(exporter, buffer, buffer_pos - buffer))
				return;

            buffer = NULL;
            k--;
            continue;
        }

        total_host_info_length += host_info_len;
    }

    if (buffer == NULL)
		return;

    // Write the length of the host info template list
    pkt_put_u16(&len_ptr, (uint16_t) total_host_info_length);

    if (add_data_record_and_send(exporter, buffer, buffer_pos - buffer))
		return;
}




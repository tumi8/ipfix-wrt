#ifndef OLSR_H_
#define OLSR_H_

#include "flows.h"

int olsr_parse_packet(capture_session *session, const struct pcap_pkthdr *const pkthdr, const u_char * data, const u_char *const end_data, const flow_key *const key);

#endif

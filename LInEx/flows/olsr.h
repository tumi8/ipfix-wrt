#ifndef OLSR_H_
#define OLSR_H_

#include "flows.h"

int olsr_parse_packet(capture_session *session, struct pktinfo *pkt, const flow_key *const key);

#endif

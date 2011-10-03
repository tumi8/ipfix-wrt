#ifndef DEFLATE_H_
#define DEFLATE_H_
#include "../ipfixlolib.h"

void ipfix_init_compression_module(const char *params);

int ipfix_compress(ipfix_exporter *exporter);

#endif

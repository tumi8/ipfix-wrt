#ifndef BZIP2_H_
#define BZIP2_H_
#include "../ipfixlolib.h"

void ipfix_init_compression_module(const char *params);

int ipfix_compress(ipfix_exporter *exporter);

#endif

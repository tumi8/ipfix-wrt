/*
 * ipfix_data.h
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */

#ifndef IPFIX_HANDLING_H_
#define IPFIX_HANDLING_H_
#include <stddef.h>
#include <regex.h>
#include "core.h"

/**
 * Takes the parsed content of a config file and tries to send every record that is
 * described in this config file using IPFIX.
 */
void config_to_ipfix(ipfix_exporter* exporter,config_file_descriptor* config);

#endif /* IPFIX_DATA_H_ */

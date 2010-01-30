/*
 * ipfix_templates.h
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */

#ifndef IPFIX_TEMPLATES_H_
#define IPFIX_TEMPLATES_H_

/**
 * Generates all templates of all records/multirecords stored in the handed config file descriptor <conf>.
 */
void generate_templates_from_config(ipfix_exporter* send_exporter, config_file_descriptor* conf);

#endif /* IPFIX_TEMPLATES_H_ */
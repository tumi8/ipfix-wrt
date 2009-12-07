/*
 * config_file.h
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#ifndef CONFIG_FILE_H_
#define CONFIG_FILE_H_

#include "core.h"
#include "list.h"

#define SOURCE_TYPE_FILE 0
#define SOURCE_TYPE_COMMAND 1

typedef struct src_d {
	char* source_path;
	char* reg_exp;
	int rule_count;
	int source_type;
	list* rules;
} source_descriptor;


typedef struct rec_d{
	list* sources;
	boolean is_multirecord;
} record_descriptor;

typedef struct{
	list* record_descriptors;
} config_file_descriptor;

config_file_descriptor* read_config(char* filename);

#endif /* CONFIG_FILE_H_ */

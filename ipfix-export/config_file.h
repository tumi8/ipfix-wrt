/*
 * config_file.h
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#ifndef CONFIG_FILE_H_
#define CONFIG_FILE_H_

#include "core.h"

typedef struct {
	char* proc_file;
	char* reg_exp;
	transform_rule* rules;
	int rule_count;
} proc_file_descriptor;

#endif /* CONFIG_FILE_H_ */

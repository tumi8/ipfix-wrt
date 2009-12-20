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


config_file_descriptor* read_config(char* filename);

//debug function, echos the whole config tree
void echo_config_file(config_file_descriptor* conf);

#endif /* CONFIG_FILE_H_ */

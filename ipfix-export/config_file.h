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


/**
 * Parses a config file and returns its content in a treelike structure
 * <filename> The path to the file.
 */
config_file_descriptor* read_config(char* filename);

//debug function, echos the whole config tree
void echo_config_file(config_file_descriptor* conf);

/**
 * Extracts the content of the capturing group <match> from the <input>
 * and returns it as a string.
 */
unsigned int extract_int_from_regmatch(regmatch_t* match, char* input);

/**
 * Extracts the content of a capturing group <match> from the <input>
 * and returns it as an unsigned int.
 */
char* extract_string_from_regmatch(regmatch_t* match, char* input);

#endif /* CONFIG_FILE_H_ */

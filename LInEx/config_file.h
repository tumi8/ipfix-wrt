/*
 * LInEx - Lightweight Information Export
 * Copyright (C) 2010 Vermont Project (http://vermont.berlios.de)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

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

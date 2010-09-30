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
 * core.h
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#ifndef CORE_H_
#define CORE_H_
#include <stdio.h>
#include <stdlib.h>
#include "ipfixlolib/ipfixlolib.h"
#include "ipfixlolib/ipfix.h"
#include <unistd.h>
#include <string.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "list.h"

/*
 * The size of the sendbuffer in bytes
 */
#define SEND_BUFFER_SIZE 2048

//How many bytes an input source may be (for example, the maximum length of a proc file)
#define INPUT_BUFFER_SIZE 4096

// How many capturing groups (rules) may be in one regexp pattern in the config
#define MATCH_BUFFER_SIZE 40

// How long a line in the config file may be
#define MAX_CONF_LINE_LENGTH 512


//The standard interval for sending datasets (in seconds)
#define STANDARD_SEND_INTERVAL 30

//The standard observation domain id of the exporter
#define OBSERVATION_DOMAIN_STANDARD_ID 1

//** The different source types **
#define SOURCE_TYPE_FILE 0 		//A file
#define SOURCE_TYPE_COMMAND 1	//A shell command

/**
 * The standard verbosity, possible values:
 * 0 : show nothing, only init stuff
 * 1 : show whenever an export is made
 * 2 : show information about each source that is read
 * 3 : show even more detailed information, i.e. the result of each transform rule
 * 4 : show everything, even the content of all sources read (generates really a lot of text!)
 */
#define STANDARD_VERBOSE_LEVEL 1


/**
 * bool, since C doesn't have it :(
 */
typedef int boolean;

/**
 * A descriptor for a config file, containing a list of records
 */
typedef struct{
	list* record_descriptors;
	list* collectors;
	int interval;
	uint32_t observation_domain_id;
	int verbose;
} config_file_descriptor;

/**
 * A descriptor for a collector in a config file, i.e. its IP and port
 */
typedef struct{
	char* ip;
	uint16_t port;
} collector_descriptor;


/**
 * A descriptor for one record which becomes one
 * ipfix template and contains a list of sources
 * to gather data from.
 */
typedef struct rec_d{
	list* sources;
	uint16_t template_id;
	int is_multirecord;
} record_descriptor;


/*
 * A descriptor for one source to read data from.
 * It contains the path and the type of the source
 * to read the data and a list of transformation rules
 * and the pattern to extract the fields from the data read.
 */
typedef struct src_d {
	char* source_path;
	char* reg_exp;
	regex_t reg_exp_compiled;
	int rule_count;
	int source_type; // 0 or 1
	list* rules;
} source_descriptor;


/*
 * The rule struct describes a rule to transform the content of a capturing group:
 *
 * The <bytecount> denotes how much bytes the data will have after transformation. Also needed for IPFIX
 * The <transform_id> is the index of the transform function used to transform the string input to the desired format
 * The <transform_func> is a pointer to the transform function to be used.
 * It can be obtained by calling get_rule_by_index(transform_id), it is just stored reduntantly here for performance improvements
 *
 * The <ie_id> and the <enterprise_id> are the IPFIX information id and the enterprise
 * id to be used for this data element, respectively.
 */
typedef struct tr_rule {
	uint16_t bytecount;
	int transform_id;
	void (*transform_func)(char* input,void* target_buffer, struct tr_rule* rule);
	uint16_t ie_id;
	uint32_t enterprise_id;
} transform_rule;

/**
 * Signature of a transform function which handles the transformation
 * of input data into desired formats
 */
typedef void (*transform_func) (char* input,void* target_buffer, struct tr_rule* rule);







#endif /* CORE_H_ */

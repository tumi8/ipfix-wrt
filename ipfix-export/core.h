/*
 * core.h
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#ifndef CORE_H_
#define CORE_H_
#include <stdio.h>
#include "ipfixlolib/ipfixlolib.h"
#include "ipfixlolib/ipfix.h"
#include "ipfixlolib/msg.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "list.h"

/*
 * The size of the sendbuffer in bytes
 * Since one record is stored in the sendbuffer
 * this puts a limit to the amount of data retrieved from one record
 */
#define SEND_BUFFER_SIZE 2048

//How many bytes an input source may be (for example, the maximum length of a proc file)
#define INPUT_BUFFER_SIZE 4096

// How many capturing groups (rules) may be in one regexp pattern in the config
#define MATCH_BUFFER_SIZE 40

// How long a line in the config file may be
#define MAX_CONF_LINE_LENGTH 512

//The source id of the exporter
#define MY_SOURCE_ID 70539

//** The different source types **
#define SOURCE_TYPE_FILE 0 		//A file
#define SOURCE_TYPE_COMMAND 1	//A shell command

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
	int source_type;
	list* rules;
} source_descriptor;


/**
 * A descriptor for one record which becomes one
 * ipfix template and contains a list of sources
 * to gather data from.
 */
typedef struct rec_d{
	list* sources;
	int template_id;
	int is_multirecord;
} record_descriptor;

/**
 * A descriptor for a config file, containing a list of records
 */
typedef struct{
	list* record_descriptors;
} config_file_descriptor;


/*
 * Das zentrale rule struct beschreibt die Regel zur Umwandlung einer Capturing
 * Group:
 * Der bytecount gibt an wieviel byte der wert nach der konvertierung im sendbuffer belegen wird
 * transform muss eine funktion sein, die die eingabe (char*) und den sendbuffer (void*)
 * erhält, die eingabe geeignet konvertiert (z.B. in int umwandeln, networkbyteorder konvertierungen usw)
 * und dann in den übergebenen buffer schreibt.
 *
 * Dabei ist zu beachten, dass die funktion nicht mehr bytes schreiben sollte, als
 * im bytecount angegeben sind.
 */
typedef struct tr_rule {
	uint16_t bytecount;
	void (*transform)(char* input,void* target_buffer, struct tr_rule* rule);
	uint16_t ie_id;
	uint32_t enterprise_id;
} transform_rule;

/**
 * Signature of a transform function which handles the transformation
 * of input data into desired formats
 */
typedef void (*transform_func) (char* input,void* target_buffer, struct tr_rule* rule);

/**
 * bool, since C doesn't have it :(
 */
typedef int boolean;





#endif /* CORE_H_ */

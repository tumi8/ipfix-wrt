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
 * config_file.c
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#include "config_file.h"
#include "transform_rules.h"
#include "core.h"
#include "list.h"

#define PARSE_MODE_MAIN 0
#define PARSE_MODE_SOURCE_DESCR 1
#define PARSE_MODE_RULE 2
#define PARSE_MODE_SOURCE_OR_MAIN 3
#define PARSE_MODE_XML_SOURCE_DESCR 4
#define PARSE_MODE_XML_RULE 5
#define PARSE_MODE_XML_SOURCE_OR_MAIN 6

int config_regex_inited = 0;
int num_rule_lines = 0;
int number_of_proc_file = 0;
int parse_mode = PARSE_MODE_MAIN;
int current_default_template_id = 256;
regex_t regex_empty_line;
regex_t regex_comment;
regex_t regex_record_selector;
regex_t regex_source_selector;
regex_t regex_source_suffix;
regex_t regex_rule;
regex_t regex_collector;
regex_t regex_interval;
regex_t regex_interface;
regex_t regex_compression;
regex_t regex_flow_params;
regex_t regex_flow_sampling;
regex_t regex_anonymization;
regex_t regex_export_flow_interval;
regex_t regex_export_olsr_interval;
regex_t regex_dtls;
regex_t regex_odid;
regex_t regex_xmlfile;
regex_t regex_xmlpostprocessing;
regex_t regex_xmlrecord_selector;
regex_t regex_xml_rule;
config_file_descriptor* current_config_file = NULL;
record_descriptor* current_record = NULL;
source_descriptor* current_source = NULL;
xmlrecord_descriptor* current_xmlrecord = NULL;
regmatch_t config_buffer[10];

//Constructor for config file descriptor
config_file_descriptor* create_config_file_descriptor(){
	current_config_file = (config_file_descriptor*) malloc(sizeof(config_file_descriptor));
	current_config_file->record_descriptors = list_create();
	current_config_file->xmlrecord_descriptors = list_create();
	current_config_file->collectors = list_create();
	current_config_file->verbose = STANDARD_VERBOSE_LEVEL;
	current_config_file->interval = STANDARD_SEND_INTERVAL;
	current_config_file->interfaces = list_create();
	current_config_file->compression_method = NULL;
	current_config_file->compression_method_params = NULL;
	current_config_file->flow_inactive_timeout = 15;
	current_config_file->flow_active_timeout = 120;
	current_config_file->flow_object_cache_size = 64;
	current_config_file->flow_sampling_mode = NullSamplingMode;
	current_config_file->flow_sampling_polynom = 0;
	current_config_file->flow_sampling_max_value = 0;
#ifdef SUPPORT_ANONYMIZATION
	current_config_file->anonymization_enabled = 0;
	memset(current_config_file->anonymization_key, 0, sizeof(current_config_file->anonymization_key));
	memset(current_config_file->anonymization_pad, 0, sizeof(current_config_file->anonymization_pad));
#endif
#ifdef SUPPORT_DTLS
	current_config_file->certificate = NULL;
	current_config_file->certificate_key = NULL;
	current_config_file->ca = NULL;
	current_config_file->ca_path = NULL;
#endif
	current_config_file->export_flow_interval = 60000;
	current_config_file->export_olsr_interval = 120000;
	current_config_file->observation_domain_id = OBSERVATION_DOMAIN_STANDARD_ID;
	current_config_file->xmlfile = NULL;
	current_config_file->xmlpostprocessing = NULL;
	return current_config_file;
}


//Constructor for collector descriptor
collector_descriptor* create_collector_descriptor(char* ip, int port,
												  enum ipfix_transport_protocol transport_protocol,
												  char *fqdn){
	collector_descriptor* result = (collector_descriptor*) malloc(sizeof(collector_descriptor));
	result->ip = ip;
	result->port = port;
	result->transport_protocol = transport_protocol;
#ifdef SUPPORT_DTLS
	result->fqdn = fqdn;
#endif
	list_insert(current_config_file->collectors, result);
	return result;
}

//Constructor for record descriptor
record_descriptor* create_record_descriptor(){
	current_record = (record_descriptor*) malloc(sizeof(record_descriptor));
	current_record->sources = list_create();
	current_record->template_id = current_default_template_id++;
	list_insert(current_config_file->record_descriptors, current_record);
	return current_record;
}

//Constructor for source_descriptor
source_descriptor* create_source_descriptor(){
	current_source = (source_descriptor*) malloc(sizeof(source_descriptor));
	current_source->rules = list_create();
	switch (parse_mode) {
		case PARSE_MODE_SOURCE_DESCR:
		case PARSE_MODE_SOURCE_OR_MAIN:
			list_insert(current_record->sources,current_source);
			break;
		case PARSE_MODE_XML_SOURCE_DESCR:
		case PARSE_MODE_XML_SOURCE_OR_MAIN:
			list_insert(current_xmlrecord->sources,current_source);
			break;
		default:
			THROWEXCEPTION("parse_mode %i in create_source_descriptor, this should never happen", parse_mode);
	}

	return current_source;
}

//Constructor for xmlrecord descriptor
xmlrecord_descriptor* create_xmlrecord_descriptor(){
	current_xmlrecord = (xmlrecord_descriptor*) malloc(sizeof(xmlrecord_descriptor));
	current_xmlrecord->sources = list_create();
	current_xmlrecord->name = NULL;
	list_insert(current_config_file->xmlrecord_descriptors, current_xmlrecord);
	return current_xmlrecord;
}

//Constructor for rule
transform_rule* create_transform_rule(){
	transform_rule* tr = (transform_rule*) malloc(sizeof(transform_rule));;
	list_insert(current_source->rules,tr);
	return tr;
}

/**
 * Inits the regular expressions needed for config parsing.
 */
void init_config_regex(){
	// Regex on OpenWRT does not support predefined character classes such as
	// \s or \w.
	regcomp(&regex_comment,"^[ \t]*\\#.*$",REG_EXTENDED);
	regcomp(&regex_empty_line,"^[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_record_selector,"^[ \t]*(RECORD|MULTIRECORD)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_source_selector,"^[ \t]*(FILE|COMMAND).*$",REG_EXTENDED);
	regcomp(&regex_source_suffix,"^[ \t]*([A-Za-z0-9/_-]+|\"([^\"]*)\")[ \t]*,[ \t]*([0-9]+)[ \t]*,[ \t]*\"(.*)\"[ \t\n]*",REG_EXTENDED);
	regcomp(&regex_rule,"^[ \t]*([0-9]+)[ \t]*,[ \t]*([0-9]+)[ \t]*,[ \t]*([0-9]+)[ \t]*,[ \t]*([0-9]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_collector,"^[ \t]*COLLECTOR[ \t]+([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})[ \t]*\\:[ \t]*([0-9]{1,5})([ \t]+(TCP|UDP|SCTP|DTLS_OVER_UDP|DTLS_OVER_SCTP))?([ \t]+([^ \t\n\r]+))?[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_interval,"^[ \t]*INTERVAL[ \t]+([0-9]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_interface,"^[ \t]*INTERFACE[ \t]+([A-Za-z0-9.-]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_compression,"^[ \t]*COMPRESSION[ \t]+([A-Za-z0-9.-]+)([ \t]+(.+))?[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_flow_params, "^[ \t]*FLOW_PARAMS[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_flow_sampling, "^[ \t]*FLOW_SAMPLING[ \t]+(CRC32|BPF)[ \t]+([0-9]+)[ \t]*(0x[0-9a-fA-F]+|[0-9]+)?[ \t\n]*$", REG_EXTENDED);
#ifdef SUPPORT_ANONYMIZATION
	regcomp(&regex_anonymization,"^[ \t]*ANONYMIZATION[ \t]+([A-Fa-f0-9]+)[ \t]+([A-Fa-f0-9]+)[ \t\n]*$", REG_EXTENDED);
#endif
	regcomp(&regex_export_flow_interval, "^[ \t]*EXPORT_FLOW_INTERVAL[ \t]+([0-9]+)", REG_EXTENDED);
	regcomp(&regex_export_olsr_interval, "^[ \t]*EXPORT_OLSR_INTERVAL[ \t]+([0-9]+)", REG_EXTENDED);
#ifdef SUPPORT_DTLS
	regcomp(&regex_dtls, "^[ \t]*DTLS[ \t]+([^ ]+)[ \t]+([^ ]+)[ \t]+([^ ]+)[ \t]+([^ ]+)[ \t\n]*$", REG_EXTENDED);
#endif
	regcomp(&regex_odid,"^[ \t]*ODID[ \t]+([0-9]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_xmlfile,"^[ \t]*XMLFILE[ \t]+\"([^\"]+)\"[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_xmlpostprocessing,"^[ \t]*XMLPOSTPROCESSING[ \t]+\"([^\"]+)\"[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_xmlrecord_selector,"^[ \t]*XMLRECORD[ \t]+([A-Za-z0-9/_-]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_xml_rule,"^[ \t]*([A-Za-z0-9/_-]+)[ \t\n]*$",REG_EXTENDED);
	config_regex_inited = 1;
}

void deinit_config_regex() {
	regfree(&regex_comment);
	regfree(&regex_empty_line);
	regfree(&regex_record_selector);
	regfree(&regex_source_selector);
	regfree(&regex_source_suffix);
	regfree(&regex_rule);
	regfree(&regex_collector);
	regfree(&regex_interval);
	regfree(&regex_interface);
	regfree(&regex_compression);
	regfree(&regex_flow_params);
	regfree(&regex_flow_sampling);
#ifdef SUPPORT_ANONYMIZATION
	regfree(&regex_anonymization);
#endif
	regfree(&regex_export_flow_interval);
	regfree(&regex_export_olsr_interval);
#ifdef SUPPORT_DTLS
	regfree(&regex_dtls);
#endif
	regfree(&regex_odid);
	regfree(&regex_xmlfile);
	regfree(&regex_xmlpostprocessing);
	regfree(&regex_xmlrecord_selector);
	regfree(&regex_xml_rule);

	config_regex_inited = 0;
}

/**
 * Extracts the content of the capturing group <match> from the <input>
 * and returns it as a string.
 */
char* extract_string_from_regmatch(regmatch_t* match, char* input){
	int length = (match->rm_eo-match->rm_so);
	char* output = (char*)malloc(sizeof(char)*(length+1));
	memcpy(output,&input[match->rm_so],length);
	output[length] = '\0';
	return output;
}

/**
 * Extracts the content of a capturing group <match> from the <input>
 * and returns it as an unsigned int.
 */
unsigned int extract_uint_from_regmatch(regmatch_t* match, char* input){
	//Null terminate
	char swap = input[match->rm_eo];
	unsigned int result;
	input[match->rm_eo] = '\0';
	result = strtoul(&input[match->rm_so], NULL, 10);
	input[match->rm_eo] = swap;
	return result;
}

/**
 * Processes a rule line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_rule_line(char* line, int in_line){

	if(regexec(&regex_rule,line,5,config_buffer,0)){
		THROWEXCEPTION("Malformed line (line %d)!\nExpecting rule line, but found this line:\n%s", in_line,line);
	}
	int transform_id = extract_uint_from_regmatch(&config_buffer[2],line);
	transform_rule* tr = create_transform_rule();
	tr->bytecount = (uint16_t)extract_uint_from_regmatch(&config_buffer[1],line);
	tr->transform_func = get_rule_by_index(transform_id, tr->bytecount);
	tr->transform_id = transform_id;
	tr->ie_id = extract_uint_from_regmatch(&config_buffer[3],line);
	tr->enterprise_id = extract_uint_from_regmatch(&config_buffer[4],line);

	//decrease number of rule lines to parse.
	//If no more rule lines are to be parsed, the parsers expects
	//a new source descriptor or record descriptor in the next line
	num_rule_lines--;
	if(num_rule_lines<=0){
		parse_mode = PARSE_MODE_SOURCE_OR_MAIN;
	}

	return 1;

}

/**
 * Processes a source line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_source_line(char* line, int in_line){

	if(regexec(&regex_source_selector,line,2,config_buffer,0)){
		THROWEXCEPTION("Line %d in config file is malformed!\nParser expects a rule line that starts with a source type descriptor (e.g. \"FILE:\")\nThis line was found:\n%s",in_line,line);
	}

	//Multirecords may NOT contain more than one source
	if ((parse_mode == PARSE_MODE_SOURCE_OR_MAIN) && current_record->is_multirecord && (current_record->sources->size > 1)) {
		THROWEXCEPTION("Found a multirecord with more than one source! Multirecords may only contain one source!");
	}
	//Create new source descriptor
	create_source_descriptor();

	line[config_buffer[1].rm_eo]='\0'; //0 terminate

	if(!strcasecmp(&line[config_buffer[1].rm_so],"FILE")){
		current_source->source_type = SOURCE_TYPE_FILE;
	} else if(!strcasecmp(&line[config_buffer[1].rm_so],"COMMAND")){
		current_source->source_type = SOURCE_TYPE_COMMAND;
	} else {
		THROWEXCEPTION("Unrecognized type selector \"%s\" in line %d",&line[config_buffer[1].rm_so],in_line);
	}

	//store line with config data in dataline
	char* dataline = &line[config_buffer[1].rm_eo+1];
	if(regexec(&regex_source_suffix,dataline,5,config_buffer,0)){
		THROWEXCEPTION("Unrecognized config line (Line %d):\n%s",in_line,dataline);
	}

	//Check which capturing group to use for source index, if the 2nd exists use this one
	int path_index = 1;
	if(config_buffer[2].rm_so!=-1) path_index = 2;

	//extract file name
	current_source->source_path = extract_string_from_regmatch(&config_buffer[path_index],dataline);

	//extract rule count
	current_source->rule_count = extract_uint_from_regmatch(&config_buffer[3],dataline);

	//extract pattern
	current_source->reg_exp = extract_string_from_regmatch(&config_buffer[4],dataline);

	//compile pattern
	regcomp(&(current_source->reg_exp_compiled),current_source->reg_exp,REG_EXTENDED);

	//Set num_rule_lines so the next lines get parsed as rule lines
	num_rule_lines = current_source->rule_count;


	//fprintf(stderr,"Found proc line:\nFile Name: %s\nRule count: %d\nPattern: <%s>\n",current_source->source_path,current_source->rule_count,current_source->reg_exp);
	number_of_proc_file++;

	//Go into rule mode
	switch (parse_mode) {
		case PARSE_MODE_SOURCE_DESCR:
		case PARSE_MODE_SOURCE_OR_MAIN:
			parse_mode = PARSE_MODE_RULE;
			break;
		case PARSE_MODE_XML_SOURCE_DESCR:
		case PARSE_MODE_XML_SOURCE_OR_MAIN:
			parse_mode = PARSE_MODE_XML_RULE;
			break;
		default:
			THROWEXCEPTION("parse_mode %i in process_source_line, this should never happen", parse_mode);
	}

	return 1;
}

/**
 * Processes a record line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_record_line(char* line, int in_line){

	if(regexec(&regex_record_selector,line,2,config_buffer,0)){
		THROWEXCEPTION("Record line %d in config file is malformed (not starting with a record type selector):\n%s",in_line,line);
	}

	//Create new record descriptor
	create_record_descriptor();

	line[config_buffer[1].rm_eo]='\0'; //0 terminieren

	if(!strcasecmp(&line[config_buffer[1].rm_so],"RECORD")){
		current_record->is_multirecord = 0;

	} else if(!strcasecmp(&line[config_buffer[1].rm_so],"MULTIRECORD")) {
		current_record->is_multirecord = 1;
	} else {
		THROWEXCEPTION("Unrecognized record type selector \"%s\" in line %d",&line[config_buffer[1].rm_so],in_line);
	}

	parse_mode = PARSE_MODE_SOURCE_DESCR;
	return 1;
}

/**
 * Processes a collector line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_collector_line(char* line, int in_line){
	if(regexec(&regex_collector,line,7,config_buffer,0)){
		THROWEXCEPTION("COLLECTOR line %d in config file is malformed:\n%s",in_line,line);
	}

	char* ip = extract_string_from_regmatch(&config_buffer[1],line);
	int port = extract_uint_from_regmatch(&config_buffer[2],line);
	char* transport_protocol_str = extract_string_from_regmatch(&config_buffer[4], line);
	char *fqdn = extract_string_from_regmatch(&config_buffer[6], line);
	enum ipfix_transport_protocol transport_protocol = UDP;

	if (!strcmp(transport_protocol_str, "TCP")) {
		transport_protocol = TCP;
	} else if (!strcmp(transport_protocol_str, "SCTP")) {
		transport_protocol = SCTP;
	} else if (!strcmp(transport_protocol_str, "UDP")) {
		transport_protocol = UDP;
	} else if (!strcmp(transport_protocol_str, "DTLS_OVER_UDP")) {
		transport_protocol = DTLS_OVER_UDP;
	} else if (!strcmp(transport_protocol_str, "DTLS_OVER_SCTP")) {
		transport_protocol = DTLS_OVER_SCTP;
	}

	create_collector_descriptor(ip,port,transport_protocol, fqdn);
	return 1;
}

/**
 * Processes a export interval line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_interval_line(char* line, int in_line){
	if(regexec(&regex_interval,line,2,config_buffer,0)){
		THROWEXCEPTION("INTERVAL line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->interval = extract_uint_from_regmatch(&config_buffer[1],line);
	return 1;
}

/**
 * Processes the interface line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_interface_line(char* line, int in_line){
	if(regexec(&regex_interface,line,2,config_buffer,0)){
		THROWEXCEPTION("INTERFACE line %d in config file is malformed:\n%s",in_line,line);
	}

	list_insert(current_config_file->interfaces, extract_string_from_regmatch(&config_buffer[1], line));

	return 1;
}

/**
 * Processes the compression line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_compression_line(char* line, int in_line){
	if(regexec(&regex_compression,line,4,config_buffer,0)){
		THROWEXCEPTION("COMPRESSION line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->compression_method = extract_string_from_regmatch(&config_buffer[1], line);
	current_config_file->compression_method_params = extract_string_from_regmatch(&config_buffer[3], line);

	return 1;
}

/**
 * Processes the flow params line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_flow_params_line(char* line, int in_line){
	if(regexec(&regex_flow_params,line,4,config_buffer,0)){
		THROWEXCEPTION("FLOW_PARAMS line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->flow_inactive_timeout = extract_uint_from_regmatch(&config_buffer[1], line);
	current_config_file->flow_active_timeout = extract_uint_from_regmatch(&config_buffer[2], line);
	current_config_file->flow_object_cache_size = extract_uint_from_regmatch(&config_buffer[3], line);

	return 1;
}

/**
 * Processes the flow sampling line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_flow_sampling_line(char* line, int in_line){
	if(regexec(&regex_flow_sampling,line,4,config_buffer,0)){
		THROWEXCEPTION("FLOW_SAMPLING line %d in config file is malformed:\n%s",in_line,line);
	}

	char *mode = extract_string_from_regmatch(&config_buffer[1], line);

	if (strcmp(mode, "CRC32") == 0) {
		current_config_file->flow_sampling_mode = CRC32SamplingMode;

		char *crc_polynom = extract_string_from_regmatch(&config_buffer[3], line);
		if (strncmp(crc_polynom, "0x", 2) == 0) {
			current_config_file->flow_sampling_polynom = strtoul(crc_polynom, NULL, 16);
		} else {
			current_config_file->flow_sampling_polynom = strtoul(crc_polynom, NULL, 10);
		}

	} else if (strcmp(mode, "BPF") == 0) {
		current_config_file->flow_sampling_mode = BPFSamplingMode;
	}

	current_config_file->flow_sampling_max_value = extract_uint_from_regmatch(&config_buffer[2], line);

	return 1;
}

#ifdef SUPPORT_ANONYMIZATION
void read_hex_string(char *input, uint8_t *dst, size_t dst_len) {
	char *c = input + strlen(input);
	size_t pos = dst_len - 1;
	uint8_t msb = 0;

	while (c != input && pos >= 0) {
		*c = 0;
		c--;

		unsigned int val = strtoull(c, NULL, 16);
		if (msb)
			val <<= 4;

		dst[pos] |= val;

		if (msb) {
			pos--;
			msb = 0;
		} else {
			msb = 1;
		}
	}
}

/**
 * Processes the anonymization line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_anonymization_line(char* line, int in_line){
	if(regexec(&regex_anonymization,line,3,config_buffer,0)){
		THROWEXCEPTION("ANONYMIZATION line %d in config file is malformed:\n%s",in_line,line);
	}

	char *key = extract_string_from_regmatch(&config_buffer[1], line);
	char *pad = extract_string_from_regmatch(&config_buffer[2], line);

	read_hex_string(key, current_config_file->anonymization_key,
					sizeof(current_config_file->anonymization_key));
	read_hex_string(pad, current_config_file->anonymization_pad,
					sizeof(current_config_file->anonymization_pad));

	free(key);
	free(pad);

	current_config_file->anonymization_enabled = 1;

	return 1;
}
#endif

/**
 * Processes the export_flow_interval line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_export_flow_interval_line(char* line, int in_line){
	if(regexec(&regex_export_flow_interval,line,2,config_buffer,0)){
		THROWEXCEPTION("EXPORT_FLOW_INTERVAL line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->export_flow_interval = extract_uint_from_regmatch(&config_buffer[1], line) * 1000;

	return 1;
}

/**
 * Processes the export_olsr_interval line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_export_olsr_interval_line(char* line, int in_line){
	if(regexec(&regex_export_olsr_interval,line,2,config_buffer,0)){
		THROWEXCEPTION("EXPORT_OLSR_INTERVAL line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->export_olsr_interval = extract_uint_from_regmatch(&config_buffer[1], line) * 1000;

	return 1;
}

/**
 * Processes the interface line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_dtls_line(char* line, int in_line){
	if(regexec(&regex_dtls,line,5,config_buffer,0)){
		THROWEXCEPTION("DTLS line %d in config file is malformed:\n%s",in_line,line);
	}
#ifdef SUPPORT_DTLS
	current_config_file->certificate = extract_string_from_regmatch(&config_buffer[1], line);
	current_config_file->certificate_key = extract_string_from_regmatch(&config_buffer[2], line);
	current_config_file->ca = extract_string_from_regmatch(&config_buffer[3], line);
	current_config_file->ca_path = extract_string_from_regmatch(&config_buffer[4], line);
#endif
	return 1;
}

/**
 * Processes an observation domain ID line (source ID line) in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_odid_line(char* line, int in_line){
	if(regexec(&regex_odid,line,2,config_buffer,0)){
		THROWEXCEPTION("ODID line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->observation_domain_id = extract_uint_from_regmatch(&config_buffer[1],line);
	return 1;
}

/**
 * Processes an XML filename line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_xmlfile_line(char* line, int in_line){
	if(regexec(&regex_xmlfile,line,2,config_buffer,0)){
		THROWEXCEPTION("XMLFILE line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->xmlfile = extract_string_from_regmatch(&config_buffer[1],line);
	return 1;
}

/**
 * Processes an XML postprocessing line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_xmlpostprocessing_line(char* line, int in_line){
	if(regexec(&regex_xmlpostprocessing,line,2,config_buffer,0)){
		THROWEXCEPTION("XMLPOSTPROCESSING line %d in config file is malformed:\n%s",in_line,line);
	}

	current_config_file->xmlpostprocessing = extract_string_from_regmatch(&config_buffer[1],line);
	return 1;
}

/**
 * Processes a record line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_xmlrecord_line(char* line, int in_line){

	if(regexec(&regex_xmlrecord_selector,line,2,config_buffer,0)){
		THROWEXCEPTION("XMLRECORD line %d in config file is malformed (not starting with the XMLRECORD selector):\n%s",in_line,line);
	}

	//Create new record descriptor
	create_xmlrecord_descriptor();
	current_xmlrecord->name = extract_string_from_regmatch(&config_buffer[1], line);

	parse_mode = PARSE_MODE_XML_SOURCE_DESCR;
	return 1;
}

/**
 * Processes an XML rule line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_xml_rule_line(char* line, int in_line){

	if(regexec(&regex_xml_rule,line,2,config_buffer,0)){
		THROWEXCEPTION("Malformed line (line %d)!\nExpecting XML rule line, but found this line:\n%s", in_line,line);
	}

	line[config_buffer[1].rm_eo]='\0'; //0 terminieren
	char* name = extract_string_from_regmatch(&config_buffer[1], line);
	list_insert(current_source->rules, name);

	//decrease number of rule lines to parse.
	//If no more rule lines are to be parsed, the parsers expects
	//a new source descriptor or record descriptor in the next line
	num_rule_lines--;
	if(num_rule_lines<=0){
		parse_mode = PARSE_MODE_XML_SOURCE_OR_MAIN;
	}

	return 1;

}

/**
 * The main parsing function. Gets a line and decides which type of line this is
 * and give an error if this type of line may not be in this position.
 * If it may be there, then the appropriate process_xxx_line function is called.
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_config_line(char* line, int in_line){
	//Skip empty lines
	if(!regexec(&regex_empty_line,line,2,config_buffer,0)){
		return 0;
	}

	//Skip comments
	if(!regexec(&regex_comment,line,2,config_buffer,0)){
		return 0;

	}

	switch(parse_mode){
		case PARSE_MODE_MAIN:
			if(!regexec(&regex_collector,line,3,config_buffer,0)){
				process_collector_line(line, in_line);
			} else if(!regexec(&regex_record_selector,line,2,config_buffer,0)) {
				process_record_line(line, in_line);
			} else if(!regexec(&regex_interval,line,2,config_buffer,0)) {
				process_interval_line(line, in_line);
			} else if(!regexec(&regex_compression,line,2,config_buffer,0)) {
				process_compression_line(line, in_line);
			} else if(!regexec(&regex_flow_params,line,4,config_buffer,0)) {
				process_flow_params_line(line, in_line);
			} else if(!regexec(&regex_flow_sampling,line,4,config_buffer,0)) {
				process_flow_sampling_line(line, in_line);
			} else if(!regexec(&regex_interface,line,2,config_buffer,0)) {
				process_interface_line(line, in_line);
#ifdef SUPPORT_ANONYMIZATION
			} else if (!regexec(&regex_anonymization,line,2,config_buffer,0)) {
				process_anonymization_line(line, in_line);
#endif
			} else if (!regexec(&regex_export_flow_interval, line, 2, config_buffer, 0)) {
				process_export_flow_interval_line(line, in_line);
			} else if (!regexec(&regex_export_olsr_interval, line, 2, config_buffer, 0)) {
				process_export_olsr_interval_line(line, in_line);
#ifdef SUPPORT_DTLS
			} else if (!regexec(&regex_dtls, line, 5, config_buffer, 0)) {
				process_dtls_line(line, in_line);
#endif
			} else if(!regexec(&regex_odid,line,2,config_buffer,0)) {
				process_odid_line(line, in_line);
			} else if(!regexec(&regex_xmlrecord_selector,line,2,config_buffer,0)) {
				process_xmlrecord_line(line, in_line);
			} else if(!regexec(&regex_xmlfile,line,2,config_buffer,0)) {
				process_xmlfile_line(line, in_line);
			} else if(!regexec(&regex_xmlpostprocessing,line,2,config_buffer,0)) {
				process_xmlpostprocessing_line(line, in_line);
			} else {
				THROWEXCEPTION("Line %d is malformed (expecting record descriptor, interval descriptor, or collector descriptor):\n%s",in_line,line);
			}
			break;
		case PARSE_MODE_SOURCE_DESCR:
		case PARSE_MODE_XML_SOURCE_DESCR:
			process_source_line(line, in_line);
			break;
		case PARSE_MODE_RULE:
			process_rule_line(line, in_line);
			break;
		case PARSE_MODE_XML_RULE:
			process_xml_rule_line(line, in_line);
			break;
		case PARSE_MODE_SOURCE_OR_MAIN:
		case PARSE_MODE_XML_SOURCE_OR_MAIN:
			if(!regexec(&regex_collector,line,3,config_buffer,0)){
				process_collector_line(line, in_line);
			} else if(!regexec(&regex_record_selector,line,2,config_buffer,0)){
				process_record_line(line, in_line);
			} else if(!regexec(&regex_source_selector,line,2,config_buffer,0)){
				process_source_line(line, in_line);
			} else if(!regexec(&regex_interval,line,2,config_buffer,0)) {
				process_interval_line(line, in_line);
			} else if(!regexec(&regex_odid,line,2,config_buffer,0)) {
				process_odid_line(line, in_line);
			} else if(!regexec(&regex_xmlrecord_selector,line,2,config_buffer,0)) {
				process_xmlrecord_line(line, in_line);
			} else if(!regexec(&regex_xmlfile,line,2,config_buffer,0)) {
				process_xmlfile_line(line, in_line);
			} else if(!regexec(&regex_xmlpostprocessing,line,2,config_buffer,0)) {
				process_xmlpostprocessing_line(line, in_line);
			} else {
				THROWEXCEPTION("Line %d is malformed (expecting record descriptor, collector descriptor, interval descriptor, or source descriptor from previous record):\n%s",in_line,line);
			}
			break;
	}

	return 1;
}

/**
 * Parses a config file and returns its content in a treelike structure
 * <filename> The path to the file.
 */
config_file_descriptor* read_config(char* filename){


	//Init config regexes if necessary
	if(!config_regex_inited){
		init_config_regex();
	}

	//Create new config descriptor
	create_config_file_descriptor();

	//File öffnen und checken obs alles geklappt hat
	FILE* fp = fopen(filename, "r");
	if (fp == NULL){
		THROWEXCEPTION("Reading from config file failed!");
	}

	//Set parse mode to record (the parser first expects a record line)
	parse_mode = PARSE_MODE_MAIN;

	int in_line;
	char curr_line[MAX_CONF_LINE_LENGTH];

	//Main loop over all lines in the config file
	for (in_line = 1; fgets(curr_line, MAX_CONF_LINE_LENGTH, fp) != NULL; in_line++){
		process_config_line(curr_line,in_line);
	}
	fclose(fp);

	/*
	 * ERROR HANDLING
	 */

	//Missing rule lines at the end of file
	if(num_rule_lines>0){
		THROWEXCEPTION("Reached end of config file, but still %d rules missing for the last source!", num_rule_lines);
	}

	//No collectors defined
	if(current_config_file->record_descriptors->size>0 && current_config_file->collectors->size==0){
		msg(MSG_DIALOG, "Records will not be exported because no COLLECTOR definition was found in config file.");
	}

	//No collectors defined
	if(current_config_file->xmlrecord_descriptors->size>0 && current_config_file->xmlfile==NULL){
		msg(MSG_DIALOG, "XML file will not be written because no XMLFILE definition was found in config file.");
	}

	if (msg_getlevel() >= MSG_VDEBUG) {
		msg(MSG_VDEBUG, "Parsed configuration:");
		echo_config_file(current_config_file);
	}

	// Free regexps to save memory
	deinit_config_regex();

	return current_config_file;
}

/**
 * DEBUGGING STUFF
 */


char indent_str [30];
char* get_indent(int num_spaces){
	indent_str[num_spaces] = '\0';
	for(;num_spaces>0;num_spaces--){
		indent_str[num_spaces-1] = ' ';
	}
	return indent_str;
}

/**
 * Prints the whole content of a config file descriptor, to check if the config was read thoroughly and
 * correctly.
 */
void echo_config_file(config_file_descriptor* conf){
	list_node* cur;
	int indent = 0;
	printf("Config file with %d records and %d collectors:\n", conf->record_descriptors->size, conf->collectors->size);
	indent += 2;
	printf("%sSend interval: %d\n%sObservation domain id: %d\n", get_indent(indent), conf->interval, get_indent(indent), conf->observation_domain_id);
	printf("%sCollector descriptors:\n", get_indent(indent));
	indent += 2;
	for(cur=conf->collectors->first;cur!=NULL;cur=cur->next){
			collector_descriptor* cur_collector = (collector_descriptor*)cur->data;
			printf("%sCollector: %s:%d\n",
					get_indent(indent),
					cur_collector->ip,
					cur_collector->port);
		}
	indent -= 2;
	printf("%sRecords descriptors:\n", get_indent(indent));
	indent += 2;
	for(cur=conf->record_descriptors->first;cur!=NULL;cur=cur->next){
		record_descriptor* cur_record = (record_descriptor*)cur->data;
		printf("%s%sRecord with %i sources\n",
				get_indent(indent),
				(cur_record->is_multirecord?"Multi":""),
				cur_record->sources->size);

		//start echo sources
		indent+=2;

		list_node* cur2;

		for(cur2=cur_record->sources->first;cur2!=NULL;cur2=cur2->next){
			source_descriptor* cur_source = (source_descriptor*)cur2->data;

			printf("%sSource %s (type %d) with %d rules and pattern: %s\n",
					get_indent(indent),
					cur_source->source_path,
					cur_source->source_type,
					cur_source->rule_count,
					cur_source->reg_exp);

			//start echo rules
			indent+=2;

			list_node* cur3;

			for(cur3=cur_source->rules->first;cur3!=NULL;cur3=cur3->next){
				transform_rule* cur_rule = (transform_rule*)cur3->data;

				printf("%sRule with bytecount %d, information element id %d and enterprise id %d\n",
						get_indent(indent),
						cur_rule->bytecount,
						cur_rule->ie_id,
						cur_rule->enterprise_id);
			}

			indent-=2;
			//end echo rules
		}

		indent-=2;
		//end echo sources
	}

	indent -= 2;
	printf("%sXML file: %s\n", get_indent(indent), conf->xmlfile);
	printf("%sXML postprocessing: %s\n", get_indent(indent), conf->xmlpostprocessing);

	for(cur=conf->xmlrecord_descriptors->first;cur!=NULL;cur=cur->next){
		xmlrecord_descriptor* cur_xmlrecord = (xmlrecord_descriptor*)cur->data;
		printf("%sXML record <%s> with %i sources\n",
				get_indent(indent),
				cur_xmlrecord->name,
				cur_xmlrecord->sources->size);

		//start echo sources
		indent+=2;

		list_node* cur2;

		for(cur2=cur_xmlrecord->sources->first;cur2!=NULL;cur2=cur2->next){
			source_descriptor* cur_source = (source_descriptor*)cur2->data;

			printf("%sSource %s (type %d) with %d rules and pattern: %s\n",
					get_indent(indent),
					cur_source->source_path,
					cur_source->source_type,
					cur_source->rule_count,
					cur_source->reg_exp);

			//start echo rules
			indent+=2;

			list_node* cur3;

			for(cur3=cur_source->rules->first;cur3!=NULL;cur3=cur3->next){
				char* name = (char*)cur3->data;

				printf("%sSubelement: <%s>\n",
						get_indent(indent),
						name);
			}

			indent-=2;
			//end echo rules
		}

		indent-=2;
		//end echo sources
	}

}


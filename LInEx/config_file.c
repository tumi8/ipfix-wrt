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

int config_regex_inited = 0;
int num_rule_lines = 0;
int number_of_proc_file = 0;
int parse_mode = PARSE_MODE_MAIN;
int current_default_template_id = 257;
regex_t regex_empty_line;
regex_t regex_comment;
regex_t regex_record_selector;
regex_t regex_source_selector;
regex_t regex_source_suffix;
regex_t regex_rule;
regex_t regex_collector;
regex_t regex_interval;
regex_t regex_odid;
config_file_descriptor* current_config_file;
record_descriptor* current_record;
source_descriptor* current_source;
regmatch_t config_buffer[5];

//Constructor for config file descriptor
config_file_descriptor* create_config_file_descriptor(){
	current_config_file = (config_file_descriptor*) malloc(sizeof(config_file_descriptor));
	current_config_file->record_descriptors = list_create();
	current_config_file->collectors = list_create();
	current_config_file->verbose = STANDARD_VERBOSE_LEVEL;
	current_config_file->interval = STANDARD_SEND_INTERVAL;
	current_config_file->observation_domain_id = OBSERVATION_DOMAIN_STANDARD_ID;
	return current_config_file;
}


//Constructor for collector descriptor
collector_descriptor* create_collector_descriptor(char* ip, int port){
	collector_descriptor* result = (collector_descriptor*) malloc(sizeof(collector_descriptor));
	result->ip = ip;
	result->port = port;
	list_insert(current_config_file->collectors,result);
	return result;
}

//Constructor for record descriptor
record_descriptor* create_record_descriptor(){
	current_record = (record_descriptor*) malloc(sizeof(record_descriptor));
	current_record->sources = list_create();
	current_record->template_id = current_default_template_id++;
	list_insert(current_config_file->record_descriptors,current_record);
	return current_record;
}

//Constructor for source_descriptor
source_descriptor* create_source_descriptor(){
	current_source = (source_descriptor*) malloc(sizeof(source_descriptor));
	current_source->rules = list_create();
	list_insert(current_record->sources,current_source);

	//Multirecords may NOT contain more than one source
	if(current_record->is_multirecord && current_record->sources->size > 1){
		fprintf(stderr, "Found a multirecord with more than one source! Multirecords may only contain one source!\n");
		exit(-1);
	}
	return current_source;
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
	regcomp(&regex_comment,"^[ \t]*\\#.*$",REG_EXTENDED);
	regcomp(&regex_empty_line,"^[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_record_selector,"^[ \t]*(RECORD|MULTIRECORD)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_source_selector,"^[ \t]*(FILE|COMMAND).*$",REG_EXTENDED);
	regcomp(&regex_source_suffix,"^[ \t]*([A-Za-z0-9/-]+|\"([^\"]*)\")[ \t]*,[ \t]*([0-9]+)[ \t]*,[ \t]*\"(.*)\"[ \t\n]*",REG_EXTENDED);
	regcomp(&regex_rule,"^[ \t]*([0-9]+)[ \t]*,[ \t]*([0-9]+)[ \t]*,[ \t]*([0-9]+)[ \t]*,[ \t]*([0-9]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_collector,"^[ \t]*COLLECTOR[ \t]+([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})[ \t]*\\:[ \t]*([0-9]{1,5})[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_interval,"^[ \t]*INTERVAL[ \t]+([0-9]+)[ \t\n]*$",REG_EXTENDED);
	regcomp(&regex_odid,"^[ \t]*SOURCEID[ \t]+([0-9]+)[ \t\n]*$",REG_EXTENDED);
	config_regex_inited = 1;
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
unsigned int extract_int_from_regmatch(regmatch_t* match, char* input){
	//Null terminate
	char swap = input[match->rm_eo];
	unsigned int result;
	input[match->rm_eo] = '\0';
	result = atoi(&input[match->rm_so]);
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
		fprintf(stderr,"Malformed line (line %d)!\nExpecting rule line, but found this line:\n%s\n", in_line,line);
		exit(-1);
	}
	int transform_id = extract_int_from_regmatch(&config_buffer[2],line);
	transform_rule* tr = create_transform_rule();
	tr->bytecount = (uint16_t)extract_int_from_regmatch(&config_buffer[1],line);
	tr->transform_func = get_rule_by_index(transform_id);
	tr->transform_id = transform_id;
	tr->ie_id = extract_int_from_regmatch(&config_buffer[3],line);
	tr->enterprise_id = extract_int_from_regmatch(&config_buffer[4],line);

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
		fprintf(stderr,"Line %d in config file is malformed!\nParser expects a rule line that starts with a source type descriptor (e.g. \"FILE:\")\nThis line was found:\n%s\n",in_line,line);
		exit(-1);
	}

	//Create new source descriptor
	create_source_descriptor();

	line[config_buffer[1].rm_eo]='\0'; //0 terminate

	if(!strcasecmp(&line[config_buffer[1].rm_so],"FILE")){
		current_source->source_type = SOURCE_TYPE_FILE;
	} else if(!strcasecmp(&line[config_buffer[1].rm_so],"COMMAND")){
		current_source->source_type = SOURCE_TYPE_COMMAND;
	} else {
		fprintf(stderr,"Unrecognized type selector \"%s\" in line %d\n",&line[config_buffer[1].rm_so],in_line);
		exit(-1);
	}

	//store line with config data in dataline
	char* dataline = &line[config_buffer[1].rm_eo+1];
	if(regexec(&regex_source_suffix,dataline,5,config_buffer,0)){
		fprintf(stderr,"Unrecognized config line (Line %d):\n%s",in_line,dataline);
		exit(-1);
	}

	//Check which capturing group to use for source index, if the 2nd exists use this one
	int path_index = 1;
	if(config_buffer[2].rm_so!=-1) path_index = 2;

	//extract file name
	current_source->source_path = extract_string_from_regmatch(&config_buffer[path_index],dataline);

	//extract rule count
	current_source->rule_count = extract_int_from_regmatch(&config_buffer[3],dataline);

	//extract pattern
	current_source->reg_exp = extract_string_from_regmatch(&config_buffer[4],dataline);

	//compile pattern
	regcomp(&(current_source->reg_exp_compiled),current_source->reg_exp,REG_EXTENDED);

	//Set num_rule_lines so the next lines get parsed as rule lines
	num_rule_lines = current_source->rule_count;


	//fprintf(stderr,"Found proc line:\nFile Name: %s\nRule count: %d\nPattern: <%s>\n",current_source->source_path,current_source->rule_count,current_source->reg_exp);
	number_of_proc_file++;

	//Go into rule mode
	parse_mode = PARSE_MODE_RULE;

	return 1;
}

/**
 * Processes a record line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_record_line(char* line, int in_line){

	if(regexec(&regex_record_selector,line,2,config_buffer,0)){
		fprintf(stderr,"Record line %d in config file is malformed (not starting with a record type selector):\n%s\n",in_line,line);
		exit(-1);
	}

	//Create new record descriptor
	create_record_descriptor();

	line[config_buffer[1].rm_eo]='\0'; //0 terminieren

	if(!strcasecmp(&line[config_buffer[1].rm_so],"RECORD")){
		current_record->is_multirecord = 0;

	} else if(!strcasecmp(&line[config_buffer[1].rm_so],"MULTIRECORD")) {
		current_record->is_multirecord = 1;
	} else {
		fprintf(stderr,"Unrecognized record type selector \"%s\" in line %d\n",&line[config_buffer[1].rm_so],in_line);
		exit(-1);
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
	if(regexec(&regex_collector,line,3,config_buffer,0)){
		fprintf(stderr,"Collector line %d in config file is malformed:\n%s\n",in_line,line);
		exit(-1);
	}

	char* ip = extract_string_from_regmatch(&config_buffer[1],line);
	int port = extract_int_from_regmatch(&config_buffer[2],line);
	create_collector_descriptor(ip,port);
	return 1;
}

/**
 * Processes a export interval line in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_interval_line(char* line, int in_line){
	if(regexec(&regex_interval,line,2,config_buffer,0)){
		fprintf(stderr,"Interval line %d in config file is malformed:\n%s\n",in_line,line);
		exit(-1);
	}

	current_config_file->interval = extract_int_from_regmatch(&config_buffer[1],line);
	return 1;
}

/**
 * Processes an observation domain ID line (source ID line) in the config file
 * <line> is the content of that line
 * <in_line> is the number of that line
 */
int process_odid_line(char* line, int in_line){
	if(regexec(&regex_odid,line,2,config_buffer,0)){
		fprintf(stderr,"Source id line %d in config file is malformed:\n%s\n",in_line,line);
		exit(-1);
	}

	current_config_file->observation_domain_id = extract_int_from_regmatch(&config_buffer[1],line);
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
			} else if(!regexec(&regex_odid,line,2,config_buffer,0)) {
				process_odid_line(line, in_line);
			} else {
				fprintf(stderr,"Line %d is malformed (expecting record descriptor, interval descriptor, or collector descriptor):\n%s\n",in_line,line);
				exit(-1);
			}
			break;
		case PARSE_MODE_SOURCE_DESCR:
			process_source_line(line, in_line);
			break;
		case PARSE_MODE_RULE:
			process_rule_line(line, in_line);
			break;
		case PARSE_MODE_SOURCE_OR_MAIN:
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
			} else {
				fprintf(stderr,"Line %d is malformed (expecting record descriptor, collector descriptor, interval descriptor, or source descriptor from previous record):\n%s\n",in_line,line);
				exit(-1);
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
		fprintf(stderr, "Reading from config file failed!\n");
		exit(-1);
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
		fprintf(stderr, "Reached end of config file, but still %d rules missing for the last source!\n", num_rule_lines);
		exit(-1);
	}

	//No records found
	if(current_config_file->record_descriptors->size==0){
		fprintf(stderr, "Reached end of config file, but no record found (empty config?)\n");
		exit(-1);
	}

	//Missing sources at the end of file
	if(current_record->sources->size==0){
		fprintf(stderr, "Reached end of config file, but the last record has no sources!\n");
		exit(-1);
	}

	//No collectors defined
	if(current_config_file->collectors->size==0){
		fprintf(stderr, "Reached end of config file, but no collector definitions found\n");
		exit(-1);
	}

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


}


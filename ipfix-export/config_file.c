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

#define PARSE_MODE_RECORD 0
#define PARSE_MODE_SOURCE_DESCR 1
#define PARSE_MODE_RULE 2
#define PARSE_MODE_SOURCE_OR_RECORD 3

int config_regex_inited = 0;
int num_rule_lines = 0;
int number_of_proc_file = 0;
int parse_mode = PARSE_MODE_RECORD;
regex_t regex_empty_line;
regex_t regex_comment;
regex_t regex_source_selector;
regex_t regex_record_selector;
regex_t regex_file;
regex_t regex_rule;
config_file_descriptor* current_config_file;
record_descriptor* current_record;
source_descriptor* current_source;
regmatch_t config_buffer[5];

//Constructor for config file descriptor
config_file_descriptor* create_config_file_descriptor(){
	current_config_file = (config_file_descriptor*) malloc(sizeof(config_file_descriptor));
	current_config_file->record_descriptors = list_create();
	return current_config_file;
}

//Constructor for record descriptor
record_descriptor* create_record_descriptor(){
	current_record = (record_descriptor*) malloc(sizeof(record_descriptor));
	current_record->sources = list_create();
	list_insert(current_config_file->record_descriptors,current_record);
	return current_record;
}

//Constructor for source_descriptor
source_descriptor* create_source_descriptor(){
	current_source = (source_descriptor*) malloc(sizeof(source_descriptor));
	current_source->rules = list_create();
	list_insert(current_record->sources,current_source);
	return current_source;
}

//Constructor for rule
transform_rule* create_transform_rule(){
	transform_rule* tr = (transform_rule*) malloc(sizeof(transform_rule));;
	list_insert(current_source->rules,tr);
	return tr;
}


void init_config_regex(){
	regcomp(&regex_comment,"^\\s*(\\#?).*$",REG_EXTENDED);
	regcomp(&regex_empty_line,"^\\s*$",REG_EXTENDED);
	regcomp(&regex_record_selector,"^\\s*(RECORD|MULTIRECORD)\\s*$",REG_EXTENDED);
	regcomp(&regex_source_selector,"^\\s*(FILE|COMMAND)\\:.*$",REG_EXTENDED); //(\\w+)
	regcomp(&regex_file,"^\\s*(\\w+)\\s*,\\s*([0-9]+)\\s*,\\s*(.*?)\\s*$",REG_EXTENDED);
	regcomp(&regex_rule,"^\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*$",REG_EXTENDED);
	config_regex_inited = 1;
}

char* extract_string_from_regmatch(regmatch_t* match, char* input){
	int length = (match->rm_eo-match->rm_so);
	char* output = (char*)malloc(sizeof(char)*(length+1));
	memcpy(output,&input[match->rm_so],length);
	output[length] = '\0';
	return output;
}

unsigned int extract_int_from_regmatch(regmatch_t* match, char* input){
	//Null terminate
	char swap = input[match->rm_eo];
	unsigned int result;
	input[match->rm_eo] = '\0';
	result = atoi(&input[match->rm_so]);
	input[match->rm_eo] = swap;
	return result;
}

int process_rule_line(char* line, int in_line){

	if(regexec(&regex_rule,line,5,config_buffer,0)){
		printf("Malformed line (line %d)!\nExpecting rule line, but found this line:\n%s\n", in_line,line);
		exit(-1);
	}

	transform_rule* tr = create_transform_rule();
	tr->bytecount = (uint16_t)extract_int_from_regmatch(&config_buffer[1],line);
	tr->transform = get_rule_by_index(extract_int_from_regmatch(&config_buffer[2],line));
	tr->ie_id = extract_int_from_regmatch(&config_buffer[3],line);
	tr->enterprise_id = extract_int_from_regmatch(&config_buffer[4],line);
	/*printf("Found rule line (%d rule lines expected afterwards):\nBytecount: %d\nTransform: %d\nIE: %d\nEnterprise id: %d\n"
				,num_rule_lines-1
				,tr->bytecount
				,extract_int_from_regmatch(&config_buffer[2],line)
				,tr->ie_id
				,tr->enterprise_id);*/

	//decrease number of rule lines to parse.
	//If no more rule lines are to be parsed, the parsers expects
	//a new source descriptor or record descriptor in the next line
	num_rule_lines--;
	if(num_rule_lines<=0){
		parse_mode = PARSE_MODE_SOURCE_OR_RECORD;
	}

	return 1;

}
int process_source_line(char* line, int in_line){

	if(regexec(&regex_source_selector,line,2,config_buffer,0)){
		printf("Line %d in config file is malformed!\nParser expects a rule line that starts with a source type descriptor (e.g. \"FILE:\")\nThis line was found:\n%s\n",in_line,line);
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
		printf("Unrecognized type selector \"%s\" in line %d\n",&line[config_buffer[1].rm_so],in_line);
		exit(-1);
	}

	//store line with config data in dataline
	char* dataline = &line[config_buffer[1].rm_eo+1];
	if(regexec(&regex_file,dataline,4,config_buffer,0)){
		printf("Unrecognized config line (Line %d):\n%s",in_line,dataline);
		exit(-1);
	}

	//extract file name
	current_source->source_path = extract_string_from_regmatch(&config_buffer[1],dataline);

	//extract rule count
	current_source->rule_count = extract_int_from_regmatch(&config_buffer[2],dataline);

	//extract pattern
	current_source->reg_exp = extract_string_from_regmatch(&config_buffer[3],dataline);

	printf("%d,%d",config_buffer[3].rm_so,config_buffer[3].rm_eo);
	//Set num_rule_lines so the next lines get parsed as rule lines
	num_rule_lines = current_source->rule_count;


	printf("Found proc line:\nFile Name: %s\nRule count: %d\nPattern: <%s>\n",current_source->source_path,current_source->rule_count,current_source->reg_exp);
	number_of_proc_file++;

	//Go into rule mode
	parse_mode = PARSE_MODE_RULE;

	return 1;
}

int process_record_line(char* line, int in_line){

	if(regexec(&regex_record_selector,line,2,config_buffer,0)){
		printf("Record line %d in config file is malformed (not starting with a record type selector):\n%s\n",in_line,line);
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
		printf("Unrecognized record type selector \"%s\" in line %d\n",&line[config_buffer[1].rm_so],in_line);
		exit(-1);
	}

	parse_mode = PARSE_MODE_SOURCE_DESCR;
	return 1;

}

int process_config_line(char* line, int in_line){

	//Skip empty lines
	if(!regexec(&regex_empty_line,line,2,config_buffer,0)){
		return 0;
	}

	//Skip comments
	if(!regexec(&regex_comment,line,2,config_buffer,0)){
		if(line[config_buffer[1].rm_so] == '#'){
			return 0;
		}
	}

	if(parse_mode == PARSE_MODE_RECORD){
		process_record_line(line, in_line);
	}else if(parse_mode == PARSE_MODE_SOURCE_DESCR){
		process_source_line(line, in_line);
	}else if(parse_mode == PARSE_MODE_RULE){
		process_rule_line(line, in_line);
	}else if(parse_mode == PARSE_MODE_SOURCE_OR_RECORD){
		if(!regexec(&regex_record_selector,line,2,config_buffer,0)){
			process_record_line(line, in_line);
		} else if(!regexec(&regex_source_selector,line,2,config_buffer,0)){
			process_source_line(line, in_line);
		} else {
			printf("Expecting record selector or source selector in line %d\n",in_line);
			exit(-1);
		}
	}

	return 1;
}

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
	parse_mode = PARSE_MODE_RECORD;

	int in_line;
	char curr_line[MAX_LINE_LENGTH];

	//Main loop over all lines in the config file
	for (in_line = 1; fgets(curr_line, MAX_LINE_LENGTH, fp) != NULL; in_line++){
		process_config_line(curr_line,in_line);
	}
	fclose(fp);

	if(num_rule_lines>0){
		fprintf(stderr, "Reached end of config file, but still %d rules missing for the last source!\n", num_rule_lines);
		exit(-1);
	}

	if(current_config_file->record_descriptors->size==0){
		fprintf(stderr, "Reached end of config file, but no record found (empty config?)\n");
		exit(-1);
	}

	if(current_record->sources->size==0){
		fprintf(stderr, "Reached end of config file, but the last record has no sources!\n");
		exit(-1);
	}

	return current_config_file;
}

char indent_str [30];
char* get_indent(int num_spaces){
	indent_str[num_spaces] = '\0';
	for(;num_spaces>0;num_spaces--){
		indent_str[num_spaces-1] = ' ';
	}
	return indent_str;
}

void echo_config_file(config_file_descriptor* conf){
	list_node* cur;
	int indent = 0;
	printf("Config file with %d records:\n", conf->record_descriptors->size);
	indent = 2;
	for(cur=conf->record_descriptors->first;cur!=NULL;cur=cur->next){
		record_descriptor* curRecord = (record_descriptor*)cur->data;
		printf("%s%sRecord with %i sources\n",
				get_indent(indent),
				(curRecord->is_multirecord?"Multi":""),
				curRecord->sources->size);

		//start echo sources
		indent+=2;

		list_node* cur2;

		for(cur2=curRecord->sources->first;cur2!=NULL;cur2=cur2->next){
			source_descriptor* curSource = (source_descriptor*)cur2->data;

			printf("%sSource %s (type %d) with %d rules and pattern: %s\n",
					get_indent(indent),
					curSource->source_path,
					curSource->source_type,
					curSource->rule_count,
					curSource->reg_exp);
		}

		indent-=2;
		//end echo sources
	}


}


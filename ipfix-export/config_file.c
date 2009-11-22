/*
 * config_file.c
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#include "config_file.h"
#include "transform_rules.h"


int config_regex_inited = 0;
int num_rule_lines = 0;
regex_t regex_empty_line;
regex_t regex_comment;
regex_t regex_selector;
regex_t regex_file;
regex_t regex_rule;
proc_file_descriptor* current_descriptor;
regmatch_t config_buffer[5];

void init_config_regex(){
	regcomp(&regex_comment,"^\\s*(\\#?).*$",REG_EXTENDED);
	regcomp(&regex_empty_line,"^\\s*$",REG_EXTENDED);
	regcomp(&regex_selector,"^\\s*(\\w+)\\:.*$",REG_EXTENDED);
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

	if(!regexec(&regex_rule,line,5,config_buffer,0)){
		transform_rule* tf = &current_descriptor->rules[current_descriptor->rule_count-num_rule_lines];
		tf->bytecount = (uint16_t)extract_int_from_regmatch(&config_buffer[1],line);
		tf->transform = get_rule_by_index(extract_int_from_regmatch(&config_buffer[2],line));
		tf->ie_id = extract_int_from_regmatch(&config_buffer[3],line);
		tf->enterprise_id = extract_int_from_regmatch(&config_buffer[4],line);
		printf("Found rule line:\nBytecount: %d\nTransform: %d\nIE: %d\nEnterprise id: %d\n",tf->bytecount,extract_int_from_regmatch(&config_buffer[2],line),tf->ie_id,tf->enterprise_id);

	} else {
		printf("Unrecognized rule line (line %d)!", in_line);
	}

	num_rule_lines--;
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

	//Still rule lines to process? -> do it
	if(num_rule_lines > 0){
		return process_rule_line(line,in_line);
	}
	//Allocate memory for the pattern

	if(!regexec(&regex_selector,line,2,config_buffer,0)){

		line[config_buffer[1].rm_eo]='\0'; //0 terminieren

		if(!strcasecmp(&line[config_buffer[1].rm_so],"FILE")){

			char* dataline = &line[config_buffer[1].rm_eo+1];
			if(!regexec(&regex_file,dataline,4,config_buffer,0)){
				current_descriptor = (proc_file_descriptor*) malloc(sizeof(proc_file_descriptor));

				//Extract file name
				current_descriptor->proc_file = extract_string_from_regmatch(&config_buffer[1],dataline);

				//Extract rule count
				current_descriptor->rule_count = extract_int_from_regmatch(&config_buffer[2],dataline);

				//Extract pattern
				current_descriptor->reg_exp = extract_string_from_regmatch(&config_buffer[3],dataline);

				printf("%d,%d",config_buffer[3].rm_so,config_buffer[3].rm_eo);
				//Set num_rule_lines so the next lines get parsed as rule lines
				num_rule_lines = current_descriptor->rule_count;

				//Allocate a rule array
				current_descriptor->rules = (transform_rule*) malloc(sizeof(transform_rule)*num_rule_lines);

				printf("Found proc line:\nFile Name: %s\nRule count: %d\nPattern: <%s>\n",current_descriptor->proc_file,current_descriptor->rule_count,current_descriptor->reg_exp);

			} else {
				printf("Unrecognized config line (Line %d):\n%s",in_line,dataline);
				exit(-1);
			}


		} else {
			printf("Unrecognized type selector \"%s\" in line %d\n",&line[config_buffer[1].rm_so],in_line);
			exit(-1);
		}

	}else{
		printf("Line %d in config file is malformed (not starting with a type selector):\n%s\n",in_line,line);
		exit(-1);
	}

	return 1;

}

void read_config(char* filename){

	if(!config_regex_inited){
		init_config_regex();
	}

	//File öffnen und checken obs alles geklappt hat
	FILE* fp = fopen(filename, "r");
	if (fp == NULL){
		fprintf(stderr, "Reading from config file failed!\n");
		exit(-1);
	}

	int in_line;
	char curr_line[MAX_LINE_LENGTH];
	for (in_line = 1; fgets(curr_line, MAX_LINE_LENGTH, fp) != NULL; in_line++){
		process_config_line(curr_line,in_line);
	}
	fclose(fp);

	if(num_rule_lines>0){
		fprintf(stderr, "Reached end of file, but still %d rules missing!", num_rule_lines);
		exit(-1);
	}
}


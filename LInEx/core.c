/*
 * core.c
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */
//#include "core.h"
#include "config_file.h"
#include "ipfixlolib/msg.h"
#include "ipfix_templates.h"
#include "ipfix_data.h"



int verbose_level = STANDARD_VERBOSE_LEVEL;
regex_t param_regex;
regex_t long_param_regex;
regmatch_t param_matches[3];

/**
 * Takes all collectors from config file <conf>
 * and adds them to the exporter <exporter>
 * by calling the appropriate ipfixlolib function.
 */
void init_collectors(config_file_descriptor* conf, ipfix_exporter* exporter){
	list_node* cur;

	for(cur = conf->collectors->first;cur!=NULL;cur=cur->next){
		collector_descriptor* cur_descriptor = (collector_descriptor*)cur->data;
		int ret = ipfix_add_collector(exporter, cur_descriptor->ip, cur_descriptor->port, UDP);
		printf("Added collector %s:%d (return: %d)\n", cur_descriptor->ip,cur_descriptor->port,  ret);
	}
}

void process_normal_param(char* param_name, int param_param){
	if(!strcasecmp(param_name,"v")){
		if(param_param > 4){
			fprintf(stderr,"Verbose level must be between 0 and 4!\n");
			exit(-1);
		}
		verbose_level = param_param;
		printf("Verbose level set to %d!\n",verbose_level);
	} else {
		fprintf(stderr,"Unknown command line parameter -%s\n",param_name);
		exit(-1);
	}
}

void process_long_param(char* param_name){
	if(!strcasecmp(param_name,"help")){
		printf("Usage:\n LInEx [-vX]\n-vX sets the verbose level to X, X must be between 0 and 4. 0 is no command line output, 4 is very much!\n\nDon't forget to write an appropriate config.conf file before starting LInEx.\n");
		exit(0);
	} else {
		fprintf(stderr,"Unknown command line parameter --%s\n",param_name);
		exit(-1);
	}

}
void parse_command_line_parameter(char* param){
	if(!regexec(&param_regex,param,3,param_matches,0)){
		char* name = extract_string_from_regmatch(&param_matches[1],param);
		int parameter = extract_int_from_regmatch(&param_matches[2],param);
		process_normal_param(name,parameter);
	} else if(!regexec(&long_param_regex,param,3,param_matches,0)){
		char* name = extract_string_from_regmatch(&param_matches[1],param);
		process_long_param(name);
	} else {
		fprintf(stderr,"Unknown command line parameter %s",param);
		exit(-1);
	}
}

void parse_command_line_parameters(int argc, char **argv){
	regcomp(&param_regex,"^\\-([a-z])([0-9]+)$",REG_EXTENDED);
	regcomp(&long_param_regex,"^\\-\\-([a-z]+)$",REG_EXTENDED);
	int i;
	for(i=1;i<argc;i++){
		parse_command_line_parameter(argv[i]);
	}

}

/**
 * Test main methode
 */
int main(int argc, char **argv)
{
	//Process command line parameters
	parse_command_line_parameters(argc,argv);

	//Read config file
	config_file_descriptor* conf = read_config("config.conf");
	//Init exporter
	ipfix_exporter* send_exporter;
	int ret = ipfix_init_exporter(conf->observation_domain_id, &send_exporter);

	if (ret != 0) {
		fprintf(stderr, "ipfix_init_exporter failed!\n");
		exit(-1);
	}

	//Add collectors from config file
	init_collectors(conf,send_exporter);

	//Generate templates
	printf("Generating templates from config...");
	fflush(NULL);
	generate_templates_from_config(send_exporter,conf);
	printf(" DONE!\n");

	//Periodically, send the configured datasets
	int i = 0;
	while(1){
		i++;
		if(verbose_level>=1)printf("Starting export %d...\n",i);
		config_to_ipfix(send_exporter,conf);
		if(verbose_level>=1)printf("Export finished!\n");
		sleep(conf->interval);
	}

	//Dead code :)
	return 0;
}





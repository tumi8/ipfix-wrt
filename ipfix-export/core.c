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


/**
 * Test main methode
 */
int main(int argc, char **argv)
{
	//Read config file
	config_file_descriptor* conf = read_config("config.conf");
	//echo_config_file(conf);
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





/*
 * core.c
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */
#include "core.h"
#include "ipfix_templates.h"
#include "ipfix_data.h"
#include "config_file.h"



void mainLoop(int interval, config_file_descriptor* conf, ipfix_exporter* exporter){
	while(1){
		config_to_ipfix(exporter,conf);
		sleep(interval);
	}
}


/**
 * Test main methode
 */
int main(int argc, char **argv)
{
	echo_config_file(read_config("test.txt"));
	return 0;

	int ret =0;
	char *collector_ip = "127.0.0.1";
	int collector_port = 1500;

	ipfix_exporter* send_exporter;

	//Init test exporter
	ret=ipfix_init_exporter(MY_SOURCE_ID, &send_exporter);

	if (ret != 0) {
		fprintf(stderr, "ipfix_init_exporter failed!\n");
		exit(-1);
	}

	//test collector hinzufügen
	ret = ipfix_add_collector(send_exporter, collector_ip, collector_port, UDP);
	printf("ipfix_add_collector returned %i\n", ret);

	return 0;
}





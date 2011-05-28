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
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>


regex_t param_regex;
regex_t long_param_regex;
regmatch_t param_matches[3];
char* config_file = NULL;
pid_t childpid = -1;

/**
 * Takes all collectors from config file <conf>
 * and adds them to the exporter <exporter>
 * by calling the appropriate ipfixlolib function.
 */
void init_collectors(config_file_descriptor* conf, ipfix_exporter* exporter){
	list_node* cur;

        ipfix_aux_config_udp aux_config; /* Auxiliary parameter for UDP */
       	aux_config.mtu = 1500;           /* MTU */
	for(cur = conf->collectors->first;cur!=NULL;cur=cur->next){
		collector_descriptor* cur_descriptor = (collector_descriptor*)cur->data;
		int ret = ipfix_add_collector(exporter, cur_descriptor->ip, cur_descriptor->port, UDP, &aux_config);
		msg(MSG_INFO, "Added collector %s:%d (return: %d)", cur_descriptor->ip,cur_descriptor->port,  ret);
	}
}

void usage(){
	printf("Usage: LInEx -f <config_file> [-v <X>]\n");
	printf("-f <config_file>     specifies configuration file\n");
	printf("-v <X>               sets verbosity level (X=0,1,2,3,4,5 default=2)\n");
}

void parse_command_line_parameters(int argc, char **argv){
	/* parse command line */
	int c;
	while ((c=getopt(argc, argv, "hf:v:")) != -1) {

		switch (c) {

			case 'f':
				config_file = optarg;
				break;

			case 'v':
				msg_setlevel(atoi(optarg));
				break;

			case 'h':
			default:
				/* print usage and quit vermont, if unknow switch */
				usage();
				exit(1);
		}
	}
	if (config_file == NULL)
	{
		usage();
		exit(1);
	}
}

void sigwait_handler(int signal)
{
	int status;
	pid_t pid;

        //Wait for child without blocking
        if ((pid = waitpid(-1, &status, WNOHANG)) < 0) 
	{
		//msg(MSG_VDEBUG, "waitpid failed.");
		return;
	}
	//Return if this is not the XML postprocessing child
	if (pid != childpid) return; 

	childpid = -1;
}

/**
 * Test main methode
 */
int main(int argc, char **argv)
{
	//Initialize signal handler
	struct sigaction new_sa;
	new_sa.sa_handler = sigwait_handler;
	sigemptyset(&new_sa.sa_mask);
	new_sa.sa_flags = 0;
	if (sigaction(SIGCHLD, &new_sa, NULL) == -1) {
		THROWEXCEPTION("Could not install signal handler.");
	}

	//Process command line parameters
	parse_command_line_parameters(argc,argv);

	//Read config file
	config_file_descriptor* conf = read_config(config_file);

	//Init exporter
	ipfix_exporter* send_exporter;
	int ret = ipfix_init_exporter(conf->observation_domain_id, &send_exporter);
	if (ret != 0) {
		THROWEXCEPTION("ipfix_init_exporter failed!\n");
	}

	//Add collectors from config file
	init_collectors(conf,send_exporter);

	//Generate templates
	msg(MSG_INFO, "Generating templates from config");
	generate_templates_from_config(send_exporter,conf);
	msg(MSG_DIALOG, "LInEx is up and running. Press Ctrl-C to exit.");

	//Open XML file
	FILE* xmlfh = NULL;
	if(conf->xmlfile != NULL) {
		xmlfh = fopen(conf->xmlfile, "w");
		if (xmlfh == NULL)
			THROWEXCEPTION("Could not open XML file %s", conf->xmlfile);
	}

	//Periodically, send the configured datasets
	unsigned long i = 0;
	unsigned timeout;
	time_t now;
	char timestr[20];

	while(1){
		i++;
		now = time(NULL);
		strftime(timestr, 20, "%X", localtime(&now));
		msg(MSG_DIALOG, "Export status at %s (round %d)", timestr, i);
		if(conf->record_descriptors->size>0 && conf->collectors->size>0) {
			msg(MSG_INFO, "Exporting IPFIX messages...");
			config_to_ipfix(send_exporter, conf);
		}
		if(xmlfh != NULL) {
			msg(MSG_INFO, "Updating XML file %s", conf->xmlfile);
			config_to_xml(xmlfh, conf);
			//Optional XML postprocessing
			if(conf->xmlpostprocessing != NULL) {
				//Kill old XML postprocessing child if it is still alive
				if(childpid != -1) {
					msg(MSG_FATAL, "XML postprocessing has not terminated in time. Killing it.");
					kill(childpid, SIGKILL);
				}
				//Create new XML postprocessing child
				if((childpid = fork()) == -1) {
					msg(MSG_FATAL, "Could not fork. XML postprocessing skipped.");
				}
				if(childpid == 0) {
					msg(MSG_INFO, "Trigger XML postprocessing.");
					int ret = system(conf->xmlpostprocessing);
					exit(ret);
				}
			}
		}
		timeout = conf->interval;
		while(timeout = sleep(timeout)) {}
	}

	//Dead code :)
	return 0;
}





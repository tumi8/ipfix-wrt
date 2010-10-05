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
 * ipfix_templates.c
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */
#include "config_file.h"
#include "list.h"

/**
 * Gets how many template fields are in this record by just looping over all
 * sources and accumulating the number of rules with bytecount > 0 in them (bytecount <= 0 means ignore).
 */
int	get_template_field_count_from_record(record_descriptor* record){
	list_node* cur;
	list_node* cur2;
	int result = 0;

	for(cur=record->sources->first;cur!=NULL;cur=cur->next){
		source_descriptor* cur_source = (source_descriptor*)cur->data;

		for(cur2=cur_source->rules->first;cur2!=NULL;cur2=cur2->next){
			transform_rule* cur_rule = (transform_rule*)cur2->data;
			if(cur_rule->bytecount>0) result++;
		}
	}

	return result;
}


/**
 * Generates the template for a record or multirecord, respectively.
 */
void generate_template_from_record(ipfix_exporter* send_exporter, record_descriptor* record){

	//determine the number of rules in this record/template
	int num_rules = get_template_field_count_from_record(record);

	//Start the template
	//(1 record => 1 template)
	ipfix_start_template(send_exporter, record->template_id, num_rules);

	//Loop over all sources
	list_node* cur;
	for(cur=record->sources->first;cur!=NULL;cur=cur->next){
		source_descriptor* cur_source = (source_descriptor*)cur->data;

		//Loop over all rules
		list_node* cur2;
		for(cur2=cur_source->rules->first;cur2!=NULL;cur2=cur2->next){
			transform_rule* cur_rule = (transform_rule*)cur2->data;

			//Only create a template field if the rule has a positive bytecount
			if(cur_rule->bytecount > 0){
				//build a template field from this rule
				ipfix_put_template_field(send_exporter, record->template_id, cur_rule->ie_id, cur_rule->bytecount, cur_rule->enterprise_id);
			}
		}

	}

	//Finish the template
	ipfix_end_template(send_exporter, record->template_id);
}

/**
 * Generates all templates of all records/multirecords stored in the handed config file descriptor <conf>.
 */
void generate_templates_from_config(ipfix_exporter* send_exporter, config_file_descriptor* conf){
	list_node* cur;
	for(cur=conf->record_descriptors->first;cur!=NULL;cur=cur->next){
		record_descriptor* curRecord = (record_descriptor*)cur->data;
		generate_template_from_record(send_exporter, curRecord);

	}
}

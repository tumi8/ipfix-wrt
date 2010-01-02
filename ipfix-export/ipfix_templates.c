/*
 * ipfix_templates.c
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */
#include "config_file.h"
#include "list.h"

int	get_template_field_count_from_record(record_descriptor* record){
	list_node* cur;
	int result = 0;

	for(cur=record->sources->first;cur!=NULL;cur=cur->next){
		source_descriptor* cur_source = (source_descriptor*)cur->data;
		result += cur_source->rule_count;
	}

	return result;
}

void generate_template_from_record(ipfix_exporter* send_exporter, record_descriptor* record){


	//determine the number of rules in this record/template
	int num_rules = get_template_field_count_from_record(record);

	//Start the template
	//(1 record => 1 template)
	ipfix_start_template_set(send_exporter, record->template_id, num_rules);

	//Loop over all sources
	list_node* cur;
	for(cur=record->sources->first;cur!=NULL;cur=cur->next){
		source_descriptor* cur_source = (source_descriptor*)cur->data;

		//Loop over all rules
		list_node* cur2;
		for(cur2=cur_source->rules->first;cur2!=NULL;cur2=cur2->next){
			transform_rule* cur_rule = (transform_rule*)cur2->data;

			//build a template field from this rule
			ipfix_put_template_field(send_exporter, record->template_id, cur_rule->ie_id, cur_rule->bytecount, cur_rule->enterprise_id);
		}

	}

	//Finish the template
	ipfix_end_template_set(send_exporter, record->template_id);
}

void generate_templates_from_config(ipfix_exporter* send_exporter, config_file_descriptor* conf){
	list_node* cur;
	for(cur=conf->record_descriptors->first;cur!=NULL;cur=cur->next){
		record_descriptor* curRecord = (record_descriptor*)cur->data;

		generate_template_from_record(send_exporter, curRecord);

	}
}

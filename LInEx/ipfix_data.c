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
 * ipfix_handling.c
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */

#include "ipfix_data.h"
#include "load_data.h"
#include "transform_rules.h"
#include "ipfixlolib/ipfixlolib.h"
#include "ipfixlolib/msg.h"

extern int verbose_level;

char send_buffer[SEND_BUFFER_SIZE];
regmatch_t match_buffer[MATCH_BUFFER_SIZE];
int send_buffer_offset = 0;



/*
 *
 * Apply a rule onto the <input> string
 * The transform function in the rule should convert the string as desired and
 * then write it to the buffer pointer that was handed to this transform function.
 * After the transform function was called, the buffer offset pointer will
 * be increased by rule->bytecount such that the pointer again points at the end of the
 * occupied send buffer.
 */

void apply_rule(char* input,transform_rule* rule){

	//Check if buffer is long enough
	if(send_buffer_offset+rule->bytecount>SEND_BUFFER_SIZE){
		fprintf(stderr, "Send buffer overflow! More than %d bytes in the send buffer. Please enlarge the send buffer.\n",SEND_BUFFER_SIZE);
		exit(-1);
	}

	//Apply transform rule
	rule->transform_func(input,send_buffer+send_buffer_offset,rule);

	//Shift buffer offset
	send_buffer_offset+=rule->bytecount;
}

/**
 * Tries to find data in an input and append it to the send buffer.
 *
 * Parameters:
 * input: The input string (for example the content of a /proc file),
 * source: A source descriptor which defines the pattern and rules for the input (obtained from the config file)
 * is_multirecord: true, if this source belongs to a multirecord, false otherwise
 * Returns true (1) if the pattern was found in the input and 0 otherwise.
 */
int source_to_send_buffer(char* input, source_descriptor* source, boolean is_multirecord){

	//Count number of datarecords in the sendbuffer
	int num_datarecords = 0;

	regex_t* reg_ex = &(source->reg_exp_compiled);
	int num_rules = source->rule_count;

	if(verbose_level>=2){
		printf("Processing source \"%s\" (%d rules)\n", source->source_path, source->rule_count);
		if(verbose_level>=4){
			printf("Source content:\n%s\n",input);
		}
	}

	boolean matched;
	do{

		matched = FALSE;
		//Do pattern matching
		if(!regexec(reg_ex, input,num_rules+1, match_buffer, 0)){
			//Successful match!
			matched = TRUE;

			//One more data record in the sendbuffer
			num_datarecords++;

			if(verbose_level>=3) printf("  Found data record (Num:%d):\n", num_datarecords);

			//Iterate over all capturing groups/ rules
			list_node* cur;
			int i=0;
			for(cur=source->rules->first;cur!=NULL;cur=cur->next){
				transform_rule* cur_rule = (transform_rule*)cur->data;

				//Count rules
				i++;

				//Only do something if the rule has positive bytecount (0 == ignore)
				if(cur_rule->bytecount>0){
					//Null terminate the capturing group so that it is recognized as a string.
					//We save the char that was replaced with \0, so we can revert it later
					char swap = input[match_buffer[i].rm_eo]; //save
					input[match_buffer[i].rm_eo]='\0'; //0 terminate

					//Apply the rule! (transforms the content and append it to the send_buffer)
					apply_rule(&input[match_buffer[i].rm_so],cur_rule);

					if(verbose_level>=3) printf("    Field %d (%s, %d byte): \"%s\"\n", i,get_description_by_index(cur_rule->transform_id),cur_rule->bytecount, &input[match_buffer[i].rm_so]);

					//Revert null termination
					input[match_buffer[i].rm_eo] = swap;
				} else {
					//Field ignored, bytecount 0 or less
					if(verbose_level>=3) printf("    Field %d: ignored\n", i);
				}

			}

			//Shift input, so we get the next match
			input = &input[match_buffer[0].rm_eo];

			//Infinite loop protection, if the match was empty (an empty pattern like \\w*) was used, we break
			if(match_buffer[0].rm_eo==0){
				break;
			}


		} else{
			if(verbose_level >= 2){
				if(num_datarecords==0){
					printf("No datarecord found!\n");
				}
			}
		}

	//If this is a multirecord and we found a match, search the next match;
	}while(is_multirecord && matched);

	if(verbose_level >= 2 && num_datarecords > 0){
		printf("--> Found %d datarecords!\n", num_datarecords);
	}
	return num_datarecords;
}

/**
 * Writes zeros into the send buffer for a source
 * This method is called if no valid data was found in the resource
 */
int source_default_to_send_buffer(char* input, source_descriptor* source, boolean is_multirecord){


	//Count number of bytes to set to zero
	int num_bytes = 0;
	list_node* cur;
	for(cur=source->rules->first;cur!=NULL;cur=cur->next){
			transform_rule* curRule = (transform_rule*)cur->data;
			num_bytes += curRule->bytecount;
	}

	//Zero them!
	memset(send_buffer+send_buffer_offset,0,num_bytes);

	//Shift buffer pointer
	send_buffer_offset+=num_bytes;

	//Verbose...
	if(verbose_level>=2)printf("Skipping %d bytes, because no dataset found in source %s!\n",num_bytes, source->source_path);

	return num_bytes;

}


/**
 * Sends the complete sendbuffer to ipfix.
 *
 */
int dump_send_buffer_to_ipfix(ipfix_exporter* exporter, uint16_t template_id, int num_datarecords){
	//printf("dump_send_buffer_to_ipfix called with tid=%u\n", template_id);

	//check if buffer can be divided in data records with the same length
	//If this is not possible, something has gone completely wrong
	//(shouldn't happen at all)
	if(send_buffer_offset % num_datarecords != 0){
		fprintf(stderr, "Buffer length error! This should not happen!\n");
		exit(-1);
	}

	int datarecord_length = send_buffer_offset / num_datarecords;

	int i;
	int ret;
	//loop over all datarecords

	//start
	ret=ipfix_start_data_set(exporter, (uint16_t)htons(template_id));
	if (ret != 0 ) {
		fprintf(stderr, "ipfix_start_data_set failed!\n");
		return ret;
	}

	for(i = 0; i < num_datarecords; i++){

		//** Assemble a dataset **

		//put Data Record
		ipfix_put_data_field(exporter, send_buffer+i*datarecord_length, datarecord_length);
	}

	ret=ipfix_end_data_set(exporter, num_datarecords);

	if (ret != 0){
		fprintf(stderr, "ipfix_end_data_set failed!\n");
		return ret;
	}

	//Send the data
	ret=ipfix_send(exporter);
	if (ret != 0)
		fprintf(stderr, "ipfix_send failed!\n");

	return ret;
}

/**
 * Processes a whole record by reading data from each source
 * in that record, writing it to the send buffer and then handing
 * the send buffer to ipfix.
 */
void record_to_ipfix(ipfix_exporter* exporter, record_descriptor* record){
	//Reset sendbuffer offset
	send_buffer_offset = 0;

	//Count data records
	int num_datarecords = 0;

	//Loop over all sources of this record
	list_node* cur;
	for(cur=record->sources->first;cur!=NULL;cur=cur->next){
		source_descriptor* cur_source = (source_descriptor*)cur->data;

		//Load the data from the source (for example a proc file)
		char* input = load_data_from_source(cur_source);

		//Process the pattern matching, apply the transformation rules
		//and write the result to send buffer
		num_datarecords = source_to_send_buffer(input, cur_source, record->is_multirecord);

		//A source returned 0 data records, we will not send it if it is a multirecord
		//If it is a normal record, we will fill it with zeros.
		if(num_datarecords == 0){
			if(record->is_multirecord){
				if(verbose_level>=1)printf("Skipping multirecord, because no data record found in source %s!\n",cur_source->source_path);
			} else {
				source_default_to_send_buffer(input, cur_source, record->is_multirecord);
			}
		}
	}

	//printf("test %u", num_datarecords);
	//If there were data records created, dump the send buffer to ipfix
	if(num_datarecords > 0){
		dump_send_buffer_to_ipfix(exporter,record->template_id,num_datarecords);
	}
}

/**
 * Takes the parsed content of a config file and tries to send every record that is
 * described in this config file using IPFIX.
 */
void config_to_ipfix(ipfix_exporter* exporter,config_file_descriptor* config){
	list_node* cur;
	for(cur=config->record_descriptors->first;cur!=NULL;cur=cur->next){
		//Loop over all records in this config, process them and dump them to IPFIX
		record_descriptor* cur_record = (record_descriptor*)cur->data;
		record_to_ipfix(exporter, cur_record);
	}
}

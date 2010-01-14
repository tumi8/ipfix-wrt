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
 * Wendet eine regel auf einen inputstring an // Apply a rule to one input string
 * Die Transformfunktion der Regel sollte(!) den String geeignet umwandeln und // The transform funkction of the rule
 * ihn dann an die Position schreiben, die als zweiter Parameter übergeben wurde.
 * Danach schiebt apply_rule den offset um bytecount weiter, sodass der neue offset
 * wieder hinter den belegten Speicher im send_buffer zeigt.
 */
//
void apply_rule(char* input,transform_rule* rule){

	//Check if buffer is long enough
	if(send_buffer_offset+rule->bytecount>SEND_BUFFER_SIZE){
		fprintf(stderr, "Send buffer overflow! More than %d bytes in the send buffer. Please enlarge the send buffer.\n",SEND_BUFFER_SIZE);
		exit(-1);
	}

	//Regel anwenden
	rule->transform_func(input,send_buffer+send_buffer_offset,rule);

	//Offset weiterschieben
	send_buffer_offset+=rule->bytecount;
}

/**
 * Nimmt eine eingabe string <input> (z.B. den Inhalt einer proc Datei)
 * wendet das übergebene pattern <regEx> auf sie an
 * Die ersten <num_rules> matches werden mit den übergebenen <rules>
 * transformiert und in den globalen send_buffer geschrieben.
 * <rules> muss dabei eine Liste aus *transform_rules sein mit (mindestens) <num_rules> Nodes
 * Jede rule aus der Liste wird für eine Capturing Group des Patterns verwendet
 * Soll eine Capturing Group gar nicht gesendet werden, muss einfach an der jeweiligen
 * Stelle im array eine Regel mit .bytecount==0 stehen
 *Die Funktion gibt true zurück, falls die Zeile gematcht werden konnte (Pattern traf zu)
 *ansonsten false
 */
int source_to_send_buffer(char* input, source_descriptor* source, boolean is_multirecord){

	//Count number of datasets in the sendbuffer
	int num_datasets = 0;

	regex_t* regEx = &(source->reg_exp_compiled);
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
		//Mit pattern matchen
		if(!regexec(regEx, input,num_rules+1, match_buffer, 0)){
			//if(verbose_level>=3)printf("%s\n",input);

			matched = TRUE;

			//One more dataset in the sendbuffer
			num_datasets++;

			if(verbose_level>=3) printf("  Found dataset (Num:%d):\n", num_datasets);

			//Über alle Capturing Groups/Rules iterieren
			list_node* cur;
			int i=0;
			for(cur=source->rules->first;cur!=NULL;cur=cur->next){
				transform_rule* curRule = (transform_rule*)cur->data;

				//Count rules
				i++;

				//Nur was tun, wenn die Regel bytecount > 0
				if(curRule->bytecount!=0){

					//Jede Capturing Group erst nullterminieren, dass sie als Eingabestring benutzt werden kann
					//Dabei das durch \0 ersetzte Zeichen merken, dass wir es später wieder tauschen können
					char swap = input[match_buffer[i].rm_eo]; //merken
					input[match_buffer[i].rm_eo]='\0'; //0 terminieren

					//Regel anwenden! (dies transformiert den Inhalt und schreibt ihn in den send_buffer)
					apply_rule(&input[match_buffer[i].rm_so],curRule);

					if(verbose_level>=3) printf("    Field %d (%s, %d byte): \"%s\"\n", i,get_description_by_index(curRule->transform_id),curRule->bytecount, &input[match_buffer[i].rm_so]);

					//Nullterminierung rückgängig machen
					input[match_buffer[i].rm_eo] = swap;
				} else {
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
				if(num_datasets==0){
					printf("No dataset found!\n");

				}
			}
		}

	//If this is a multirecord and we found a match, search the next match;
	}while(is_multirecord && matched);

	if(verbose_level >= 2 && num_datasets > 0){
		printf("--> Found %d datasets!\n", num_datasets);
	}
	return num_datasets;
}

/**
 * Writes zeros into the send buffer for a source
 * This method is called if no valid dataset for the resource is found
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
 * Sendet einfach den kompletten send_buffer als ein Datensatz an ipfix.
 *
 * Diese funktion kann/sollte noch verändert werden, sodass sie mehrere
 * datensätze aufeinmal schicken kann.
 *
 * Bis jetzt wird nämlich nach jedem Datensatz sofort ein send() aufgerufen,
 * was unnötigen Paketoverhead bedeuten könnte.
 *
 */
int dump_send_buffer_to_ipfix(ipfix_exporter* exporter, uint16_t template_n_id, int num_datasets){

	//check if buffer can be divided in datasets with the same length
	//If this is not possible, something has gone completely wrong
	//(shouldn't happen at all)
	if(send_buffer_offset % num_datasets != 0){
		fprintf(stderr, "Buffer length error! This should not happen!\n");
		exit(-1);
	}

	int dataset_length = send_buffer_offset / num_datasets;

	int i;
	int ret;
	//loop over all datasets
	for(i = 0; i < num_datasets; i++){

		//** Assemble a dataset **

		//start
		ret=ipfix_start_data_set(exporter, template_n_id);

		if (ret != 0 ) {
			fprintf(stderr, "ipfix_start_data_set failed!\n");
			return ret;
		}

		//put and end
		ipfix_put_data_field(exporter, send_buffer+i*dataset_length, dataset_length);
		ret=ipfix_end_data_set(exporter, 1);

		if (ret != 0){
			fprintf(stderr, "ipfix_end_data_set failed!\n");
			return ret;
		}

	}

	//Send the data
	ret=ipfix_send(exporter);
	if (ret != 0)
		fprintf(stderr, "ipfix_send failed!\n");

	return ret;
}

void record_to_ipfix(ipfix_exporter* exporter, record_descriptor* record){
	//Reset sendbuffer offset
	send_buffer_offset = 0;

	//Count data sets
	int num_datasets = 0;

	//Loop over all sources of this record
	list_node* cur;
	for(cur=record->sources->first;cur!=NULL;cur=cur->next){
		source_descriptor* cur_source = (source_descriptor*)cur->data;

		//Load the data from the source (for example a proc file)
		char* input = load_data_from_source(cur_source);

		//Process the pattern matching, apply the transformation rules
		//and write the result to send buffer
		num_datasets = source_to_send_buffer(input, cur_source, record->is_multirecord);

		//A source returned 0 datasets, we will not send it if it is a multirecord
		//If it is a normal record, we will fill it with zeros.
		if(num_datasets == 0){
			if(record->is_multirecord){
				if(verbose_level>=1)printf("Skipping multirecord, because no dataset found in source %s!\n",cur_source->source_path);
			} else {
				source_default_to_send_buffer(input, cur_source, record->is_multirecord);
			}
		}
	}

	//If there were datasets created, dump the send buffer to ipfix
	if(num_datasets > 0){
		dump_send_buffer_to_ipfix(exporter,record->template_id,num_datasets);
	}
}

void config_to_ipfix(ipfix_exporter* exporter,config_file_descriptor* config){
	list_node* cur;
	for(cur=config->record_descriptors->first;cur!=NULL;cur=cur->next){
		record_descriptor* cur_record = (record_descriptor*)cur->data;
		record_to_ipfix(exporter, cur_record);
	}
}

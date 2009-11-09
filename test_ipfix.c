#include <stdio.h>
#include "ipfixlolib/ipfixlolib.h"
#include "ipfixlolib/msg.h"
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>

//Variablen für die größe der einzelnen sendefenster/buffer
#define SEND_BUFFER_SIZE 1024
#define MATCH_BUFFER_SIZE 15
#define MAX_LINE_LENGTH 512

char send_buffer[SEND_BUFFER_SIZE];
regmatch_t match_buffer[MATCH_BUFFER_SIZE];
int send_buffer_offset = 0;
ipfix_exporter *send_exporter;
uint16_t my_template_id = 12345;

/*
 * Das zentrale rule struct beschreibt die Regel zur Umwandlung einer Capturing
 * Group:
 * Der bytecount gibt an wieviel byte der wert nach der konvertierung im sendbuffer belegen wird
 * transform muss eine funktion sein, die die eingabe (char*) und den sendbuffer (void*)
 * erhält, die eingabe geeignet konvertiert (z.B. in int umwandeln, networkbyteorder konvertierungen usw)
 * und dann in den übergebenen buffer schreibt.
 *
 * Dabei ist zu beachten, dass die funktion nicht mehr bytes schreiben sollte, als
 * im bytecount angegeben sind.
 */
typedef struct {
	uint16_t bytecount;
	void (*transform)(char* input,void* target_buffer, transform_rule* rule);
	uint16_t type;
	uint32_t enterprise_id;
} transform_rule;

/******* IMPLEMENTIERTE REGELN ***********/
/**
 * Hier sind einige Beispielregeln implementiert.
 * Zuerst muss jeweils die Transformationsfunktion definiert werden
 * welche dann im struct als Pointer referenziert werden kann.
 */

//Transformation in 4 byte signed int
void transform_int(char* input, void* buffer, transform_rule* rule){
	int i = atoi(input);
	(*(int*)buffer) = i;
}

transform_rule rule_ip_source = {4,&transform_int,}; //Transformiert in 4 byte int per atoi
transform_rule rule_ignore = {0,0,0,0}; //Ignoriert diesen wert


//transform_rule rule_dst_ip = {1,&transform_dst_ip};

/******* IMPLEMENTIERTE REGELN ENDE ******/

void rules_to_template(uint16_t template_n_id,transform_rule* rules, int num_rules){

	ipfix_start_template_set(send_exporter, template_n_id, num_rules);
	for(int i=0;i<num_rules;i++){
		//Skip rules with bytecount 0
		if(rules[i].bytecount == 0) continue;

		ipfix_put_template_field(send_exporter, template_n_id, rules[i].type, rules[i].bytecount, rules[i].enterprise_id);
	}
	ipfix_end_template_set(send_exporter, template_n_id);


}
//Wendet eine regel auf einen inputstring an
//Die Transformfunktion der Regel sollte(!) den String geeignet umwandeln und
//ihn dann an die Position schreiben, die als zweiter Parameter übergeben wurde.
//Danach schiebt apply_rule den offset um bytecount weiter, sodass der neue offset
//wieder hinter den belegten Speicher im send_buffer zeigt.
void apply_rule(char* input,transform_rule* rule){

	//Regel anwenden
	rule->transform(input,send_buffer+send_buffer_offset,rule);

	//Offset weiterschieben
	send_buffer_offset+=rule->bytecount;
}

//Nimmt eine line <input> (z.B. aus einer proc datei)
//wendet das übergebene pattern <regEx> auf sie an
//Die ersten <num_rules> matches werden mit den übergebenen <rules>
//transformiert und in den globalen send_buffer geschrieben.
//<rules> muss dabei ein array aus *transform_rules sein mit (mindestens) <num_rules> Einträgen
//Jede rule aus dem array wird für eine Capturing Group des Patterns verwendet
//Soll eine Capturing Group gar nicht gesendet werden, muss einfach an der jeweiligen
//Stelle im array eine Regel mit .bytecount==0 stehen
//Die Funktion gibt true zurück, falls die Zeile gematcht werden konnte (Pattern traf zu)
//ansonsten false
int line_to_send_buffer(char* input, regex_t* regEx,transform_rule* rules, int num_rules){

	//Sendbuffer offset resetten
	send_buffer_offset = 0;

	//Mit pattern matchen
	if(!regexec(regEx, input,num_rules+1, match_buffer, 0)){
		printf("%s\n",input);
		//Über alle Capturing Groups/Rules iterieren
		int i;
		for(i=1; i <= num_rules; i++){

			//Nur was tun, wenn die Regel bytecount > 0
			if(rules[i-1].bytecount!=0){

				//Jede Capturing Group erst nullterminieren, dass sie als Eingabestring benutzt werden kann
				//Dabei das durch \0 ersetzte Zeichen merken, dass wir es später wieder tauschen können
				char swap = input[match_buffer[i].rm_eo]; //merken
				input[match_buffer[i].rm_eo]='\0'; //0 terminieren

				//Regel anwenden! (dies transformiert den Inhalt und schreibt ihn in den send_buffer)
				apply_rule(&input[match_buffer[i].rm_so],&rules[i-1]);

				//Nullterminierung rückgängig machen
				input[match_buffer[i].rm_eo] = swap;
			}

		}

		return 1;
	}

	return 0;
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
int dump_buffer_to_ipfix(uint16_t template_n_id){

	int ret=ipfix_start_data_set(send_exporter, template_n_id);

	if (ret != 0 ) {
		fprintf(stderr, "ipfix_start_data_set failed!\n");
	} else {
		ipfix_put_data_field(send_exporter, send_buffer, send_buffer_offset);
		ret=ipfix_end_data_set(send_exporter, 1);

		if (ret != 0)
		fprintf(stderr, "ipfix_end_data_set failed!\n");
		ret=ipfix_send(send_exporter);
		if (ret != 0)
			fprintf(stderr, "ipfix_send failed!\n");

	}
	return ret;
}

/*
 * Sendet den Inhalt eines (proc)files an ipfix
 *
 * ACHTUNG: noch kein template Handling implementiert! *
 * Bis jetzt wird immer mit template id 0 gesendet, was nicht klappen sollte ;)
 */
void file_to_ipfix(char* filename,regex_t* regEx,transform_rule* rules, int num_rules){
	//File öffnen und checken obs alles geklappt hat
	FILE* fp = fopen(filename, "r");
	if (fp == NULL){
		fprintf(stderr, "Reading from /proc-System failed!\n");
		exit(-1);
	}
	//Lines durchgehen, matchen und verschicken
	int in_line;
	char curr_line[MAX_LINE_LENGTH];
	for (in_line = 0; fgets(curr_line, MAX_LINE_LENGTH, fp) != NULL; in_line++){

		//Falls line dem pattern genügt wird sie in den send_buffer kopiert und kann
		//per ipfix verschickt werden
		if(line_to_send_buffer(curr_line,regEx,rules,num_rules)){

			//Buffer per ipfix versenden
			/* ACHTUNG: GEHT NOCH NICHT, DA KEINE TEMPLATES DEFINIERT WURDEN
			 * FÜR DIE 0 DANN DIE TEMPLATE ID ÜBERGEBEN */
			dump_buffer_to_ipfix(my_template_id);
		}

	}
}

/**
 * Test main methode
 */
#define MY_SOURCE_ID 70538
int main(int argc, char **argv)
{
	int ret =0;
	char *collector_ip = "127.0.0.1";
	int collector_port = 1500;

	//Init test exporter
	ret=ipfix_init_exporter(MY_SOURCE_ID, &send_exporter);

	if (ret != 0) {
		fprintf(stderr, "ipfix_init_exporter failed!\n");
		exit(-1);
	}

	//test collector hinzufügen
	ret = ipfix_add_collector(send_exporter, collector_ip, collector_port, UDP);
	printf("ipfix_add_collector returned %i\n", ret);

	//Test pattern und rules erstellen
	regex_t regEx;
	regcomp(&regEx,"(\\w+)\\s+([0-9]+)\\s+(\\w+)\\s+([0-9]+)\\s+([0-9]+)\\s+(\\w*)\\s*src\\=([\\.0-9]+)",REG_EXTENDED);

	//Es werden erstmal nur für die ersten 4 capturing groups regeln erstellt
	//die erste und dritte wird ignoriert (null regel)
	//die zweite und vierte wird in 4 byte signed int umgewandelt
	transform_rule ex_rules[10];
	ex_rules[0] = rule_null;
	ex_rules[1] = rule_int;
	ex_rules[2] = rule_null;
	ex_rules[3] = rule_int;

	//Testen mit test file
	file_to_ipfix("./test_data",&regEx,ex_rules,4);
	return 0;
}








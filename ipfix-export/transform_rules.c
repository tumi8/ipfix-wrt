/*
 * transform_rules.c
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#include "transform_rules.h"

transform_func get_rule_by_index(unsigned int index){
	return NULL;
}

/******************** Concrete transform rules **************/
//Transformation in 4 byte signed int
void transform_int(char* input, void* buffer, transform_rule* rule){
	int i = htons(atoi(input));
	(*(int*)buffer) = i;
    // der Int-Wert soll in der Adresse gespeichert werden, wo der Zeiger zeigt..
	//(int*)buffer -> es muss angegeben werden, was für Daten in dem Buffer gespeichert werden
}
void transform_ip(char* input, void* buffer, transform_rule* rule){
	struct in_addr addr;
	if(!inet_aton(input,&addr)){
		//Fehlerbehandlung falls invalide ip übergeben wurde
		fprintf(stderr, "convert failed!");
	}
	uint32_t ip_addr = htonl(addr.s_addr);
	(*(uint32_t*)buffer)= ip_addr;
}
//siehe
/* Internet address.  */
//typedef uint32_t in_addr_t;
//struct in_addr
//  {
//	 in_addr_t s_addr;
//	};

void transform_mac_address(char* input, void* buffer, transform_rule* rule){
 	memcpy(buffer,input,17);
}

void transform_port(char* input, void* buffer, transform_rule* rule){
	uint16_t dst_port = htons(atoi(input));
	(*(uint16_t*)buffer)= dst_port;
}

transform_rule rule_src_ip = {4,&transform_ip,IPFIX_TYPEID_sourceIPv4Address,0};
transform_rule rule_sMacAddress = {4,&transform_mac_address, IPFIX_TYPEID_sourceMacAddress,0};
transform_rule rule_udp_src_port = {4,&transform_port,IPFIX_TYPEID_udpSourcePort,0};
transform_rule rule_ignore = {0,0,0,0}; //Ignoriert diesen wert

//transfocorerm_rule rule_string = {1,&transform_string};
//transform_rule rule_ip = {1,&transform_ip};

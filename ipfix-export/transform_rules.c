/*
 * transform_rules.c
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#include "transform_rules.h"

/******************** Concrete transform rules **************/

/**
 * Transform rule for transforming a 4 byte signed int
 */
void transform_int(char* input, void* buffer, transform_rule* rule){
	int i = htonl(atoi(input));
	(*(int*)buffer) = i;
    // der Int-Wert soll in der Adresse gespeichert werden, wo der Zeiger zeigt..
	//(int*)buffer -> es muss angegeben werden, was für Daten in dem Buffer gespeichert werden
}


/**
 * Transform rule for transforming a float value
 */
void transform_float(char* input, void* buffer, transform_rule* rule){
	// atof should provide "network byte order" of IEEE float
	float f = (float)atof(input);
	(*(float*)buffer) = f;
}

/**
 * Transform rule for transforming a double value
 */
void transform_double(char* input, void* buffer, transform_rule* rule){
	double f = atof(input);
	(*(double*)buffer) = f;
}

/*
 * Transform rule for transforming a percentage value
 */
void transform_percent(char* input, void* buffer, transform_rule* rule){
	float f = (float)atof(input);
	(*(float*)buffer) = f*0.01;
}

//Will always be a 0 terminated string, so the bytecount
//should be string length + 1 at least.
//If the string is shorter, the field will be padded with zeros
void transform_string(char* input, void* buffer, transform_rule* rule){
	strncpy((char*)buffer,input,rule->bytecount-1);
	buffer = buffer + (rule->bytecount-1);
	(*(char*)buffer) = '\0';
}

/**
 * Transform rule for transforming an ip address
 */
void transform_ip(char* input, void* buffer, transform_rule* rule){
	struct in_addr addr;
	if(!inet_aton(input,&addr)){
		//Fehlerbehandlung falls invalide ip übergeben wurde
		fprintf(stderr, "convert failed!");
	}
	uint32_t ip_addr = htonl(addr.s_addr);
	(*(uint32_t*)buffer)= ip_addr;
}



/**
 * Transform rule for transforming a mac address (it is transmitted as string)
 */
void transform_mac_address(char* input, void* buffer, transform_rule* rule){
 	memcpy(buffer,input,17);
}

/**
 * Transform rule for transforming a port
 */
void transform_port(char* input, void* buffer, transform_rule* rule){
	uint16_t dst_port = htons(atoi(input));
	(*(uint16_t*)buffer)= dst_port;
}

/******************** Transform rule selection functions **************/

/**
 * Returns a pointer to a transform function, specified by its <index>
 */
transform_func get_rule_by_index(unsigned int index){
	switch(index){
		case 0:	return NULL;
		case 1:	return transform_int;
		case 2: return transform_string;
		case 3:	return transform_ip;
		case 4:	return transform_mac_address;
		case 5: return transform_float;
		case 6: return transform_double;
		case 7: return transform_percent;

	}
	return NULL;
}

/**
 * Gets the description for a rule, by index.
 * For verbose messages only.
 */
char* get_description_by_index(unsigned int index){
	switch(index){
		case 0:	return "ignore";
		case 1:	return "int";
		case 2: return "string";
		case 3:	return "ip addr";
		case 4:	return "mac addr";
		case 5: return "float";
		case 6: return "double";
		case 7: return "percent";

	}
	return "unknown";
}


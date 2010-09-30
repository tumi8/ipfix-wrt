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
 * transform_rules.c
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#include "transform_rules.h"

/******************** Concrete transform rules **************/

/**
 * Transform rule for transforming a 2 or 4 byte signed int
 */
void transform_int(char* input, void* buffer, transform_rule* rule){
	if(rule->bytecount == 2) {
		int16_t i = htons(atoi(input));
		(*(int16_t*)buffer) = i;
	} else if(rule->bytecount == 4) {
		int32_t i = htonl(atoi(input));
		(*(int32_t*)buffer) = i;
	} else {
		fprintf(stderr, "transform_int: invalid length!\n");
	}
}


/**
 * Transform rule for transforming a 2 or 4 byte unsigned int
 */
void transform_uint(char* input, void* buffer, transform_rule* rule){
	if(rule->bytecount == 2) {
		uint16_t i = htons(atoi(input));
		(*(uint16_t*)buffer) = i;
	} else if(rule->bytecount == 4) {
		uint32_t i = htonl(atoi(input));
		(*(uint32_t*)buffer) = i;
	} else {
		fprintf(stderr, "transform_uint: invalid length!\n");
	}
}


/**
 * Transform rule for transforming a float value
 */
void transform_float(char* input, void* buffer, transform_rule* rule){
	// atof should provide "network byte order" of IEEE float
	if(rule->bytecount == 4) {
		float f = (float)atof(input);
		(*(float*)buffer) = f;
	} else if(rule->bytecount == 8) {
		double f = atof(input);
		(*(double*)buffer) = f;
	} else {
		fprintf(stderr, "transform_float: invalid length!\n");
	}
}


/*
 * Transform rule for transforming a percentage value
 */
void transform_percent(char* input, void* buffer, transform_rule* rule){
	if(rule->bytecount != 2) {
		fprintf(stderr, "transform_percent: invalid length!\n");
		return;
	}
	int16_t i = htons((int16_t)(atof(input)*100));
	(*(int16_t*)buffer) = i;
}


//Will always be a 0 terminated string, so the bytecount
//should be string length + 1 at least.
//If the string is shorter, the field will be padded with zeros
void transform_string(char* input, void* buffer, transform_rule* rule){
	if(rule->bytecount < 2) {
		fprintf(stderr, "transform_string: invalid length!\n");
		return;
	}
	strncpy((char*)buffer,input,rule->bytecount-1);
	buffer = buffer + (rule->bytecount-1);
	(*(char*)buffer) = '\0';
}

/**
 * Transform rule for transforming an ip address
 */
void transform_ip(char* input, void* buffer, transform_rule* rule){
	if(rule->bytecount != 4) {
		fprintf(stderr, "transform_ip: invalid length!\n");
		return;
	}
	struct in_addr addr;
	if(!inet_aton(input,&addr)){
		fprintf(stderr, "convert failed!\n");
	}
	uint32_t ip_addr = htonl(addr.s_addr);
	(*(uint32_t*)buffer)= ip_addr;
}

/**
 * Transform rule for transforming a mac address (it is transmitted as string)
 */
void transform_mac_address(char* input, void* buffer, transform_rule* rule){
	if(rule->bytecount != 6) {
		fprintf(stderr, "transform_mac_address: invalid length!\n");
		return;
	}
	int i;
	for (i = 0; i < 6; i++)
	{
		long b = strtol(input+(3*i), (char **) NULL, 16);
		((char*)buffer)[i] = (char)b;
	}
}


/******************** Transform rule selection functions **************/

/**
 * Returns a pointer to a transform function, specified by its <index>
 * Exits if bytecount does not work with given transform function
 */
transform_func get_rule_by_index(unsigned int index, uint16_t bytecount){
	switch(index){
		case 0:	return NULL;
		case 1:	if((bytecount != 2) && (bytecount != 4)) {
				fprintf(stderr, "transform 1 (int) requires field length 2 or 4!\n");
				exit(-1);
			}
			return transform_int;
		case 2:	if((bytecount != 2) && (bytecount != 4)) {
				fprintf(stderr, "transform 2 (unsigned) requires field length 2 or 4!\n");
				exit(-1);
			}
			return transform_uint;
		case 3:	if(bytecount != 4) {
				fprintf(stderr, "transform 3 (IPv4) requires field length 4!\n");
				exit(-1);
			}
			return transform_ip;
		case 4:	if(bytecount != 6) {
				fprintf(stderr, "transform 4 (mac) requires field length 6!\n");
				exit(-1);
			}
			return transform_mac_address;
		case 5: if((bytecount != 4) && (bytecount != 8)) {
				fprintf(stderr, "transform 5 (float) requires field length 4 or 8!\n");
				exit(-1);
			}
			return transform_float;
		case 6: if(bytecount != 2) {
				fprintf(stderr, "transform 6 (percent) requires field length 2!\n");
				exit(-1);
			}
			return transform_percent;
		case 7: if(bytecount < 2) {
				fprintf(stderr, "transform 7 (string) requires field length >=2!\n");
				exit(-1);
			}
			return transform_string;

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
		case 2:	return "uint";
		case 3:	return "ip addr";
		case 4:	return "mac addr";
		case 5: return "float/double";
		case 6: return "percent";
		case 7: return "string";
	}
	return "unknown";
}


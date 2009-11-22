/*
 * core.h
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#ifndef CORE_H_
#define CORE_H_
#include <stdio.h>
#include "ipfixlolib/ipfixlolib.h"
#include "ipfixlolib/ipfix.h"
#include "ipfixlolib/msg.h"
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//Variablen für die größe der einzelnen sendefenster/buffer
#define SEND_BUFFER_SIZE 1024
#define MATCH_BUFFER_SIZE 15
#define MAX_LINE_LENGTH 512
#define MY_SOURCE_ID 70538


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


typedef struct tr_rule {
	uint16_t bytecount;
	void (*transform)(char* input,void* target_buffer, struct tr_rule* rule);
	uint16_t ie_id;
	uint32_t enterprise_id;
} transform_rule;

typedef void (*transform_func) (char* input,void* target_buffer, struct tr_rule* rule);





#endif /* CORE_H_ */

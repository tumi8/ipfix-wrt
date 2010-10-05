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
 * load_data.c
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */

#include "load_data.h"
char input_buffer[INPUT_BUFFER_SIZE];

/**
 * Loads the output of a command line command to the input buffer and returns a pointer to it
 */
char* load_command(char* command){


	//Open file and check if it succeeded
	FILE* fp = popen(command, "r");
	if (fp == NULL){
		msg(MSG_FATAL, "Executing command \"%s\" failed!",command);
		return NULL;
	}
	//Read the content
	int bytes_read = fread (input_buffer, 1, sizeof(char) * INPUT_BUFFER_SIZE -1, fp);

	//If the content doesn't fit into the buffer, give a warning
	if(bytes_read == sizeof(char) * INPUT_BUFFER_SIZE-1){
		msg(MSG_ERROR, "Warning: Command \"%s\"'s output is larger than the buffer's size (%d)!", command,bytes_read);
	}


	//Null terminate
	input_buffer[bytes_read] = '\0';

	//Close the file handle
	fclose(fp);
	return input_buffer;

}
/**
 * Loads a file into the input buffer and returns a pointer to it
 */
char* load_file(char* filename){
	//Open file and check if it succeeded
	FILE* fp = fopen(filename, "r");
	if (fp == NULL){
		msg(MSG_FATAL, "Reading file \"%s\" failed!", filename);
		return NULL;
	}
	//Read the content
	int bytes_read = fread (input_buffer, 1, sizeof(char) * INPUT_BUFFER_SIZE -1, fp);

	//If the content doesn't fit into the buffer, give a warning
	if(bytes_read == sizeof(char) * INPUT_BUFFER_SIZE-1){
		msg(MSG_ERROR, "Warning: File \"%s\"'s content is larger than the buffer's size (%d)!", filename,bytes_read);
	}

	//Null terminate
	input_buffer[bytes_read] = '\0';

	//Close the file handle
	fclose(fp);
	return input_buffer;
}


/**
 * Loads data from the <source>. The function determines
 * if the source is a file or command and calls the appropriate function.
 */
char* load_data_from_source(source_descriptor* source){
	switch(source->source_type){
		case SOURCE_TYPE_FILE:
			return load_file(source->source_path);
		break;

		case SOURCE_TYPE_COMMAND:
			return load_command(source->source_path);
		break;
	}

	return NULL;
}

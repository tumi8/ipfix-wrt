/*
 * load_data.c
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */

#include "load_data.h"
char input_buffer[INPUT_BUFFER_SIZE];

char* load_command(char* command){
	//Open file and check if it succeeded
	FILE* fp = popen(command, "r");
	if (fp == NULL){
		fprintf(stderr, "Executing command \"%s\" failed!\n", command);
		exit(-1);
	}

	//Read the content
	int bytes_read = fread (input_buffer, sizeof(char) * INPUT_BUFFER_SIZE -1, 1, fp);

	//If the content doesn't fit into the buffer, give a warning
	if(bytes_read == sizeof(char) * INPUT_BUFFER_SIZE-1){
		fprintf(stderr, "Warning: Command \"%s\"'s output is larger than the buffer's size (%d)!\n", command,bytes_read);
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
		fprintf(stderr, "Reading file \"%s\" failed!\n", filename);
		exit(-1);
	}

	//Read the content
	int bytes_read = fread (input_buffer, sizeof(char) * INPUT_BUFFER_SIZE -1, 1, fp);

	//If the content doesn't fit into the buffer, give a warning
	if(bytes_read == sizeof(char) * INPUT_BUFFER_SIZE-1){
		fprintf(stderr, "Warning: File \"%s\"'s content is larger than the buffer's size (%d)!\n", filename,bytes_read);
	}

	//Null terminate
	input_buffer[bytes_read] = '\0';

	//Close the file handle
	fclose(fp);
	return input_buffer;
}



char* load_data_from_source(source_descriptor* source){
	switch(source->source_type){
		case SOURCE_TYPE_FILE:
			load_file(source->source_path);
		break;

		case SOURCE_TYPE_COMMAND:
			load_command(source->source_path);
		break;
	}

	return input_buffer;
}

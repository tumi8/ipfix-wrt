/*
 * load_data.h
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */

#ifndef LOAD_DATA_H_
#define LOAD_DATA_H_

#include <stdio.h>
#include "core.h"

/**
 * Loads data from the <source>. The function determines
 * if the source is a file or command and calls the appropriate function.
 */
char* load_data_from_source(source_descriptor* source);

#endif /* LOAD_DATA_H_ */

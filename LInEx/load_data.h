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

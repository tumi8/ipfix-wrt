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
 * ipfix_data.h
 *
 *  Created on: 13.12.2009
 *      Author: kami
 */

#ifndef IPFIX_HANDLING_H_
#define IPFIX_HANDLING_H_
#include <stddef.h>
#include <regex.h>
#include "core.h"

/**
 * Takes the parsed content of a config file and tries to send every record that is
 * described in this config file using IPFIX.
 */
void config_to_ipfix(ipfix_exporter* exporter,config_file_descriptor* config);

#endif /* IPFIX_DATA_H_ */

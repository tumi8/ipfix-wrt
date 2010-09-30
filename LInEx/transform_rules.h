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
 * transform_rules.h
 *
 *  Created on: 22.11.2009
 *      Author: kami
 */

#ifndef TRANSFORM_RULES_H_
#define TRANSFORM_RULES_H_


#include "core.h"

/**
 * Returns a pointer to a transform function, specified by its <index>
 */
transform_func get_rule_by_index(unsigned int index, uint16_t bytecount);

/**
 * Gets the description for a rule, by index.
 * For verbose messages only.
 */
char* get_description_by_index(unsigned int index);

#endif /* TRANSFORM_RULES_H_ */

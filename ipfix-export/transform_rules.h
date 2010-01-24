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
transform_func get_rule_by_index(unsigned int index);

/**
 * Gets the description for a rule, by index.
 * For verbose messages only.
 */
char* get_description_by_index(unsigned int index);

#endif /* TRANSFORM_RULES_H_ */

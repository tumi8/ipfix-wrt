#include <stdio.h>
#include <stdlib.h>
#include "test_ipfix.c"
/*
void transform_int(char* input, void* buffer){
	int i = atoi(input);
	(*(int*)buffer) = i;
}

transform_rule rule_int = {4,&transform_int};
transform_rule rule_null = {0,0};

int main(int argc, char **argv)
{

regex_t regEx;
regcomp(&regEx,"(\\w+)\\s+([0-9]+)\\s+(\\w+)\\s+([0-9]+)\\s+([0-9]+)\\s+(\\w*)\\s*src\\=([\\.0-9]+)",REG_EXTENDED);

transform_rule exRules[10];
exRules[0] = rule_null;
exRules[1] = rule_int;
exRules[2] = rule_null;
exRules[3] = rule_int;



file_to_ipfix("/home/kami/test-tx",&regEx,exRules,4);
	return 0;
}*/

/**
  * Implementation of the CryptoPAN algorithm in C. Heavily based on
  * http://www.cc.gatech.edu/computing/Telecomm/projects/cryptopan/
  */
#ifndef CRYPTOPAN_H_
#define CRYPTOPAN_H_
#include "aes.h"
#include <stdint.h>

struct cryptopan {
	aes_context ctx;
	uint8_t pad[16];
};

int init_cryptopan(struct cryptopan *state, uint8_t key[16], uint8_t pad[16]);
uint32_t anonymize_ipv4(struct cryptopan *state, uint32_t addr);
#endif

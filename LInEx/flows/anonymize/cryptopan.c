#include "cryptopan.h"

int init_cryptopan(struct cryptopan *state, uint8_t key[16], uint8_t pad[16]) {
	if (aes_setkey_enc(&state->ctx, key, 128))
		return -1;

	aes_crypt_ecb(&state->ctx, AES_ENCRYPT, pad, state->pad);
	state->initialised = 1;
	return 0;
}

uint32_t anonymize_ipv4(struct cryptopan *state, uint32_t addr) {
	uint8_t rin_output[16];
	uint8_t rin_input[16];

	uint32_t result = 0;
	uint32_t first4bytes_pad, first4bytes_input;
	int pos;

	uint8_t *pad = state->pad;
	memcpy(rin_input, pad, 16);
	first4bytes_pad = (((uint32_t) pad[0]) << 24) + (((uint32_t) pad[1]) << 16) +
			(((uint32_t) pad[2]) << 8) + (uint32_t) pad[3];

	// For each prefixes with length from 0 to 31, generate a bit using the Rijndael cipher,
	// which is used as a pseudorandom function here. The bits generated in every rounds
	// are combineed into a pseudorandom one-time-pad.
	for (pos = 0; pos <= 31 ; pos++) {

		//Padding: The most significant pos bits are taken from orig_addr. The other 128-pos
		//bits are taken from pad. The variables first4bytes_pad and first4bytes_input are used
		//to handle the annoying byte order problem.
		if (pos==0) {
			first4bytes_input =  first4bytes_pad;
		}
		else {
			first4bytes_input = ((addr >> (32-pos)) << (32-pos)) | ((first4bytes_pad<<pos) >> pos);
		}
		rin_input[0] = (uint8_t) (first4bytes_input >> 24);
		rin_input[1] = (uint8_t) ((first4bytes_input << 8) >> 24);
		rin_input[2] = (uint8_t) ((first4bytes_input << 16) >> 24);
		rin_input[3] = (uint8_t) ((first4bytes_input << 24) >> 24);

		//Encryption: The Rijndael cipher is used as pseudorandom function. During each
		//round, only the first bit of rin_output is used.
		aes_crypt_ecb(&state->ctx, AES_ENCRYPT, rin_input, rin_output);

		//Combination: the bits are combined into a pseudorandom one-time-pad
		result |=  (rin_output[0] >> 7) << (31-pos);
	}
	//XOR the orginal address with the pseudorandom one-time-pad
	return result ^ addr;
}

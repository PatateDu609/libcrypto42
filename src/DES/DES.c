#include "cipher.h"
#include "internal.h"

/**
 * @brief Process the input block with the permutation tables.
 *
 * @param block The block to process.
 * @param init true if the block should be permuted with the initial permutation, false otherwise.
 * @return The permuted block.
 */
static uint64_t process_input(uint64_t block, bool init) {
	const uint8_t initial_perm_table[64] = {
		58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,  62, 54, 46, 38, 30, 22,
		14, 6,  64, 56, 48, 40, 32, 24, 16, 8,  57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35,
		27, 19, 11, 3,  61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7,
	};

	const uint8_t final_perm_table[64] = {
		40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55, 23, 63, 31, 38, 6,  46, 14, 54, 22,
		62, 30, 37, 5,  45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60, 28, 35, 3,  43, 11,
		51, 19, 59, 27, 34, 2,  42, 10, 50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25,
	};

	return permute(block, 64, init ? initial_perm_table : final_perm_table, 64);
}

union converter {
	uint64_t u64;
	uint8_t  u8_8[8];
};

uint8_t *des_encrypt(uint8_t *block, const uint8_t *key) {
	union converter conv_block, conv_key;
	memcpy(conv_block.u8_8, block, sizeof conv_block.u8_8);
	memcpy(conv_key.u8_8, key, sizeof conv_key.u8_8);

	conv_block.u64 = bswap_64(conv_block.u64);
	conv_key.u64   = bswap_64(conv_key.u64);

	conv_block.u64 = process_input(conv_block.u64, true);
	uint64_t subkeys[NB_ROUNDS];
	key_schedule(conv_key.u64, subkeys);

	uint32_t left, right;
	left  = conv_block.u64 >> 32;
	right = conv_block.u64;
	for (int i = 0; i < NB_ROUNDS; i++)
		feistel(subkeys[i], &left, &right);

	// Concatenate backward
	conv_block.u64 = ((uint64_t) right) << 32 | left;
	conv_block.u64 = process_input(conv_block.u64, false);

	conv_block.u64 = bswap_64(conv_block.u64);
	uint8_t *res   = calloc(sizeof conv_block.u8_8, sizeof *res);
	if (!res)
		return NULL;
	memcpy(res, conv_block.u8_8, sizeof conv_block.u8_8);
	return res;
}

uint8_t *des_decrypt(uint8_t *block, const uint8_t *key) {
	union converter conv_block, conv_key;
	memcpy(conv_block.u8_8, block, sizeof conv_block.u8_8);
	memcpy(conv_key.u8_8, key, sizeof conv_key.u8_8);

	conv_block.u64 = bswap_64(conv_block.u64);
	conv_key.u64   = bswap_64(conv_key.u64);

	conv_block.u64 = process_input(conv_block.u64, true);
	uint64_t subkeys[NB_ROUNDS];
	key_schedule(conv_key.u64, subkeys);

	uint32_t left, right;
	left  = conv_block.u64;
	right = conv_block.u64 >> 32;
	for (int i = 0; i < NB_ROUNDS; i++)
		feistel(subkeys[NB_ROUNDS - i - 1], &right, &left);

	conv_block.u64 = ((uint64_t) left) << 32 | right;
	conv_block.u64 = process_input(conv_block.u64, false);

	conv_block.u64 = bswap_64(conv_block.u64);
	uint8_t *res   = calloc(sizeof conv_block.u8_8, sizeof *res);
	if (!res)
		return NULL;
	memcpy(res, conv_block.u8_8, sizeof conv_block.u8_8);
	return res;
}

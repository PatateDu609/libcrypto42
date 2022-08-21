/**
 * @file DES.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief DES implementation
 * @date 2022-08-13
 */

#include "cipher.h"
#include "internal.h"

/**
 * @brief Process the input block with the permutation tables.
 *
 * @param block The block to process.
 * @param init true if the block should be permuted with the initial permutation, false otherwise.
 * @return The permuted block.
 */
static uint64_t process_input(uint64_t block, bool init)
{
	const uint8_t initial_perm_table[64] = {
		58,		50,		42,		34,		26,		18,		10,		2,
		60,		52,		44,		36,		28,		20,		12,		4,
		62,		54,		46,		38,		30,		22,		14,		6,
		64,		56,		48,		40,		32,		24,		16,		8,
		57,		49,		41,		33,		25,		17,		9,		1,
		59,		51,		43,		35,		27,		19,		11,		3,
		61,		53,		45,		37,		29,		21,		13,		5,
		63,		55,		47,		39,		31,		23,		15,		7,
	};

	const uint8_t final_perm_table[64] = {
		40,		8,		48,		16,		56,		24,		64,		32,
		39,		7,		47,		15,		55,		23,		63,		31,
		38,		6,		46,		14,		54,		22,		62,		30,
		37,		5,		45,		13,		53,		21,		61,		29,
		36,		4,		44,		12,		52,		20,		60,		28,
		35,		3,		43,		11,		51,		19,		59,		27,
		34,		2,		42,		10,		50,		18,		58,		26,
		33,		1,		41,		9,		49,		17,		57,		25,
	};

	return permute(block, 64, init ? initial_perm_table : final_perm_table, 64);
}

uint64_t des_encrypt(uint64_t block, uint64_t key)
{
	block = process_input(block, true);
	uint64_t subkeys[NB_ROUNDS];
	key_schedule(key, subkeys);

	uint32_t left, right;
	left = block >> 32;
	right = block;
	for (int i = 0; i < NB_ROUNDS; i++)
		feistel(subkeys[i], &left, &right);

	// Concatenate backward
	block = ((uint64_t)right) << 32 | left;
	return process_input(block, false);
}

uint64_t des_decrypt(uint64_t block, uint64_t key)
{
	block = process_input(block, true);
	uint64_t subkeys[NB_ROUNDS];
	key_schedule(key, subkeys);

	uint32_t left, right;
	left = block;
	right = block >> 32;
	for (int i = 0; i < NB_ROUNDS; i++)
		feistel(subkeys[NB_ROUNDS - i - 1], &right, &left);

	block = ((uint64_t)left) << 32 | right;
	return process_input(block, false);
}

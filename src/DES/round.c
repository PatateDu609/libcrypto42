/**
 * @file round.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief DES rounds implementation
 * @date 2022-08-14
 */

#include "internal.h"

/**
 * @brief Apply the substitution box to a block.
 *
 * @param block The block to apply the substitution box to, this block is seen as a 48 bits long block.
 * @return The block after the substitution box has been applied.
 */
static uint32_t substitute(uint64_t block)
{
	const uint8_t substitution_box[8][64] = {
		{
			14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
			0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
		},
		{
			15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
			3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
		},
		{
			10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
			13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
		},
		{
			7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
			13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
		},
		{
			2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
			14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
		},
		{
			12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
			10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
		},
		{
			4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
			13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
		},
		{
			13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
			1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
		},
	};

	uint32_t new_block = 0;

	for (int i = 0; i < 8; i++)
	{
		uint8_t current = (block >> (i * 6)) & 0b111111;

		// Get the 2 outer bits of the current block
		uint8_t row = (block & 0b000001) | ((current >> 4) & 0b10);
		// Get the 4 inner bits of the current block
		uint8_t col = (current & 0b011110) >> 1;

		new_block |= (substitution_box[i][row * 16 + col] << (i * 4));
	}

	return new_block;
}

uint64_t feistel(uint64_t block, uint64_t subkey)
{
	union blk_split new_block = {.raw = block};
	uint64_t right = new_block.right;

	const uint8_t E[48] = {
		32,		1,		2,		3,		4,		5,
		4,		5,		6,		7,		8,		9,
		8,		9,		10,		11,		12,		13,
		12,		13,		14,		15,		16,		17,
		16,		17,		18,		19,		20,		21,
		20,		21,		22,		23,		24,		25,
		24,		25,		26,		27,		28,		29,
		28,		29,		30,		31,		32,		1,
	};

	const uint8_t P[32] = {
		16,		7,		20,		21,		29,		12,		28,		17,
		1,		15,		23,		26,		5,		18,		31,		10,
		2,		8,		24,		14,		32,		27,		3,		9,
		19,		13,		30,		6,		22,		11,		4,		25,
	};

	right = permute(right, E, 48);
	right ^= subkey;
	right = substitute(right);
	right = permute(right, P, 32);

	new_block.right = new_block.left ^ right;
	new_block.left = right;
	return new_block.raw;
}

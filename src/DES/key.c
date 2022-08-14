/**
 * @file key.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief All the key management functions
 * @date 2022-08-14
 */

#include "internal.h"

/**
 * @brief Set the up key object. It will remove the parity bits and permute the key.
 *
 * @param key The key object to set up
 * @return An object with the key split in halves and permuted.
 */
static union blk_split setup_key(uint64_t key)
{
	union blk_split new_key = {.raw = 0};

	const uint8_t pc_1[2][28] = {
		{
			57,		49,		41,		33,		25,		17,		9,
			1,		58,		50,		42,		34,		26,		18,
			10,		2,		59,		51,		43,		35,		27,
			19,		11,		3,		60,		52,		44,		36,
		},
		{
			63,		55,		47,		39,		31,		23,		15,
			7,		62,		54,		46,		38,		30,		22,
			14,		6,		61,		53,		45,		37,		29,
			21,		13,		5,		28,		20,		12,		4,
		}
	};

	new_key.left = permute(key, pc_1[0], 28);
	new_key.right = permute(key, pc_1[1], 28);
	return new_key;
}

void key_schedule(uint64_t key, uint64_t subkeys[NB_ROUNDS])
{
	union blk_split new_key = setup_key(key);
	const uint8_t pc_2[48] = {
		14,		17,		11,		24,		1,		5,		3,		28,
		15,		6,		21,		10,		23,		19,		12,		4,
		26,		8,		16,		7,		27,		20,		13,		2,
		41,		52,		31,		37,		47,		55,		30,		40,
		51,		45,		33,		48,		44,		49,		39,		56,
		34,		53,		46,		42,		50,		36,		29,		32,
	};

	const uint8_t shifts[NB_ROUNDS] = {
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	};

	for (int i = 0; i < NB_ROUNDS; i++)
	{
		// It is important to mask the overflow bits (as they will override the bits of the other half)
		new_key.left = ((new_key.left << shifts[i]) | (new_key.left >> (28 - shifts[i])))
						& OVERFLOW_MASK_28;
		new_key.right = ((new_key.right << shifts[i]) | (new_key.right >> (28 - shifts[i])))
						& OVERFLOW_MASK_28;
		subkeys[i] = permute(new_key.raw, pc_2, 48);
	}
}

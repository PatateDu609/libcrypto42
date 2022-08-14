/**
 * @file permutation.c
 * @author Ghali Boucetta (gboucett@student.42,fr)
 * @brief DES permutation module
 * @date 2022-08-13
 */

#include "internal.h"

uint64_t permute(uint64_t block, const uint8_t *table, size_t size)
{
	uint64_t permuted = 0;

	for (size_t i = 0; i < size; i++)
		permuted |= ((block >> table[i]) & 1) << i;
	return permuted;
}

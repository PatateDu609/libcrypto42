/**
 * @file permutation.c
 * @author Ghali Boucetta (gboucett@student.42,fr)
 * @brief DES permutation module
 * @date 2022-08-13
 */

#include "internal.h"

uint64_t permute(uint64_t block, size_t input_size, const uint8_t *table, size_t size) {
	uint64_t permuted = 0;

	for (uint64_t i = 0; i < size; i++) {
		uint64_t bit = (((uint64_t) 1 << (input_size - table[i])) & block);
		if (bit)
			permuted |= ((uint64_t) 1 << (size - (i + 1)));
	}
	return permuted;
}

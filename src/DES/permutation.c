#include "internal.h"

#ifdef HAVE_CLANG_COMPILER
uint64_t permute(uint64_t block, size_t input_size, const uint8_t *__nonnull table, size_t size)
#else
uint64_t permute(uint64_t block, size_t input_size, const uint8_t *table, size_t size)
#endif
{

	uint64_t permuted = 0;

	for (uint64_t i = 0; i < size; i++) {
		uint64_t bit = (((uint64_t) 1 << (input_size - table[i])) & block);
		if (bit)
			permuted |= ((uint64_t) 1 << (size - (i + 1)));
	}
	return permuted;
}

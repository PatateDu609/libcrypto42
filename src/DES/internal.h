/**
 * @file internal.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief DES internal functions
 * @date 2022-08-13
 */

#ifndef DES_INTERNAL_H
#define DES_INTERNAL_H

#include <stdint.h>
#include "common.h"

#define NB_ROUNDS 16
#define OVERFLOW_MASK_28 0b0001111111111111111111111111111 // Force exactly 28 bits

#ifndef __nonnull
# define __nonnull __attribute__((nonnull))
#endif
#define __pure __attribute__((pure))
#define __const __attribute__((const))

/**
 * @brief Union to easily swap left and right halves of a 64-bit block
 *
 */
union blk_split {
	uint64_t raw;
	struct
	{
		uint32_t right;
		uint32_t left;
	};
};

/**
 * @brief Permutes a 64-bit block using a given permutation table.
 *
 * @param block The block to permute
 * @param size_input Size of the input block in bits
 * @param table The permutation table to use
 * @param size The size of the permutation table
 *
 * @return The permuted block
 */
uint64_t permute(uint64_t block, size_t size_input, const uint8_t *table, size_t size)
	__internal __nonnull((3));

/**
 * @brief Setup a subkey array from a given key.
 *
 * @param key The key to use
 * @param subkeys The subkey array to setup (must be at least NB_ROUNDS long)
 */
void key_schedule(uint64_t key, uint64_t subkeys[static NB_ROUNDS]) __internal;

/**
 * @brief The Feistel function.
 *
 * @param subkey The subkey of the current round
 * @param l32 Pointer to the left component of the final block
 * @param r32 Pointer to the right component of the final block
 */
void feistel(uint64_t subkey, uint32_t *l32, uint32_t *r32) __internal;

#endif

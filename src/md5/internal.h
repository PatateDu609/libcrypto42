/**
 * @file internal.h
 * @author Ghali Boucetta (gboucett@student.42,fr)
 * @brief Internal functions for the md5 library
 * @date 2022-08-08
 */

#ifndef MD5_INTERNAL_H
#define MD5_INTERNAL_H

#include "common.h"
#include "crypto.h"
#include <stdlib.h>

#undef F
#undef G
#undef H
#undef I

/**
 * @brief Miscellaneous defines defined by the RFC 1321
 *
 * @see https://tools.ietf.org/html/rfc1321
 *
 */
#define F(B, C, D) (D ^ (B & (C ^ D)))
#define G(B, C, D) F(D, B, C)
#define H(B, C, D) (B ^ C ^ D)
#define I(B, C, D) (C ^ (B | ~D))

#define MD5_HASH_SIZE 16 * 2 + 1
#define MD5_BLK_LEN 1 << 6
#define MD5_SIZE_LAST 8
#define MD5_DIGEST_SIZE 16

/**
 * @brief Structure used to store the md5 context.
 */
struct md5_ctx {
	uint32_t        a, b, c, d;///< Current state

	///< These values point to static variables in the init.c
	///< @see init.c
	const uint32_t *buf;  ///< Precomputed constants (for speed up, formula: floor(abs(sin(i + 1)) * 2**32))
	const uint8_t  *shift;///< Shift amounts
};


/**
 * @brief Initialize the MD5 context with all the values given by the RFC 1321.
 * @param ctx The context to initialize.
 *
 * @see https://tools.ietf.org/html/rfc1321
 *
 * @warning This function is internal and should not be called by the user.
 * @warning This function must be called before any operation related to md5.
 */
void     md5_init(struct md5_ctx *ctx) __visibility_internal;

/**
 * @brief Updates the md5 context with the given data.
 *
 * @param ctx The context to update.
 * @param input The data to update the context with.
 *
 * @warning This function is internal and should not be called by the user.
 * @warning This function must be called after exactly one call to md5_init.
 *
 * @see md5_init
 */
void     md5_update(struct md5_ctx *ctx, const uint8_t *input) __visibility_internal;

/**
 * @brief Generates the final hash from the md5 context.
 * @param ctx The context to generate the hash from.
 *
 * @warning This function is internal and should not be called by the user.
 * @note This function will flush the context after generating the hash.
 */
char    *md5_final(struct md5_ctx *ctx) __visibility_internal;

/**
 * @brief Generates the final hash from the md5 context and uses the given buffer to store the hash.
 *
 * @param ctx The context to generate the hash from.
 * @param output The buffer to store the hash in.
 * @return The buffer containing the hash.
 */
uint8_t *md5_final_raw(struct md5_ctx *ctx, uint8_t *output) __visibility_internal;

#endif

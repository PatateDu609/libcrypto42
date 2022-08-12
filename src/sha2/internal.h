/**
 * @file internal.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief This file contains the internal definitions of the SHA2 functions.
 * @date 2022-08-09
 */

#ifndef SHA2_INTERNAL_H
#define SHA2_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "crypto.h"

#define SHA2_224_DIGEST_SIZE 28
#define SHA2_256_DIGEST_SIZE 32
#define SHA2_384_DIGEST_SIZE 48
#define SHA2_512_DIGEST_SIZE 64

#define SHA2_512_224_DIGEST_SIZE SHA2_224_DIGEST_SIZE
#define SHA2_512_256_DIGEST_SIZE SHA2_256_DIGEST_SIZE

#define SHA2_256_BLOCK_SIZE 64
#define SHA2_224_BLOCK_SIZE SHA2_256_BLOCK_SIZE

#define SHA2_512_BLOCK_SIZE 128
#define SHA2_384_BLOCK_SIZE SHA2_512_BLOCK_SIZE
#define SHA2_512_224_BLOCK_SIZE SHA2_512_BLOCK_SIZE
#define SHA2_512_256_BLOCK_SIZE SHA2_512_BLOCK_SIZE

#define SHA2_256_NB_ROUNDS 64
#define SHA2_224_NB_ROUNDS SHA2_256_NB_ROUNDS

#define SHA2_512_NB_ROUNDS 80
#define SHA2_384_NB_ROUNDS SHA2_512_NB_ROUNDS
#define SHA2_512_224_NB_ROUNDS SHA2_512_NB_ROUNDS
#define SHA2_512_256_NB_ROUNDS SHA2_512_NB_ROUNDS

#define SHA2_256_WANTED_SIZE 8
#define SHA2_224_WANTED_SIZE SHA2_256_WANTED_SIZE

#define SHA2_512_WANTED_SIZE 16
#define SHA2_384_WANTED_SIZE SHA2_512_WANTED_SIZE
#define SHA2_512_224_WANTED_SIZE SHA2_512_WANTED_SIZE
#define SHA2_512_256_WANTED_SIZE SHA2_512_WANTED_SIZE

#undef Ch
#undef Ma
#undef sum0
#undef sum1

// Operations defined in RFC 6234
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Ma(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define BSIG0_32(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1_32(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0_32(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SSIG1_32(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

#define BSIG0_64(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define BSIG1_64(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SSIG0_64(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define SSIG1_64(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

/**
 * @brief Represents a SHA2 algorithm.
 */
struct sha2_alg {
	enum SHA2_ALG alg; /**< The algorithm. */

	size_t digest_size; /**< The size of the digest. */
	size_t block_size; /**< The size of the block. */
	size_t wanted_size; /**< The size of the wanted digest. */
	size_t nb_rounds; /**< The number of rounds. */
};

/**
 * @brief Represents a SHA2 context within 32bit (i.e. SHA2-224 or SHA2-256).
 */
struct sha2_ctx_32 {
	struct sha2_alg data; /**< The algorithm. */

	union
	{
		uint32_t state[8]; /**< The state. */
		uint8_t hash[32]; /**< The current hash. */
	};

	const uint32_t *cnsts; /**< The constants. */
};

/**
 * @brief Represents a SHA2 context within 64bit (i.e. SHA2-384, SHA2-512, SHA2-512_224 or SHA2-512_256).
 */
struct sha2_ctx_64 {
	struct sha2_alg data;

	union
	{
		uint64_t state[8]; /**< The state. */
		uint8_t hash[64]; /**< The current hash. */
	};

	const uint64_t *cnsts; /**< The constants. */
};

/**
 * @brief Represents a SHA2 context with every thing needed to compute a SHA2 hash.
 */
struct sha2
{
	struct sha2_alg alg; /**< The algorithm. */

	union // As its an union of pointers it takes exactly 8 bytes and avoid the need of a pointer to void.
	{
		struct sha2_ctx_32 *ctx_32; /**< The context for 32bit. */
		struct sha2_ctx_64 *ctx_64; /**< The context for 64bit. */
	};
};

/**
 * @brief Setup the sha2 context depending on the given algorithm.
 *
 * @param ctx The context to initialize.
 * @param alg The algorithm.
 */
void sha2_init(struct sha2 *ctx, enum SHA2_ALG alg);

/**
 * @brief Update the context with the given data.
 *
 * @param ctx The context to update.
 * @param data The data to update the context with.
 *
 * @note The data must be a void pointer since we do not know which kind of algorithm we are using.
 */
void sha2_update(struct sha2 *ctx, void *data);

/**
 * @brief Return the final hash string.
 *
 * @param ctx The context to get the hash from.
 *
 * @return The hash string.
 *
 * @warning This function returns a malloc-ed string which must be freed by the caller.
 */
char *sha2_final(struct sha2 *ctx);

/**
 * @brief Put the hash in the given buffer.
 *
 * @param ctx The context to get the hash from.
 * @param buf The buffer to put the hash in.
 *
 * @return The buffer itself.
 */
uint8_t *sha2_final_raw(struct sha2 *ctx, uint8_t *buf);

#endif

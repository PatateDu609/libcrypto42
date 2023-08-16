#ifndef BLOCK_CIPHER_MODES_INTERNAL_H
#define BLOCK_CIPHER_MODES_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cipher.h"
#include "common.h"
#include <stdbool.h>

enum cipher_mode {
	CIPHER_MODE_ECB,
	CIPHER_MODE_CBC,
	CIPHER_MODE_CFB,
	CIPHER_MODE_CFB1,
	CIPHER_MODE_CFB8,
};

struct block {
	uint8_t *data;
	size_t   size;
};

/**
 * @brief Check if the context is valid.
 *
 * @param ctx The context to check.
 * @param cipher_mode The cipher mode to check.
 * @param enc True if the context is for encryption, false otherwise.
 *
 * @return Returns true if the context is valid, false otherwise.
 */
bool          __cipher_ctx_valid(struct cipher_ctx *ctx, enum cipher_mode cipher_mode, bool enc) __visibility_internal;

/**
 * @brief Pad the plaintext with the given padding.
 *
 * @param plaintext The plaintext to pad.
 * @param len The length of the plaintext, this will be updated according to the padding.
 * @param blk_size The block size, used to determine the padding needed.
 *
 * @return Returns the padded plaintext.
 *
 * @note The padding algorithm follows PKCS#5 and PKCS#7, and is described by the RFC5652.
 * @see https://tools.ietf.org/html/rfc5652#section-6.3
 */
uint8_t      *pad(uint8_t *plaintext, size_t *len, size_t blk_size) __visibility_internal;

/**
 * @brief Unpad the plaintext, it is assumed that the plaintext is padded with
 * the padding algorithm described in the RFC5652.
 *
 * @param plaintext The plaintext to unpad.
 * @param len The length of the plaintext. This will be modified to the length
 * of the plaintext without the padding.
 *
 * @return Returns the unpadded ciphertext.
 *
 * @see https://tools.ietf.org/html/rfc5652#section-6.3
 */
uint8_t      *unpad(uint8_t *plaintext, size_t *len) __visibility_internal;

/**
 * @brief Same as (a XOR b).
 *
 * @param res Result of the XOR operation.
 * @param a Left hand operand.
 * @param b Right hand operand.
 */
void          block_xor(struct block *res, const struct block *a, const struct block *b) __visibility_internal;

void          block_right_shift(struct block *a, size_t s) __visibility_internal;

void          block_left_shift(struct block *a, size_t n) __visibility_internal;

void          block_bit_assign(struct block *res, struct block *src, size_t start, size_t nb) __visibility_internal;

struct block *block_dup(const struct block *src) __visibility_internal;

struct block *block_dup_data(uint8_t *data, size_t size) __visibility_internal;

struct block *block_create(size_t size) __visibility_internal;

void          block_delete(struct block *blk) __visibility_internal;

struct block *block_bit_extract(const struct block *blk, size_t sub) __visibility_internal;

/**
 * @brief Encrypts a given block using a context and saving the result
 *
 * @param ctx The context from which we pull the algorithm.
 * @param res Where the result will be stored.
 * @param a The plain block to encrypt.
 */
void block_encrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) __visibility_internal;

/**
 * @brief Decrypts a given block using a context and saving the result
 *
 * @param ctx The context from which we pull the algorithm.
 * @param res Where the result will be stored.
 * @param a The plain block to decrypt.
 */
void block_decrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) __visibility_internal;

bool __init_cipher_mode_enc(struct cipher_ctx *ctx, enum cipher_mode mode) __visibility_internal;

/**
 * @brief Setup the algorithm description to use in this library..
 *
 * @param algo The algorithm to setup.
 *
 * @return Returns a struct containing information about the current algorithm..
 */
struct block_cipher_ctx setup_algo(enum block_cipher algo);

/**
 * @brief Performs an ECB encryption on the given context.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t                *ECB_encrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs an ECB decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t                *ECB_decrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CBC encryption on the given context.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t                *CBC_encrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CBC decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t                *CBC_decrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CFB encryption on the given context.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t                *full_CFB_encrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CFB1 encryption on the given context.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t                *CFB1_encrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CFB8 encryption on the given context.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t                *CFB8_encrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CFB decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t                *full_CFB_decrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CFB1 decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t                *CFB1_decrypt(struct cipher_ctx *ctx) __visibility_internal;

/**
 * @brief Performs a CFB8 decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t                *CFB8_decrypt(struct cipher_ctx *ctx) __visibility_internal;

uint8_t                 gen_left_mask(size_t r) __visibility_internal;
enum cipher_mode        block_cipher_get_mode(enum block_cipher type) __visibility_internal;
enum block_cipher       get_block_cipher_algorithm(enum block_cipher type) __visibility_internal;

#ifdef __cplusplus
};
#endif

#endif

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
bool     __cipher_ctx_valid(struct cipher_ctx *ctx, enum cipher_mode cipher_mode, bool enc) __visibility_internal;

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
uint8_t *pad(uint8_t *plaintext, size_t *len, size_t blk_size) __visibility_internal;

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
uint8_t *unpad(uint8_t *plaintext, size_t *len) __visibility_internal;

void     block_xor(struct block *res, const struct block *a, const struct block *b) __visibility_internal;

void     block_encrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) __visibility_internal;

void     block_decrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) __visibility_internal;

#ifdef __cplusplus
};
#endif

#endif

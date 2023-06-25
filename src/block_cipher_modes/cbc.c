/**
 * @file cbc.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief CBC block cipher mode implementation
 * @date 2022-08-16
 */

#include "cipher.h"

#include "cipher.h"
#include "internal.h"
#include <stdio.h>

/**
 * @brief Performs an CBC encryption on the given context, using block size of 8 bytes.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t *__CBC_encrypt_8(struct cipher_ctx *ctx) {
	uint64_t *plaintext  = (uint64_t *) ctx->plaintext;
	uint64_t *ciphertext = (uint64_t *) ctx->ciphertext;

	uint64_t  key;
	memcpy(&key, ctx->key, 8);
	uint64_t last;
	memcpy(&last, ctx->iv, 8);

	key = bswap_64(key);

	for (size_t i = 0, nb = ctx->plaintext_len / 8; i < nb; i++) {
		ciphertext[i] = last = ctx->algo.blk8.enc(bswap_64(plaintext[i] ^ last), key);
		ciphertext[i]        = bswap_64(ciphertext[i]);
	}

	last = bswap_64(last);
	memcpy(ctx->iv, &last, ctx->iv_len);

	return ctx->ciphertext;
}

uint8_t *CBC_encrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_CBC, true))
		return NULL;

	uint8_t blk_size = ctx->algo.blk_size;

	uint8_t padding  = (ctx->plaintext_len % blk_size);
	if (padding == 0 && ctx->plaintext_len == 0)
		padding = blk_size;
	else if (padding != 0)
		padding = blk_size - padding;
	pad(ctx->plaintext, &ctx->plaintext_len, padding);

	if (ctx->ciphertext_len == ctx->plaintext_len && ctx->ciphertext) {
		memset(ctx->ciphertext, 0, ctx->ciphertext_len);
	} else {
		ctx->ciphertext_len = ctx->plaintext_len;
		ctx->ciphertext     = malloc(ctx->ciphertext_len);
	}

	if (blk_size == 8)
		return __CBC_encrypt_8(ctx);
	else {
		crypto42_errno = CRYPTO_BLKSIZE_INVALID;
		free(ctx->ciphertext);
		return NULL;
	}
}

/**
 * @brief Performs an CBC decryption on the given context, using block size of 8 bytes.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t *__CBC_decrypt_8(struct cipher_ctx *ctx) {
	uint64_t *plaintext  = (uint64_t *) ctx->plaintext;
	uint64_t *ciphertext = (uint64_t *) ctx->ciphertext;

	uint64_t  key;
	memcpy(&key, ctx->key, 8);

	uint64_t last;
	memcpy(&last, ctx->iv, 8);

	for (size_t i = 0, nb = ctx->plaintext_len / 8; i < nb; i++) {
		plaintext[i] = ctx->algo.blk8.dec(ciphertext[i], key) ^ last;
		last         = ciphertext[i];
	}
	return ctx->plaintext;
}

uint8_t *CBC_decrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_CBC, false))
		return NULL;

	uint8_t blk_size   = ctx->algo.blk_size;
	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = malloc(ctx->plaintext_len);

	switch (blk_size) {
		case 8:
			__CBC_decrypt_8(ctx);
			break;
		default: {
			crypto42_errno = CRYPTO_BLKSIZE_INVALID;
			free(ctx->plaintext);
			return NULL;
		}
	}

	uint8_t *temp = unpad(ctx->plaintext, &ctx->plaintext_len);
	free(ctx->plaintext);
	ctx->plaintext = temp;
	return ctx->plaintext;
}

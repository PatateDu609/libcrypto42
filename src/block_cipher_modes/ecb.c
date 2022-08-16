/**
 * @file ecb.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief ECB block cipher mode implementation
 * @date 2022-08-15
 */

#include "cipher.h"
#include "internal.h"
#include <stdio.h>

/**
 * @brief Performs an ECB encryption on the given context, using block size of 8 bytes.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t *__ECB_encrypt_8(struct cipher_ctx *ctx)
{
	uint64_t *plaintext = (uint64_t *)ctx->plaintext;
	uint64_t *ciphertext = (uint64_t *)ctx->ciphertext;

	uint64_t key;
	memcpy(&key, ctx->key, 8);

	for (size_t i = 0, nb = ctx->plaintext_len / 8; i < nb; i++)
		ciphertext[i] = ctx->algo.blk8.enc(plaintext[i], key);
	return ctx->ciphertext;
}

uint8_t *ECB_encrypt(struct cipher_ctx *ctx)
{
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_ECB, true))
		return NULL;

	uint8_t blk_size = ctx->algo.blk_size;

	uint8_t padding = ctx->plaintext_len % blk_size;
	if (padding == 0)
		padding = blk_size;
	pad(ctx->plaintext, &ctx->plaintext_len, padding);

	ctx->cipher_len = ctx->plaintext_len;
	ctx->ciphertext = malloc(ctx->cipher_len);

	switch(blk_size)
	{
		case 8:
			return __ECB_encrypt_8(ctx);
		default:
		{
			crypto42_errno = CRYPTO_BLKSIZE_INVALID;
			free(ctx->ciphertext);
			return NULL;
		}
	}
}

/**
 * @brief Performs an ECB decryption on the given context, using block size of 8 bytes.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 *
 * @warning This function assumes that the ciphertext (and the plaintext as well)
 * is a multiple of the block size.
 */
static uint8_t *__ECB_decrypt_8(struct cipher_ctx *ctx)
{
	uint64_t *plaintext = (uint64_t *)ctx->plaintext;
	uint64_t *ciphertext = (uint64_t *)ctx->ciphertext;

	uint64_t key;
	memcpy(&key, ctx->key, 8);

	for (size_t i = 0, nb =  ctx->plaintext_len / 8; i < nb; i++)
		plaintext[i] = ctx->algo.blk8.dec(ciphertext[i], key);
	return ctx->plaintext;
}

uint8_t *ECB_decrypt(struct cipher_ctx *ctx)
{
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_ECB, false))
		return NULL;

	uint8_t blk_size = ctx->algo.blk_size;
	ctx->plaintext_len = ctx->cipher_len;
	ctx->plaintext = malloc(ctx->plaintext_len);

	switch(blk_size)
	{
		case 8:
			__ECB_decrypt_8(ctx);
			break;
		default:
		{
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

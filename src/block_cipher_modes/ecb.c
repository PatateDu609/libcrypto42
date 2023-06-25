#include "cipher.h"
#include "internal.h"

/**
 * @brief Performs an ECB encryption on the given context, using block size of 8 bytes.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t *__ECB_encrypt_8(struct cipher_ctx *ctx) {
	uint64_t *plaintext  = (uint64_t *) ctx->plaintext;
	uint64_t *ciphertext = (uint64_t *) ctx->ciphertext;

	uint64_t  key;
	memcpy(&key, ctx->key, 8);

	key = bswap_64(key);

	for (size_t i = 0, nb = ctx->plaintext_len / 8; i < nb; i++) {
		ciphertext[i] = ctx->algo.blk8.enc(bswap_64(plaintext[i]), key);
		ciphertext[i] = bswap_64(ciphertext[i]);
	}
	return ctx->ciphertext;
}

uint8_t *ECB_encrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_ECB, true))
		return NULL;

	uint8_t blk_size = ctx->algo.blk_size;

	uint8_t padding  = ctx->plaintext_len % blk_size;
	if (padding == 0 && ctx->plaintext_len == 0)
		padding = blk_size;
	else if (padding != 0)
		padding = blk_size - padding;
	pad(ctx->plaintext, &ctx->plaintext_len, padding);

	ctx->ciphertext_len = ctx->plaintext_len;
	ctx->ciphertext     = malloc(ctx->ciphertext_len);

	if (blk_size == 8)
		return __ECB_encrypt_8(ctx);
	else {
		crypto42_errno = CRYPTO_BLKSIZE_INVALID;
		free(ctx->ciphertext);
		return NULL;
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
static uint8_t *__ECB_decrypt_8(struct cipher_ctx *ctx) {
	uint64_t *plaintext  = (uint64_t *) ctx->plaintext;
	uint64_t *ciphertext = (uint64_t *) ctx->ciphertext;

	uint64_t  key;
	memcpy(&key, ctx->key, 8);

	key = bswap_64(key);

	for (size_t i = 0, nb = ctx->plaintext_len / 8; i < nb; i++) {
		ciphertext[i] = bswap_64(ciphertext[i]);
		plaintext[i] = ctx->algo.blk8.dec(ciphertext[i], key);
		plaintext[i] = bswap_64(plaintext[i]);
	}
	return ctx->plaintext;
}

uint8_t *ECB_decrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_ECB, false))
		return NULL;

	uint8_t blk_size   = ctx->algo.blk_size;
	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = malloc(ctx->plaintext_len);

	if (blk_size == 8)
		__ECB_decrypt_8(ctx);
	else {
		crypto42_errno = CRYPTO_BLKSIZE_INVALID;
		free(ctx->plaintext);
		return NULL;
	}

	uint8_t *temp = unpad(ctx->plaintext, &ctx->plaintext_len);
	if (temp) {
		free(ctx->plaintext);
		ctx->plaintext = temp;
	}
	return ctx->plaintext;
}

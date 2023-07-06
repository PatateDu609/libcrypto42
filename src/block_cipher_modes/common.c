#include "common.h"
#include "cipher.h"
#include "internal.h"

struct block_cipher_ctx setup_algo(enum block_cipher algo) {
	switch (algo) {
	case BLOCK_CIPHER_DES:
		return (struct block_cipher_ctx) {
				.algo = algo,
				.blk_size = 8,

				.blk8 = {
					.enc = des_encrypt,
					.dec = des_decrypt,
				}
			};
	default:// Unmanaged algorithm
		return (struct block_cipher_ctx){
			.algo	  = algo,
			.blk_size = 0,
		};
	}
}

bool __cipher_ctx_valid(struct cipher_ctx *ctx, enum cipher_mode cipher_mode, bool enc) {
	enum crypto_error err = crypto42_errno;

	if (ctx == NULL)
		crypto42_errno = CRYPTO_CTX_NULL;
	if (ctx->algo.blk_size == 0)
		crypto42_errno = CRYPTO_BLKSIZE_ZERO;

	if (ctx->key == NULL)
		crypto42_errno = CRYPTO_KEY_NULL;
	if (ctx->key_len == 0)
		crypto42_errno = CRYPTO_KEY_LEN_ZERO;
	if (enc) {
		if (ctx->plaintext == NULL)
			crypto42_errno = CRYPTO_PLAINTEXT_NULL;
		if (ctx->plaintext_len == 0)
			crypto42_errno = CRYPTO_PLAINTEXT_LEN_ZERO;
	} else {
		if (ctx->ciphertext == NULL)
			crypto42_errno = CRYPTO_CIPHERTEXT_NULL;
		if (ctx->ciphertext_len == 0)
			crypto42_errno = CRYPTO_CIPHERTEXT_LEN_ZERO;
		if (ctx->ciphertext_len % ctx->algo.blk_size != 0)
			crypto42_errno = CRYPTO_CIPHERTEXT_BLKSIZE_UNMATCH;
	}
	if (cipher_mode != CIPHER_MODE_ECB) {
		if (ctx->iv == NULL)
			crypto42_errno = CRYPTO_IV_NULL;
		if (ctx->iv_len == 0)
			crypto42_errno = CRYPTO_IV_LEN_ZERO;
		if (ctx->iv_len != ctx->algo.blk_size)
			crypto42_errno = CRYPTO_IV_BLKSIZE_UNMATCH;
	}

	return err == crypto42_errno;

	// TODO: Add more checks for CTR mode (nonce check)
}

uint8_t *pad(uint8_t *plaintext, size_t *len, size_t blk_size) {
	uint8_t	 padding = blk_size - (*len % blk_size);
	if (!(0 < padding && padding <= 16))
		return NULL;

	uint8_t *p		 = realloc(plaintext, *len + padding);
	if (p == NULL)
		return NULL;

	for (size_t i = *len, nb = *len + padding; i < nb; i++)
		p[i] = padding;// Padding is the same for all bytes
	*len += padding;
	return p;
}

uint8_t *unpad(uint8_t *plaintext, size_t *len) {
	uint8_t padding = plaintext[*len - 1];

	if (!(0 < padding && padding <= 16))
		return NULL;

	size_t	 new_size = *len - padding;

	uint8_t *p = malloc(new_size);
	if (p == NULL)
		return NULL;

	*len = new_size;
	memcpy(p, plaintext, new_size);
	return p;
}

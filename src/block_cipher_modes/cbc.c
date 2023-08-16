#include "cipher.h"
#include "internal.h"

uint8_t *CBC_encrypt(struct cipher_ctx *ctx) {
	if (!__init_cipher_mode_enc(ctx, CIPHER_MODE_CBC))
		return NULL;

	struct block src, last, cipher;
	src.size = last.size = cipher.size = ctx->algo.blk_size;
	last.data                          = ctx->iv;

	size_t idx = 0;
	for (; idx < ctx->plaintext_len; idx += ctx->algo.blk_size) {
		src.data    = ctx->plaintext + idx;
		cipher.data = ctx->ciphertext + idx;

		block_xor(&src, &src, &last);
		block_encrypt(ctx, &cipher, &src);

		last.data = cipher.data;
	}

	if (idx != ctx->plaintext_len) {
		crypto42_errno = CRYPTO_BLKSIZE_INVALID;
		free(ctx->ciphertext);
		return NULL;
	}

	return ctx->ciphertext;
}

uint8_t *CBC_decrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_CBC, false))
		return NULL;
	if (!ctx->ciphertext_len && ctx->ciphertext == NULL)
		return NULL;

	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = calloc(sizeof *ctx->plaintext, ctx->plaintext_len);
	if (!ctx->plaintext)
		return NULL;

	struct block src, iv, plain;
	src.size = iv.size = plain.size = ctx->algo.blk_size;
	iv.data                         = ctx->iv;

	size_t idx = 0;
	for (; idx < ctx->plaintext_len; idx += ctx->algo.blk_size) {
		src.data   = ctx->ciphertext + idx;
		plain.data = ctx->plaintext + idx;

		block_decrypt(ctx, &plain, &src);
		block_xor(&plain, &plain, &iv);

		iv.data = src.data;
	}

	if (idx != ctx->ciphertext_len) {
		crypto42_errno = CRYPTO_BLKSIZE_INVALID;
		free(ctx->ciphertext);
		return NULL;
	}

	uint8_t *temp = unpad(ctx->plaintext, &ctx->plaintext_len);
	free(ctx->plaintext);
	ctx->plaintext = temp;
	return ctx->plaintext;
}

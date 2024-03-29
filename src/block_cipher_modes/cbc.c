#include "cipher.h"
#include "internal.h"

uint8_t *CBC_encrypt(struct cipher_ctx *ctx) {
	if (!__init_cipher_mode_enc(ctx, CIPHER_MODE_CBC))
		return NULL;

	struct blk src, last, cipher;
	src.len = last.len = cipher.len = ctx->algo.blk_size;
	last.data                       = ctx->iv;

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

	if (!ctx->final) {
		memcpy(ctx->iv, ctx->ciphertext, ctx->iv_len * sizeof *ctx->iv);
	}

	return ctx->ciphertext;
}

uint8_t *CBC_decrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_CBC, false))
		return NULL;
	if (!ctx->ciphertext_len && ctx->ciphertext == NULL)
		return NULL;

	if (ctx->plaintext)
		free(ctx->plaintext);
	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = calloc(sizeof *ctx->plaintext, ctx->plaintext_len);
	if (!ctx->plaintext)
		return NULL;

	struct blk src, iv, plain;
	src.len = iv.len = plain.len = ctx->algo.blk_size;
	iv.data                      = ctx->iv;

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

	if (ctx->final) {
		uint8_t *temp = unpad(ctx->plaintext, &ctx->plaintext_len);
		free(ctx->plaintext);
		ctx->plaintext = temp;
	} else {
		memcpy(ctx->iv, iv.data, ctx->iv_len * sizeof *ctx->iv);
	}
	return ctx->plaintext;
}

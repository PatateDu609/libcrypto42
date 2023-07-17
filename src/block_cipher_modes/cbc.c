#include "cipher.h"
#include "internal.h"

uint8_t *CBC_encrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_CBC, true))
		return NULL;

	pad(ctx->plaintext, &ctx->plaintext_len, ctx->algo.blk_size);

	if (ctx->ciphertext_len == ctx->plaintext_len && ctx->ciphertext) {
		memset(ctx->ciphertext, 0, ctx->ciphertext_len);
	} else {
		ctx->ciphertext_len = ctx->plaintext_len;
		ctx->ciphertext		= malloc(ctx->ciphertext_len);
	}

	struct block src, last, cipher;
	src.size = last.size = cipher.size = ctx->algo.blk_size;
	last.data						   = ctx->iv;

	size_t idx = 0;
	for (; idx < ctx->plaintext_len; idx += ctx->algo.blk_size) {
		src.data	= ctx->plaintext + idx;
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

	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext	   = calloc(sizeof *ctx->plaintext, ctx->plaintext_len);
	if (!ctx->plaintext)
		return NULL;

	struct block src, iv, plain;
	src.size = iv.size = plain.size = ctx->algo.blk_size;
	iv.data						  = ctx->iv;

	size_t idx = 0;
	for (; idx < ctx->plaintext_len; idx += ctx->algo.blk_size) {
		src.data   = ctx->ciphertext + idx;
		plain.data = ctx->plaintext + idx;

		block_decrypt(ctx, &src, &src);
		block_xor(&plain, &src, &iv);

		iv.data = src.data;
	}

	if (idx != ctx->ciphertext_len) {
		crypto42_errno = CRYPTO_BLKSIZE_INVALID;
		free(ctx->ciphertext);
		return NULL;
	}

	uint8_t *temp = unpad(ctx->plaintext, &ctx->plaintext_len);
	if (temp) {
		free(ctx->plaintext);
		ctx->plaintext = temp;
	}
	return ctx->plaintext;
}

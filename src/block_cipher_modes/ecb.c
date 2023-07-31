#include "cipher.h"
#include "internal.h"

uint8_t *ECB_encrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_ECB, true))
		return NULL;

	uint8_t *p = pad(ctx->plaintext, &ctx->plaintext_len, ctx->algo.blk_size);
	if (p == NULL) {
		perror("error: couldn't allocate memory");
		return NULL;
	}

	ctx->plaintext = p;

	ctx->ciphertext_len = ctx->plaintext_len;
	ctx->ciphertext     = calloc(ctx->ciphertext_len, sizeof *ctx->ciphertext);
	if (!ctx->ciphertext) {
		perror("error: couldn't allocate memory");
		return NULL;
	}

	struct block src, cipher;
	src.size = cipher.size = ctx->algo.blk_size;

	size_t idx = 0;
	for (; idx < ctx->plaintext_len; idx += ctx->algo.blk_size) {
		src.data    = ctx->plaintext + idx;
		cipher.data = ctx->ciphertext + idx;

		block_encrypt(ctx, &cipher, &src);
	}

	if (idx != ctx->plaintext_len) {
		crypto42_errno = CRYPTO_BLKSIZE_INVALID;
		free(ctx->ciphertext);
		return NULL;
	}

	return ctx->ciphertext;
}

uint8_t *ECB_decrypt(struct cipher_ctx *ctx) {
	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_ECB, false))
		return NULL;
	if (!ctx->ciphertext_len && ctx->ciphertext == NULL)
		return NULL;

	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = malloc(ctx->plaintext_len);

	struct block src, plain;
	src.size = plain.size = ctx->algo.blk_size;

	size_t idx = 0;
	for (; idx < ctx->plaintext_len; idx += ctx->algo.blk_size) {
		src.data   = ctx->ciphertext + idx;
		plain.data = ctx->plaintext + idx;

		block_decrypt(ctx, &plain, &src);
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

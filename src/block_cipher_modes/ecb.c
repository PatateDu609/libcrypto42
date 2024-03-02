#include "cipher.h"
#include "internal.h"

uint8_t *ECB_encrypt(struct cipher_ctx *ctx) {
	if (!__init_cipher_mode_enc(ctx, CIPHER_MODE_ECB))
		return NULL;

	struct blk src, cipher;
	src.len = cipher.len = ctx->algo.blk_size;

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

	if (ctx->plaintext)
		free(ctx->plaintext);
	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = malloc(ctx->plaintext_len);

	struct blk src, plain;
	src.len = plain.len = ctx->algo.blk_size;

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

	if (ctx->final) {
		uint8_t *temp = unpad(ctx->plaintext, &ctx->plaintext_len);
		free(ctx->plaintext);
		ctx->plaintext = temp;
	}
	return ctx->plaintext;
}

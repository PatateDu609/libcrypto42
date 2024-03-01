#include "cipher.h"
#include "internal.h"

static inline uint8_t *perform_OFB(struct cipher_ctx *ctx, struct block *in, struct block *out) {
	const size_t  s               = ctx->algo.mode_blk_size_bits;
	const size_t  input_size_bits = ctx->plaintext_len * 8;
	const size_t  blk_size_bits   = ctx->algo.blk_size * 8;

	struct block *src = block_dup_data(ctx->iv, ctx->iv_len);
	if (!src) {
		perror("error: block_dup_data");
		return NULL;
	}

	struct block *output_block = block_create(src->size);
	if (!output_block) {
		perror("error: block_create");
		block_delete(src);
		return NULL;
	}

	for (size_t idx = 0; idx < input_size_bits; idx += s) {
		block_encrypt(ctx, output_block, src);

		struct block *output_block_s_bits = block_bit_extract(output_block, s);
		if (!output_block_s_bits) {
			block_delete(src);
			block_delete(output_block);
			return NULL;
		}

		struct block *output_block_s_bits_duped = block_dup(output_block_s_bits);
		if (!output_block_s_bits_duped) {
			block_delete(src);
			block_delete(output_block);
			block_delete(output_block_s_bits);
			return NULL;
		}

		block_left_shift(src, s);
		block_right_shift(output_block_s_bits_duped, blk_size_bits - s);
		block_bit_assign(src, output_block_s_bits_duped, blk_size_bits - s, s);
		block_delete(output_block_s_bits_duped);

		struct block *input_s_bits = block_bit_extract(in, s);
		if (!input_s_bits) {
			block_delete(src);
			block_delete(output_block);
			block_delete(output_block_s_bits);
			return NULL;
		}

		if (output_block_s_bits->size < out->size) {
			uint8_t *tmp = realloc(output_block_s_bits->data, out->size * sizeof *tmp);

			if (!tmp) {
				perror("error: realloc");

				block_delete(src);
				block_delete(output_block);
				block_delete(output_block_s_bits);
				block_delete(input_s_bits);
				return NULL;
			}

			output_block_s_bits->data = tmp;
			output_block_s_bits->size = out->size;
		}

		block_xor(output_block_s_bits, output_block_s_bits, input_s_bits);
		block_right_shift(output_block_s_bits, idx);
		block_bit_assign(out, output_block_s_bits, idx, s);
		block_left_shift(in, s);

		block_delete(output_block_s_bits);
		block_delete(input_s_bits);
	}

	memcpy(ctx->iv, src->data, src->size * sizeof *src->data);
	block_delete(output_block);
	block_delete(src);
	return out->data;
}

uint8_t *OFB_encrypt(struct cipher_ctx *ctx) {
	if (!ctx->plaintext_len)
		return NULL;

	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_OFB, true))
		return NULL;

	if (ctx->ciphertext) {
		free(ctx->ciphertext);
	}
	ctx->ciphertext_len = ctx->plaintext_len;
	ctx->ciphertext     = calloc(ctx->ciphertext_len, sizeof *ctx->ciphertext);
	if (!ctx->ciphertext) {
		perror("error: calloc");
		return NULL;
	}

	struct block *plain = block_dup_data(ctx->plaintext, ctx->plaintext_len);
	if (!plain) {
		perror("error: block_dup_data");
		free(ctx->ciphertext);
		ctx->ciphertext = NULL;
		return NULL;
	}

	struct block output = { .data = ctx->ciphertext, .size = ctx->ciphertext_len };

	if (!perform_OFB(ctx, plain, &output)) {
		perror("error");
		free(ctx->ciphertext);
		ctx->ciphertext = NULL;
	}

	block_delete(plain);

	return ctx->ciphertext;
}

uint8_t *OFB_decrypt(struct cipher_ctx *ctx) {
	if (!ctx->ciphertext_len)
		return NULL;

	if (!__cipher_ctx_valid(ctx, CIPHER_MODE_OFB, false))
		return NULL;

	if (ctx->plaintext) {
		free(ctx->plaintext);
	}
	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = calloc(ctx->plaintext_len, sizeof *ctx->plaintext);
	if (!ctx->plaintext) {
		perror("error: calloc");
		return NULL;
	}

	struct block *cipher = block_dup_data(ctx->ciphertext, ctx->ciphertext_len);
	if (!cipher) {
		perror("error: block_dup_data");
		free(ctx->plaintext);
		ctx->plaintext = NULL;
		return NULL;
	}

	struct block output = { .data = ctx->plaintext, .size = ctx->plaintext_len };

	if (!perform_OFB(ctx, cipher, &output)) {
		perror("error");
		free(ctx->plaintext);
		ctx->plaintext = NULL;
	}

	block_delete(cipher);

	return ctx->plaintext;
}
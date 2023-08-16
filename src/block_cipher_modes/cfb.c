#include "cipher.h"
#include "internal.h"

static uint8_t *CFB_encrypt(struct cipher_ctx *ctx) {
	if (!ctx->plaintext_len)
		return NULL;

	if (!__cipher_ctx_valid(ctx, block_cipher_get_mode(ctx->algo.type), true))
		return NULL;

	ctx->ciphertext_len = ctx->plaintext_len;
	ctx->ciphertext     = calloc(ctx->ciphertext_len, sizeof *ctx->ciphertext);
	if (!ctx->ciphertext) {
		perror("error: calloc");
		return NULL;
	}

	const size_t  s                   = ctx->algo.mode_blk_size_bits;
	const size_t  plaintext_size_bits = ctx->plaintext_len * 8;
	const size_t  blk_size_bits       = ctx->algo.blk_size * 8;

	struct block *src = block_dup_data(ctx->iv, ctx->iv_len);
	if (!src) {
		perror("error: block_dup_data");
		free(ctx->ciphertext);
		ctx->ciphertext = NULL;
		return NULL;
	}

	struct block *raw_cipher = block_create(src->size);
	if (!raw_cipher) {
		perror("error: block_create");
		free(ctx->ciphertext);
		ctx->ciphertext = NULL;
		block_delete(src);
		return NULL;
	}

	struct block *plain = block_dup_data(ctx->plaintext, ctx->plaintext_len);
	if (!plain) {
		perror("error: block_dup_data");
		free(ctx->ciphertext);
		ctx->ciphertext = NULL;
		block_delete(src);
		block_delete(raw_cipher);
		return NULL;
	}

	struct block cipher = { .data = ctx->ciphertext, .size = ctx->ciphertext_len };

	for (size_t idx = 0; idx < plaintext_size_bits; idx += s) {
		block_encrypt(ctx, raw_cipher, src);

		struct block *ciphered_s_bits = block_bit_extract(raw_cipher, s);
		if (!ciphered_s_bits) {
			free(ctx->ciphertext);
			ctx->ciphertext = NULL;
			block_delete(src);
			block_delete(raw_cipher);
			block_delete(plain);
			return NULL;
		}

		struct block *plain_s_bits = block_bit_extract(plain, s);
		if (!plain_s_bits) {
			free(ctx->ciphertext);
			ctx->ciphertext = NULL;
			block_delete(src);
			block_delete(raw_cipher);
			block_delete(plain);
			block_delete(ciphered_s_bits);
			return NULL;
		}

		block_xor(ciphered_s_bits, ciphered_s_bits, plain_s_bits);

		struct block *ciphered_duped = block_dup(ciphered_s_bits);
		if (!ciphered_duped) {
			free(ctx->ciphertext);
			ctx->ciphertext = NULL;
			block_delete(src);
			block_delete(raw_cipher);
			block_delete(plain);
			block_delete(ciphered_s_bits);
			block_delete(plain_s_bits);
			return NULL;
		}

		block_left_shift(src, s);
		block_right_shift(ciphered_duped, blk_size_bits - s);
		block_bit_assign(src, ciphered_duped, blk_size_bits - s, s);
		block_delete(ciphered_duped);

		if (ciphered_s_bits->size < cipher.size) {
			uint8_t *tmp = realloc(ciphered_s_bits->data, cipher.size * sizeof *tmp);

			if (!tmp) {
				perror("error: realloc");

				free(ctx->ciphertext);
				ctx->ciphertext = NULL;
				block_delete(src);
				block_delete(raw_cipher);
				block_delete(plain);
				block_delete(ciphered_s_bits);
				block_delete(plain_s_bits);
				return NULL;
			}

			ciphered_s_bits->data = tmp;
			ciphered_s_bits->size = cipher.size;
		}

		block_right_shift(ciphered_s_bits, idx);
		block_bit_assign(&cipher, ciphered_s_bits, idx, s);
		block_left_shift(plain, s);

		block_delete(ciphered_s_bits);
		block_delete(plain_s_bits);
	}

	memcpy(ctx->iv, src->data, src->size * sizeof *src->data);
	block_delete(src);
	block_delete(raw_cipher);
	block_delete(plain);
	return ctx->ciphertext;
}

static uint8_t *CFB_decrypt(struct cipher_ctx *ctx) {
	if (!ctx->ciphertext_len)
		return NULL;

	if (!__cipher_ctx_valid(ctx, block_cipher_get_mode(ctx->algo.type), false))
		return NULL;

	ctx->plaintext_len = ctx->ciphertext_len;
	ctx->plaintext     = calloc(ctx->plaintext_len, sizeof *ctx->plaintext);
	if (!ctx->plaintext) {
		perror("error: calloc");
		return NULL;
	}

	const size_t  s                    = ctx->algo.mode_blk_size_bits;
	const size_t  ciphertext_size_bits = ctx->ciphertext_len * 8;
	const size_t  blk_size_bits        = ctx->algo.blk_size * 8;

	struct block *src = block_dup_data(ctx->iv, ctx->iv_len);
	if (!src) {
		perror("error: block_dup_data");
		free(ctx->plaintext);
		ctx->plaintext = NULL;
		return NULL;
	}

	struct block *raw_cipher = block_create(ctx->algo.blk_size);
	if (!raw_cipher) {
		perror("error: block_create");
		free(ctx->plaintext);
		ctx->plaintext = NULL;
		block_delete(src);
		return NULL;
	}

	struct block *cipher = block_dup_data(ctx->ciphertext, ctx->ciphertext_len);
	if (!cipher) {
		perror("error: block_dup_data");
		free(ctx->plaintext);
		ctx->plaintext = NULL;
		block_delete(src);
		block_delete(raw_cipher);
		return NULL;
	}

	struct block plain = { .data = ctx->plaintext, .size = ctx->plaintext_len };

	for (size_t idx = 0; idx < ciphertext_size_bits; idx += s) {
		block_encrypt(ctx, raw_cipher, src);

		struct block *src_ciphered_s_bits = block_bit_extract(raw_cipher, s);
		if (!src_ciphered_s_bits) {
			free(ctx->plaintext);
			ctx->plaintext = NULL;
			block_delete(src);
			block_delete(raw_cipher);
			block_delete(cipher);
			return NULL;
		}

		struct block *input_ciphered_s_bits = block_bit_extract(cipher, s);
		if (!input_ciphered_s_bits) {
			free(ctx->plaintext);
			ctx->plaintext = NULL;
			block_delete(src);
			block_delete(raw_cipher);
			block_delete(src_ciphered_s_bits);
			return NULL;
		}

		if (input_ciphered_s_bits->size < plain.size || input_ciphered_s_bits->size < ctx->algo.blk_size) {
			size_t   size = plain.size < ctx->algo.blk_size ? ctx->algo.blk_size : plain.size;
			uint8_t *tmp  = realloc(input_ciphered_s_bits->data, size * sizeof *tmp);

			if (!tmp) {
				perror("error: realloc");

				free(ctx->plaintext);
				ctx->plaintext = NULL;
				block_delete(src);
				block_delete(raw_cipher);
				block_delete(src_ciphered_s_bits);
				block_delete(input_ciphered_s_bits);
				block_delete(cipher);
				return NULL;
			}

			input_ciphered_s_bits->data = tmp;
			input_ciphered_s_bits->size = size;
		}

		struct block *input_ciphered_s_bits_duped = block_dup(input_ciphered_s_bits);
		if (!input_ciphered_s_bits_duped) {
			free(ctx->plaintext);
			ctx->plaintext = NULL;
			block_delete(src);
			block_delete(raw_cipher);
			block_delete(src_ciphered_s_bits);
			block_delete(input_ciphered_s_bits);
			return NULL;
		}

		block_left_shift(src, s);
		block_right_shift(input_ciphered_s_bits_duped, blk_size_bits - s);
		block_bit_assign(src, input_ciphered_s_bits_duped, blk_size_bits - s, s);
		block_left_shift(cipher, s);
		block_delete(input_ciphered_s_bits_duped);

		block_xor(input_ciphered_s_bits, input_ciphered_s_bits, src_ciphered_s_bits);

		block_right_shift(input_ciphered_s_bits, idx);
		block_bit_assign(&plain, input_ciphered_s_bits, idx, s);


		block_delete(src_ciphered_s_bits);
		block_delete(input_ciphered_s_bits);
	}

	memcpy(ctx->iv, src->data, src->size * sizeof *src->data);
	block_delete(raw_cipher);
	block_delete(cipher);
	block_delete(src);

	return ctx->plaintext;
}

uint8_t *full_CFB_encrypt(struct cipher_ctx *ctx) {
	return CFB_encrypt(ctx);
}

uint8_t *CFB1_encrypt(struct cipher_ctx *ctx) {
	return CFB_encrypt(ctx);
}

uint8_t *CFB8_encrypt(struct cipher_ctx *ctx) {
	return CFB_encrypt(ctx);
}

uint8_t *full_CFB_decrypt(struct cipher_ctx *ctx) {
	return CFB_decrypt(ctx);
}

uint8_t *CFB1_decrypt(struct cipher_ctx *ctx) {
	return CFB_decrypt(ctx);
}

uint8_t *CFB8_decrypt(struct cipher_ctx *ctx) {
	return CFB_decrypt(ctx);
}

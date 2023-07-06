#include "cipher.h"
#include "common.h"
#include "internal.h"
#include <string.h>

typedef uint32_t *(aes_op) (struct aes_ctx *, union aes_data *, const union aes_key *);
static aes_op cipher, inv_cipher;

uint32_t	 *cipher(struct aes_ctx *ctx, union aes_data *data, const union aes_key *key) {
	key_expansion(ctx, key->w);

	add_round_key(ctx, data, 0);

	for (size_t i = 1; i < ctx->Nr; i++) {
		sub_bytes(data);
		shift_rows(data);
		mix_columns(data);
		add_round_key(ctx, data, i);
	}
	sub_bytes(data);
	shift_rows(data);
	add_round_key(ctx, data, ctx->Nr);
	return data->w;
}

uint32_t *inv_cipher(struct aes_ctx *ctx, union aes_data *data, const union aes_key *key) {
	key_expansion(ctx, key->w);

	add_round_key(ctx, data, ctx->Nr);
	for (size_t i = ctx->Nr; i >= 1; i--) {
		inv_shift_rows(data);
		inv_sub_bytes(data);
		add_round_key(ctx, data, i);
		inv_mix_columns(data);
	}

	inv_shift_rows(data);
	inv_sub_bytes(data);
	add_round_key(ctx, data, 0);

	return data->w;
}

static uint32_t *do_aes(struct aes_ctx *ctx, uint32_t *blk, const uint32_t *k, aes_op *aes) {
	union aes_data data;
	memset(data.b, 0, sizeof data.b);
	uint8_t *raw = (uint8_t *) blk;

	for (size_t c = 0; c < 4; c++)
		for (size_t r = 0; r < 4; r++)
			data.b[(3 - r) * 4 + c] = raw[(3 - c) * 4 + r];

	union aes_key key;
	memset(key.b, 0, sizeof key.b);
	memcpy(key.w, k, sizeof key.w);

	raw					 = (uint8_t *) aes(ctx, &data, &key);
	uint32_t *ciphertext = calloc(ctx->Nb, sizeof *ciphertext);
	if (!ciphertext) {
		perror("error: couldn't allocate memory");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < ctx->Nb; i++) {
		uint8_t *b = (uint8_t *) (ciphertext + i);

		b[3] = raw[3 - i];
		b[2] = raw[4 + 3 - i];
		b[1] = raw[8 + 3 - i];
		b[0] = raw[12 + 3 - i];
	}

	return ciphertext;
}

uint32_t *aes128_encrypt(uint32_t *blk, const uint32_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES128;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES128_KEY_SIZE;
	ctx.Nr	 = AES128_NB_ROUNDS;

	return do_aes(&ctx, blk, k, cipher);
}

uint32_t *aes192_encrypt(uint32_t *blk, const uint32_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES192;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES192_KEY_SIZE;
	ctx.Nr	 = AES192_NB_ROUNDS;

	return do_aes(&ctx, blk, k, cipher);
}

uint32_t *aes256_encrypt(uint32_t *blk, const uint32_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES256;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES256_KEY_SIZE;
	ctx.Nr	 = AES256_NB_ROUNDS;

	return do_aes(&ctx, blk, k, cipher);
}

uint32_t *aes128_decrypt(uint32_t *blk, const uint32_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES128;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES128_KEY_SIZE;
	ctx.Nr	 = AES128_NB_ROUNDS;

	return do_aes(&ctx, blk, k, inv_cipher);
}

uint32_t *aes192_decrypt(uint32_t *blk, const uint32_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES192;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES192_KEY_SIZE;
	ctx.Nr	 = AES192_NB_ROUNDS;

	return do_aes(&ctx, blk, k, inv_cipher);
}

uint32_t *aes256_decrypt(uint32_t *blk, const uint32_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES256;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES256_KEY_SIZE;
	ctx.Nr	 = AES256_NB_ROUNDS;

	return do_aes(&ctx, blk, k, inv_cipher);
}
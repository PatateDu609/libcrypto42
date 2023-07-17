#include "cipher.h"
#include "common.h"
#include "internal.h"
#include <string.h>

typedef uint8_t *(aes_op) (struct aes_ctx *, union aes_data *, const union aes_key *);
static aes_op cipher, inv_cipher;

uint8_t		 *cipher(struct aes_ctx *ctx, union aes_data *data, const union aes_key *key) {
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
	 return data->b;
}

uint8_t *inv_cipher(struct aes_ctx *ctx, union aes_data *data, const union aes_key *key) {
	key_expansion(ctx, key->w);

	size_t i = ctx->Nr;

	add_round_key(ctx, data, i--);
	for (; i >= 1; i--) {
		inv_shift_rows(data);
		inv_sub_bytes(data);
		add_round_key(ctx, data, i);
		inv_mix_columns(data);
	}

	inv_shift_rows(data);
	inv_sub_bytes(data);
	add_round_key(ctx, data, 0);

	return data->b;
}

static uint8_t *do_aes(struct aes_ctx *ctx, const uint8_t *blk, const uint8_t *k, aes_op *aes) {
	union aes_data data, blk_swp;
	memcpy(blk_swp.w, blk, sizeof blk_swp.w);
	blk_swp.w[0] = bswap_32(blk_swp.w[0]);
	blk_swp.w[1] = bswap_32(blk_swp.w[1]);
	blk_swp.w[2] = bswap_32(blk_swp.w[2]);
	blk_swp.w[3] = bswap_32(blk_swp.w[3]);

	for (size_t col = 0; col < 4; col++)
		for (size_t row = 0; row < 4; row++)
			data.b[(3 - row) * 4 + col] = blk_swp.b[(3 - col) * 4 + row];

	union aes_key key;
	memset(key.b, 0, sizeof key.b);
	memcpy(key.w, k, sizeof key.w);
	for (size_t i = 0; i < ctx->Nk; i++)
		key.w[i] = bswap_32(key.w[i]);

	uint8_t *raw		= aes(ctx, &data, &key);
	uint8_t *output = calloc(AES_BLK_SIZE_BYTES, sizeof *output);
	if (!output) {
		perror("error: couldn't allocate memory");
		exit(EXIT_FAILURE);
	}

	for (size_t col = 0; col < 4; col++)
		for (size_t row = 0; row < 4; row++)
			blk_swp.b[(3 - row) * 4 + col] = raw[(3 - col) * 4 + row];

	blk_swp.w[0] = bswap_32(blk_swp.w[0]);
	blk_swp.w[1] = bswap_32(blk_swp.w[1]);
	blk_swp.w[2] = bswap_32(blk_swp.w[2]);
	blk_swp.w[3] = bswap_32(blk_swp.w[3]);
	memcpy(output, blk_swp.b, sizeof blk_swp.b);

	return output;
}

uint8_t *aes128_encrypt(uint8_t *blk, const uint8_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES128;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES128_KEY_SIZE;
	ctx.Nr	 = AES128_NB_ROUNDS;

	return do_aes(&ctx, blk, k, cipher);
}

uint8_t *aes192_encrypt(uint8_t *blk, const uint8_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES192;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES192_KEY_SIZE;
	ctx.Nr	 = AES192_NB_ROUNDS;

	return do_aes(&ctx, blk, k, cipher);
}

uint8_t *aes256_encrypt(uint8_t *blk, const uint8_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES256;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES256_KEY_SIZE;
	ctx.Nr	 = AES256_NB_ROUNDS;

	return do_aes(&ctx, blk, k, cipher);
}

uint8_t *aes128_decrypt(uint8_t *blk, const uint8_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES128;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES128_KEY_SIZE;
	ctx.Nr	 = AES128_NB_ROUNDS;

	return do_aes(&ctx, blk, k, inv_cipher);
}

uint8_t *aes192_decrypt(uint8_t *blk, const uint8_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES192;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES192_KEY_SIZE;
	ctx.Nr	 = AES192_NB_ROUNDS;

	return do_aes(&ctx, blk, k, inv_cipher);
}

uint8_t *aes256_decrypt(uint8_t *blk, const uint8_t *k) {
	struct aes_ctx ctx;

	ctx.type = AES256;
	ctx.Nb	 = AES_BLK_SIZE;
	ctx.Nk	 = AES256_KEY_SIZE;
	ctx.Nr	 = AES256_NB_ROUNDS;

	return do_aes(&ctx, blk, k, inv_cipher);
}
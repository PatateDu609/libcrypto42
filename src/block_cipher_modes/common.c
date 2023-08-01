#include "common.h"
#include "cipher.h"
#include "internal.h"

struct block_cipher_ctx setup_algo(enum block_cipher algo) {
	switch (algo) {
	case BLOCK_CIPHER_DES:
		return (struct block_cipher_ctx){
			.type     = algo,
			.blk_size = 8,
			.key_size = 8,
		};
	case BLOCK_CIPHER_AES128:
		return (struct block_cipher_ctx){
			.type     = algo,
			.blk_size = AES_BLK_SIZE_BYTES,
			.key_size = AES128_KEY_SIZE_BYTES,
		};
	case BLOCK_CIPHER_AES192:
		return (struct block_cipher_ctx){
			.type     = algo,
			.blk_size = AES_BLK_SIZE_BYTES,
			.key_size = AES192_KEY_SIZE_BYTES,
		};
	case BLOCK_CIPHER_AES256:
		return (struct block_cipher_ctx){
			.type     = algo,
			.blk_size = AES_BLK_SIZE_BYTES,
			.key_size = AES256_KEY_SIZE_BYTES,
		};
	default:// Unmanaged algorithm
		return (struct block_cipher_ctx){
			.type     = algo,
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
		if (ctx->plaintext == NULL && ctx->plaintext_len != 0)
			crypto42_errno = CRYPTO_PLAINTEXT_NULL;
		if (ctx->plaintext_len == 0 && ctx->plaintext != NULL)
			crypto42_errno = CRYPTO_PLAINTEXT_LEN_ZERO;
	} else {
		if (ctx->ciphertext == NULL && ctx->ciphertext_len != 0)
			crypto42_errno = CRYPTO_CIPHERTEXT_NULL;
		if (ctx->ciphertext_len == 0 && ctx->ciphertext != NULL)
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
	uint8_t padding = blk_size - (*len % blk_size);
	if (!(0 < padding && padding <= 16))
		return NULL;

	uint8_t *p = realloc(plaintext, *len + padding);
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

	size_t new_size = *len - padding;
	*len            = new_size;
	if (!new_size)
		return NULL;

	uint8_t *ptr = malloc(new_size);
	if (ptr == NULL)
		return NULL;

	memcpy(ptr, plaintext, new_size);
	return ptr;
}

void block_xor(struct block *res, const struct block *a, const struct block *b) {
	if (res->size != a->size || res->size != b->size)
		return;

	for (size_t i = 0; i < res->size; i++)
		res->data[i] = a->data[i] ^ b->data[i];
}

void block_encrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) {
	static uint8_t *(*alg_op[])(uint8_t *, const uint8_t *) = {
		[BLOCK_CIPHER_AES128] = aes128_encrypt,
		[BLOCK_CIPHER_AES192] = aes192_encrypt,
		[BLOCK_CIPHER_AES256] = aes256_encrypt,
	};
	res->size = a->size;

	switch (ctx->algo.type) {
	case BLOCK_CIPHER_DES: {
		uint64_t *blk = (uint64_t *) a->data, *key = (uint64_t *) ctx->key;
		uint64_t  raw_res = des_encrypt(bswap_64(*blk), bswap_64(*key));

		raw_res = bswap_64(raw_res);
		memcpy(res->data, &raw_res, sizeof raw_res);
		break;
	}
	case BLOCK_CIPHER_AES128:
	case BLOCK_CIPHER_AES192:
	case BLOCK_CIPHER_AES256: {
		uint8_t *fn_res = alg_op[ctx->algo.type](a->data, ctx->key);
		memcpy(res->data, fn_res, res->size);
		free(fn_res);

		break;
	}
	default:
		fprintf(stderr, "error: algorithm is not handled\n");
		exit(1);
	}
}

void block_decrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) {
	res->size                                               = a->size;
	static uint8_t *(*alg_op[])(uint8_t *, const uint8_t *) = {
		[BLOCK_CIPHER_AES128] = aes128_decrypt,
		[BLOCK_CIPHER_AES192] = aes192_decrypt,
		[BLOCK_CIPHER_AES256] = aes256_decrypt,
	};

	switch (ctx->algo.type) {
	case BLOCK_CIPHER_DES: {
		uint64_t *blk = (uint64_t *) a->data, *key = (uint64_t *) ctx->key;
		uint64_t  raw_res = des_decrypt(bswap_64(*blk), bswap_64(*key));

		raw_res = bswap_64(raw_res);
		memcpy(res->data, &raw_res, sizeof raw_res);
		break;
	}
	case BLOCK_CIPHER_AES128:
	case BLOCK_CIPHER_AES192:
	case BLOCK_CIPHER_AES256: {
		uint8_t *fn_res = alg_op[ctx->algo.type](a->data, ctx->key);
		memcpy(res->data, fn_res, res->size);
		free(fn_res);
		break;
	}
	default:
		fprintf(stderr, "error: algorithm is not handled\n");
		exit(1);
	}
}
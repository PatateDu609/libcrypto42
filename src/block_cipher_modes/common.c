#include "common.h"
#include "cipher.h"
#include "internal.h"

static inline struct algo get_algo(enum block_cipher cipher) {
	union {
		struct algo       alg;
		enum block_cipher cipher;
	} conv;

	conv.cipher = cipher;

	return conv.alg;
}

enum cipher_mode block_cipher_get_mode(enum block_cipher type) {
	struct algo alg = get_algo(type);

	return alg._mode;
}

enum algo_types get_block_cipher_algorithm(enum block_cipher type) {
	struct algo alg = get_algo(type);

	return alg._alg;
}

struct cipher_ctx *new_cipher_context(enum block_cipher algo) {
	struct cipher_ctx *ctx = calloc(1, sizeof *ctx);
	if (!ctx) return NULL;

	ctx->algo = setup_algo(algo);
	if (!ctx->algo.blk_size)
	{
		free(ctx);
		crypto42_errno = CRYPTO_ALGO_UNKNOWN;
		return NULL;
	}

	enum cipher_mode mode = block_cipher_get_mode(algo);

	if (mode == CIPHER_MODE_CTR) {
		ctx->nonce_len = ctx->algo.blk_size;
		ctx->nonce = calloc(ctx->nonce_len, sizeof *ctx->nonce);
		if (!ctx->nonce) {
			free(ctx);
			return NULL;
		}
	} else if (mode != CIPHER_MODE_ECB) {
		ctx->iv_len = ctx->algo.blk_size;
		ctx->iv = calloc(ctx->iv_len, sizeof *ctx->iv);
		if (!ctx->iv) {
			free(ctx);
			return NULL;
		}
	}

	return ctx;
}

struct block_cipher_ctx setup_algo(enum block_cipher algo) {
	size_t           blk_size, key_size, mode_blk_size_bits;

	enum algo_types  type = get_block_cipher_algorithm(algo);
	enum cipher_mode mode = block_cipher_get_mode(algo);

	switch (type) {
	case ALGO_TYPE_DES:
		blk_size = 8;
		key_size = 8;
		break;

	case ALGO_TYPE_3DES_EDE2:
		blk_size = 8;
		key_size = 16;
		break;

	case ALGO_TYPE_3DES_EDE3:
		blk_size = 8;
		key_size = 24;
		break;

	case ALGO_TYPE_AES128:
		blk_size = AES_BLK_SIZE_BYTES;
		key_size = AES128_KEY_SIZE_BYTES;
		break;
	case ALGO_TYPE_AES192:
		blk_size = AES_BLK_SIZE_BYTES;
		key_size = AES192_KEY_SIZE_BYTES;
		break;
	case ALGO_TYPE_AES256:
		blk_size = AES_BLK_SIZE_BYTES;
		key_size = AES256_KEY_SIZE_BYTES;
		break;

	default:// Unmanaged algorithm
		return (struct block_cipher_ctx){
			.type               = algo,
			.blk_size           = 0,
			.mode_blk_size_bits = 0,
		};
	}

	switch (mode) {
	case CIPHER_MODE_CBC:
	case CIPHER_MODE_ECB:
		mode_blk_size_bits = 0;
		break;
	case CIPHER_MODE_OFB:
	case CIPHER_MODE_CFB:
	case CIPHER_MODE_CTR:
		mode_blk_size_bits = 8 * blk_size;
		break;
	case CIPHER_MODE_CFB1:
		mode_blk_size_bits = 1;
		break;
	case CIPHER_MODE_CFB8:
		mode_blk_size_bits = 8;
		break;
	}

	return (struct block_cipher_ctx){
		.type               = algo,
		.blk_size           = blk_size,
		.key_size           = key_size,
		.mode_blk_size_bits = mode_blk_size_bits,
	};
}

bool __init_cipher_mode_enc(struct cipher_ctx *ctx, enum cipher_mode mode) {
	if (!__cipher_ctx_valid(ctx, mode, true))
		return false;

	if (mode == CIPHER_MODE_ECB || mode == CIPHER_MODE_CBC) {
		uint8_t *p = pad(ctx->plaintext, &ctx->plaintext_len, ctx->algo.blk_size);
		if (p == NULL) {
			perror("error: couldn't allocate memory");
			return false;
		}

		ctx->plaintext = p;
	}

	if (ctx->ciphertext_len == ctx->plaintext_len && ctx->ciphertext) {
		memset(ctx->ciphertext, 0, ctx->ciphertext_len);
	} else {
		ctx->ciphertext_len = ctx->plaintext_len;
		ctx->ciphertext     = calloc(ctx->ciphertext_len, sizeof *ctx->ciphertext);
	}

	return true;
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
		if ((cipher_mode == CIPHER_MODE_ECB || cipher_mode == CIPHER_MODE_CBC) &&
		    ctx->ciphertext_len % ctx->algo.blk_size != 0)
			crypto42_errno = CRYPTO_CIPHERTEXT_BLKSIZE_UNMATCH;
	}
	if (cipher_mode == CIPHER_MODE_CTR) {
		if (ctx->nonce == NULL)
			crypto42_errno = CRYPTO_NONCE_NULL;
		if (ctx->nonce_len == 0)
			crypto42_errno = CRYPTO_NONCE_LEN_ZERO;
		if (ctx->nonce_len != ctx->algo.blk_size)
			crypto42_errno = CRYPTO_NONCE_BLKSIZE_UNMATCH;
	} else if (cipher_mode != CIPHER_MODE_ECB) {
		if (ctx->iv == NULL)
			crypto42_errno = CRYPTO_IV_NULL;
		if (ctx->iv_len == 0)
			crypto42_errno = CRYPTO_IV_LEN_ZERO;
		if (ctx->iv_len != ctx->algo.blk_size)
			crypto42_errno = CRYPTO_IV_BLKSIZE_UNMATCH;
	}

	return err == crypto42_errno;
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

static uint8_t gen_mask(size_t start, size_t nb) {
	if (!nb)
		return 0;

	nb     = (nb > 8) ? 8 : nb;
	start %= 8;

	size_t  end = start + nb;

	uint8_t mask = 0;

	for (size_t i = 1 << 7, idx = 0; i > 0 && idx < end; i >>= 1, idx++) {
		if (idx < start)
			continue;
		mask |= i;
	}

	return mask;
}

void block_xor(struct block *res, const struct block *a, const struct block *b) {
	size_t min_size = res->size;

	if (a->size < min_size)
		min_size = a->size;
	if (b->size < min_size)
		min_size = b->size;

	for (size_t i = 0; i < min_size; i++)
		res->data[i] = a->data[i] ^ b->data[i];
}

void block_left_shift(struct block *a, size_t n) {
	size_t q, r;

	q = n / 8;
	if (q >= a->size) {
		memset(a->data, 0, a->size * sizeof *a->data);
		return;
	}

	r = n % 8;

	if (q) {
		memmove(a->data, a->data + q, (a->size - q) * sizeof *a->data);
		memset(a->data + (a->size - q), 0, q * sizeof *a->data);
	}

	if (r) {
		if (a->size == 1) {
			a->data[0] <<= n;
			return;
		}

		uint8_t mask = gen_left_mask(r), remaining_bits = (8 - r);

		for (size_t i = 0; i < a->size; i++) {
			uint8_t current = a->data[i];
			uint8_t next    = i + 1 < a->size ? a->data[i + 1] : 0;

			current = (current << n) | ((next & mask) >> remaining_bits);

			a->data[i] = current;
		}
	}
}

void block_right_shift(struct block *a, size_t s) {
	if (!s)
		return;

	const size_t quotient  = s / 8;
	const size_t remaining = s % 8;

	if (quotient) {
		memmove(a->data + quotient, a->data, (a->size - quotient) * sizeof *a->data);
		memset(a->data, 0, quotient * sizeof *a->data);
	}

	if (!remaining)
		return;

	const uint8_t mask = gen_right_mask(remaining);
	for (ssize_t i = (ssize_t) a->size - 1; i >= (ssize_t) quotient; i--) {
		uint8_t current = a->data[i];
		uint8_t prev    = i ? a->data[i - 1] : 0;

		current = (current >> remaining) | ((prev & mask) << (8 - remaining));

		a->data[i] = current;
	}
}

struct block *block_bit_extract(const struct block *blk, size_t sub) {
	struct block *res = calloc(1, sizeof *res);
	if (res == NULL)
		return NULL;

	size_t remaining = sub % 8;
	size_t quotient  = sub / 8;
	size_t extracted_size;
	bool   is_exact = !remaining;


	res->size = blk->size;
	res->data = calloc(res->size, sizeof *res->data);
	if (res->data == NULL) {
		free(res);
		return NULL;
	}

	extracted_size = quotient + !is_exact;
	extracted_size = (extracted_size > blk->size) ? blk->size : extracted_size;
	memcpy(res->data, blk->data, (extracted_size - !is_exact) * sizeof *res->data);

	if (is_exact)
		return res;

	uint8_t mask                  = gen_left_mask(remaining);
	res->data[extracted_size - 1] = blk->data[extracted_size - 1] & mask;

	return res;
}

void block_bit_assign(struct block *res, struct block *src, size_t start, size_t nb) {
	size_t byte_start = start / 8;
	if (res->size <= byte_start) {
		return;
	}

	size_t bit_start = start % 8;
	size_t local_nb  = 8 - bit_start;
	if (nb < local_nb)
		local_nb = nb;

	uint8_t mask          = gen_mask(start, local_nb);
	res->data[byte_start] = (res->data[byte_start] & ~mask) | (src->data[byte_start] & mask);

	nb -= local_nb;
	if (nb == 0)
		return;

	size_t byte_nb = nb / 8;
	byte_start++;

	if (res->size < byte_nb + byte_start)
		byte_nb = res->size - byte_start;

	if (byte_nb)
		memcpy(res->data + byte_start, src->data + byte_start, byte_nb * sizeof *src->data);

	size_t byte_remaining = res->size - byte_nb - byte_start;
	if (!byte_remaining)
		return;

	byte_start += byte_nb;
	nb         -= 8 * byte_nb;
	if (!nb)
		return;

	mask                  = gen_left_mask(nb);
	res->data[byte_start] = (res->data[byte_start] & ~mask) | (src->data[byte_start] & mask);
}

void block_increment(struct block *blk, size_t bit_limit) {
	int32_t tmp;
	size_t  computed     = 0;
	size_t  r            = bit_limit % 8;
	r                    = r == 0 ? 8 : r;
	size_t last_blk_mask = gen_right_mask(r);

	for (ssize_t i = (ssize_t) (blk->size - 1); i >= 0 && computed < bit_limit; i--, computed += 8) {
		uint8_t current = blk->data[i];
		tmp             = current + 1;

		if (computed + 8 < bit_limit) {
			if (tmp <= UINT8_MAX) {
				blk->data[i] = tmp;
				break;
			} else
				blk->data[i] = 0;
		} else {
			blk->data[i] = (current & ~last_blk_mask) | (tmp & last_blk_mask);
			break;
		}
	}
}

struct block *block_dup(const struct block *src) {
	struct block *res = calloc(1, sizeof *res);
	if (!res)
		return NULL;

	res->size = src->size;

	if (!(res->data = calloc(res->size, sizeof *res->data))) {
		free(res);
		return NULL;
	}

	memcpy(res->data, src->data, res->size * sizeof *res->data);
	return res;
}

struct block *block_dup_data(uint8_t *data, size_t size) {
	struct block blk;
	blk.size = size;
	blk.data = data;

	return block_dup(&blk);
}

struct block *block_create(size_t size) {
	struct block *res = calloc(1, sizeof *res);
	if (!res)
		return NULL;

	res->size = size;

	if (!(res->data = calloc(res->size, sizeof *res->data))) {
		free(res);
		return NULL;
	}

	return res;
}

void block_delete(struct block *blk) {
	if (blk) {
		free(blk->data);
		free(blk);
	}
}

void block_encrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) {
	static uint8_t *(*alg_op[])(uint8_t *, const uint8_t *) = {
		[ALGO_TYPE_AES128] = aes128_encrypt,       [ALGO_TYPE_AES192] = aes192_encrypt,
		[ALGO_TYPE_AES256] = aes256_encrypt,       [ALGO_TYPE_DES] = des_encrypt,
		[ALGO_TYPE_3DES_EDE3] = tdes_ede3_encrypt, [ALGO_TYPE_3DES_EDE2] = tdes_ede2_encrypt,
	};
	res->size = a->size;

	const enum algo_types type = get_block_cipher_algorithm(ctx->algo.type);

	uint8_t              *fn_res = alg_op[type](a->data, ctx->key);
	memcpy(res->data, fn_res, res->size);
	free(fn_res);
}

void block_decrypt(const struct cipher_ctx *ctx, struct block *res, const struct block *a) {
	res->size                                               = a->size;
	static uint8_t *(*alg_op[])(uint8_t *, const uint8_t *) = {
		[ALGO_TYPE_AES128] = aes128_decrypt,       [ALGO_TYPE_AES192] = aes192_decrypt,
		[ALGO_TYPE_AES256] = aes256_decrypt,       [ALGO_TYPE_DES] = des_decrypt,
		[ALGO_TYPE_3DES_EDE3] = tdes_ede3_decrypt, [ALGO_TYPE_3DES_EDE2] = tdes_ede2_decrypt,
	};

	const enum algo_types type = get_block_cipher_algorithm(ctx->algo.type);

	uint8_t              *fn_res = alg_op[type](a->data, ctx->key);
	memcpy(res->data, fn_res, res->size);
	free(fn_res);
}
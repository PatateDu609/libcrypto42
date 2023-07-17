#include "cipher.h"
#include "internal.h"
#include "test.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>
#include <criterion/parameterized.h>
#include <openssl/evp.h>

#define NB_AES_ENCRYPT_TEST 64
#define NB_AES_DECRYPT_TEST NB_AES_ENCRYPT_TEST

struct aes_test_params {
	uint8_t *blk;
	uint8_t *k;
};

typedef uint8_t *(do_aes) (uint8_t *, const uint8_t *);

static void do_encrypt_test(const char *alg, do_aes aes, struct aes_test_params *param) {
	uint8_t	   *mine = aes(param->blk, param->k);

	EVP_CIPHER *cp = EVP_CIPHER_fetch(NULL, alg, NULL);
	cr_assert(ne(ptr, cp, NULL));
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	cr_assert(ne(ptr, ctx, NULL));
	int blk_len = EVP_CIPHER_get_block_size(cp), expected_len = blk_len;
	cr_assert(eq(i32, expected_len, AES_BLK_SIZE_BYTES));
	uint8_t *expected_data = OPENSSL_malloc(expected_len);
	cr_assert(ne(ptr, expected_data, NULL));

	EVP_EncryptInit_ex2(ctx, cp, param->k, NULL, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, expected_data, &expected_len, param->blk, blk_len);
	EVP_EncryptFinal_ex(ctx, expected_data, &expected_len);

	EVP_CIPHER_free(cp);
	EVP_CIPHER_CTX_free(ctx);

	struct cr_mem actual = {
		.data = mine,
		.size = AES_BLK_SIZE_BYTES,
	};
	struct cr_mem expected = {
		.data = expected_data,
		.size = blk_len,
	};

	cr_expect(eq(mem, actual, expected));

	OPENSSL_free(expected_data);
	free(mine);
}

static void do_decrypt_test(const char *alg, do_aes aes, struct aes_test_params *param) {
	uint8_t	   *mine = aes(param->blk, param->k);

	EVP_CIPHER *cp = EVP_CIPHER_fetch(NULL, alg, NULL);
	cr_assert(ne(ptr, cp, NULL));
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	cr_assert(ne(ptr, ctx, NULL));
	int blk_len = EVP_CIPHER_get_block_size(cp), expected_len = blk_len;
	cr_assert(eq(i32, expected_len, AES_BLK_SIZE_BYTES));
	uint8_t *expected_data = OPENSSL_malloc(expected_len);
	cr_assert(ne(ptr, expected_data, NULL));

	EVP_DecryptInit_ex2(ctx, cp, param->k, NULL, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_DecryptUpdate(ctx, expected_data, &expected_len, param->blk, blk_len);
	EVP_DecryptFinal_ex(ctx, expected_data, &expected_len);

	EVP_CIPHER_free(cp);
	EVP_CIPHER_CTX_free(ctx);

	struct cr_mem actual = {
		.data = mine,
		.size = AES_BLK_SIZE_BYTES,
	};
	struct cr_mem expected = {
		.data = expected_data,
		.size = blk_len,
	};

	cr_expect(eq(mem, actual, expected));

	OPENSSL_free(expected_data);
	free(mine);
}

__unused static void setup_suite(void) {
	srand(((uint32_t) time(NULL) ^ getpid()) >> (getpid() % 32));
}

TestSuite(AES128, .init = setup_suite);
TestSuite(AES192, .init = setup_suite);
TestSuite(AES256, .init = setup_suite);

static void create_test_param(struct aes_test_params *param, size_t key_size) {
	const static size_t blk_size = AES_BLK_SIZE;

	param->blk = gen_u8_arr(blk_size * 4, true);
	param->k   = gen_u8_arr(key_size * 4, true);
}

static void free_aes_test_params(struct criterion_test_params *ctp) {
	struct aes_test_params *params = (struct aes_test_params *) ctp->params;

	for (size_t i = 0; i < ctp->length; i++) {
		cr_free(params[i].blk);
		cr_free(params[i].k);
	}
}

ParameterizedTestParameters(AES128, encrypt) {
	static struct aes_test_params params[NB_AES_ENCRYPT_TEST];

	for (size_t i = 0; i < NB_AES_ENCRYPT_TEST; i++) {
		create_test_param(params + i, AES128_KEY_SIZE);
	}

	return cr_make_param_array(struct aes_test_params, params, NB_AES_ENCRYPT_TEST, free_aes_test_params);
}

ParameterizedTest(struct aes_test_params *param, AES128, encrypt) {
	do_encrypt_test("AES-128-ECB", aes128_encrypt, param);
}

ParameterizedTestParameters(AES128, decrypt) {
	static struct aes_test_params params[NB_AES_DECRYPT_TEST];

	for (size_t i = 0; i < NB_AES_DECRYPT_TEST; i++) {
		create_test_param(params + i, AES128_KEY_SIZE);
	}

	return cr_make_param_array(struct aes_test_params, params, NB_AES_DECRYPT_TEST, free_aes_test_params);
}

ParameterizedTest(struct aes_test_params *param, AES128, decrypt) {
	do_decrypt_test("AES-128-ECB", aes128_decrypt, param);
}

ParameterizedTestParameters(AES192, encrypt) {
	static struct aes_test_params params[NB_AES_ENCRYPT_TEST];

	for (size_t i = 0; i < NB_AES_ENCRYPT_TEST; i++) {
		create_test_param(params + i, AES192_KEY_SIZE);
	}

	return cr_make_param_array(struct aes_test_params, params, NB_AES_ENCRYPT_TEST, free_aes_test_params);
}

ParameterizedTest(struct aes_test_params *param, AES192, encrypt) {
	do_encrypt_test("AES-192-ECB", aes192_encrypt, param);
}

ParameterizedTestParameters(AES192, decrypt) {
	static struct aes_test_params params[NB_AES_DECRYPT_TEST];

	for (size_t i = 0; i < NB_AES_DECRYPT_TEST; i++) {
		create_test_param(params + i, AES192_KEY_SIZE);
	}

	return cr_make_param_array(struct aes_test_params, params, NB_AES_DECRYPT_TEST, free_aes_test_params);
}

ParameterizedTest(struct aes_test_params *param, AES192, decrypt) {
	do_decrypt_test("AES-192-ECB", aes192_decrypt, param);
}

ParameterizedTestParameters(AES256, encrypt) {
	static struct aes_test_params params[NB_AES_ENCRYPT_TEST];

	for (size_t i = 0; i < NB_AES_ENCRYPT_TEST; i++)
		create_test_param(params + i, AES256_KEY_SIZE);

	return cr_make_param_array(struct aes_test_params, params, NB_AES_ENCRYPT_TEST, free_aes_test_params);
}

ParameterizedTest(struct aes_test_params *param, AES256, encrypt) {
	do_encrypt_test("AES-256-ECB", aes256_encrypt, param);
}

ParameterizedTestParameters(AES256, decrypt) {
	static struct aes_test_params params[NB_AES_DECRYPT_TEST];

	for (size_t i = 0; i < NB_AES_DECRYPT_TEST; i++) {
		create_test_param(params + i, AES256_KEY_SIZE);
	}

	return cr_make_param_array(struct aes_test_params, params, NB_AES_DECRYPT_TEST, free_aes_test_params);
}

ParameterizedTest(struct aes_test_params *param, AES256, decrypt) {
	do_decrypt_test("AES-256-ECB", aes256_decrypt, param);
}

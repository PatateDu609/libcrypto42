#include "cipher.h"
#include "test.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>
#include <criterion/parameterized.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <unistd.h>

struct block_cipher_test_params {
	uint8_t				   *key;
	size_t					key_size;

	struct block_cipher_ctx block_ctx;
	char				   *evp_alg;

	size_t					plaintext_size;
	uint8_t				   *plaintext;
};

__unused static void setup_suite(void) {
	srand(((uint32_t) time(NULL) ^ getpid()) >> (getpid() % 32));
}

TestSuite(AES128_modes, .init = setup_suite);
TestSuite(AES192_modes, .init = setup_suite);
TestSuite(AES256_modes, .init = setup_suite);

static void free_block_cipher_params(struct criterion_test_params *ctp) {
	struct block_cipher_test_params *params = (struct block_cipher_test_params *) ctp->params;

	for (size_t i = 0; i < ctp->length; i++) {
		cr_log_info("Freeing test param %zu/%zu", i + 1, ctp->length);
		cr_free(params[i].key);
		params[i].key = NULL;

		cr_free(params[i].evp_alg);
		params[i].evp_alg = NULL;
	}
}

static void do_block_cipher_test(const struct block_cipher_test_params *param) {
	struct cr_mem actual, expected;
	actual.data = expected.data = NULL;

	{
		struct cipher_ctx ctx;
		ctx.algo		  = param->block_ctx;
		ctx.key_len		  = param->key_size;
		ctx.key			  = param->key;
		ctx.plaintext_len = param->plaintext_size;
		ctx.plaintext	  = memdup(param->plaintext, param->plaintext_size, false);

		cr_assert(ne(ptr, ECB_encrypt(&ctx), NULL));

		actual.data = ctx.ciphertext;
		actual.size = ctx.ciphertext_len;
		free(ctx.plaintext);
	}

	{
		int			expected_len = (int) param->plaintext_size;


		EVP_CIPHER *cp = EVP_CIPHER_fetch(NULL, param->evp_alg, NULL);
		cr_assert(ne(ptr, cp, NULL));

		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		cr_assert(ne(ptr, ctx, NULL));


		uint8_t *expected_data = OPENSSL_malloc(expected_len);
		cr_assert(ne(ptr, expected_data, NULL));

		EVP_EncryptInit_ex2(ctx, cp, param->key, NULL, NULL);

		EVP_EncryptUpdate(ctx, expected_data, &expected_len, param->plaintext, expected_len);
		expected.size = expected_len;

		EVP_EncryptFinal_ex(ctx, expected_data + expected_len, &expected_len);
		expected.size += expected_len;

		EVP_CIPHER_free(cp);
		EVP_CIPHER_CTX_free(ctx);

		expected.data = expected_data;
	}

	cr_expect(eq(mem, actual, expected));

	free((void *) actual.data);
	OPENSSL_free((void *) expected.data);
}

ParameterizedTestParameters(AES128_modes, ecb_encrypt) {
	static struct block_cipher_test_params params[] = {
		{ .plaintext_size = 6 },  { .plaintext_size = 16 }, { .plaintext_size = 32 },
		{ .plaintext_size = 40 }, { .plaintext_size = 48 }, { .plaintext_size = 387 },
	};
	const size_t size = sizeof params / sizeof *params;

	for (size_t i = 0; i < size; i++) {
		cr_log_info("Creating test param %zu/%zu", i + 1, size);
		params[i].block_ctx = setup_algo(BLOCK_CIPHER_AES128);
		params[i].key_size	= params[i].block_ctx.key_size;

		params[i].key = gen_u8_arr(params[i].key_size, true);
		cr_log_info("params[%zu].key = %p", i, params[i].key);

		const char *evp_alg = "AES-128-ECB";
		params[i].evp_alg	= memdup(evp_alg, strlen(evp_alg) + 1, true);
		cr_log_info("params[%zu].evp_alg = %p", i, params[i].evp_alg);
	}

	return cr_make_param_array(struct block_cipher_test_params, params, size, free_block_cipher_params);
}

ParameterizedTest(struct block_cipher_test_params *param, AES128_modes, ecb_encrypt) {
	param->plaintext = gen_u8_arr(param->plaintext_size, false);

	do_block_cipher_test(param);

	free(param->plaintext);
}

ParameterizedTestParameters(AES192_modes, ecb_encrypt) {
	static struct block_cipher_test_params params[] = {
		{ .plaintext_size = 6 },  { .plaintext_size = 16 }, { .plaintext_size = 32 },
		{ .plaintext_size = 40 }, { .plaintext_size = 48 }, { .plaintext_size = 387 },
	};
	const size_t size = sizeof params / sizeof *params;

	for (size_t i = 0; i < size; i++) {
		cr_log_info("Creating test param %zu/%zu", i + 1, size);
		params[i].block_ctx = setup_algo(BLOCK_CIPHER_AES192);
		params[i].key_size	= params[i].block_ctx.key_size;

		params[i].key = gen_u8_arr(params[i].key_size, true);

		const char *evp_alg = "AES-192-ECB";
		params[i].evp_alg	= memdup(evp_alg, strlen(evp_alg) + 1, true);
	}

	return cr_make_param_array(struct block_cipher_test_params, params, size, free_block_cipher_params);
}

ParameterizedTest(struct block_cipher_test_params *param, AES192_modes, ecb_encrypt) {
	param->plaintext = gen_u8_arr(param->plaintext_size, false);

	do_block_cipher_test(param);

	free(param->plaintext);
}

ParameterizedTestParameters(AES256_modes, ecb_encrypt) {
	static struct block_cipher_test_params params[] = {
		{ .plaintext_size = 6 },  { .plaintext_size = 16 }, { .plaintext_size = 32 },
		{ .plaintext_size = 40 }, { .plaintext_size = 48 }, { .plaintext_size = 387 },
	};
	const size_t size = sizeof params / sizeof *params;

	for (size_t i = 0; i < size; i++) {
		cr_log_info("Creating test param %zu/%zu", i + 1, size);
		params[i].block_ctx = setup_algo(BLOCK_CIPHER_AES256);
		params[i].key_size	= params[i].block_ctx.key_size;

		params[i].key = gen_u8_arr(params[i].key_size, true);

		const char *evp_alg = "AES-256-ECB";
		params[i].evp_alg	= memdup(evp_alg, strlen(evp_alg) + 1, true);
	}

	return cr_make_param_array(struct block_cipher_test_params, params, size, free_block_cipher_params);
}

ParameterizedTest(struct block_cipher_test_params *param, AES256_modes, ecb_encrypt) {
	param->plaintext = gen_u8_arr(param->plaintext_size, false);

	do_block_cipher_test(param);

	free(param->plaintext);
	param->plaintext = NULL;
}
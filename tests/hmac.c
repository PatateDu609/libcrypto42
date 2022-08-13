#include "tests.h"
#include "hmac.h"
#include "crypto.h"
#include "libft.h"
#include <stdlib.h>
#include <stdio.h>
#include <CUnit/Basic.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

typedef const EVP_MD *(*EVP_hash)(void);

static void get_hmac(EVP_hash func, const void *key, size_t key_len, const void *msg, size_t msg_len, char *hash, size_t output)
{
	unsigned char result[output];
	HMAC(func(), key, key_len, msg, msg_len, result, NULL);

	get_output(result, output, hash);
}

static void get_hmac_actual(enum hmac_algorithm alg, const char *key, const char *msg, char *hash)
{
	struct hmac_req req;
	req.ctx = hmac_setup(alg);

	uint8_t res[req.ctx.L];

	req.key = (uint8_t *)key;
	req.key_len = ft_strlen(key);
	req.message = (uint8_t *)msg;
	req.message_len = ft_strlen(msg);
	req.res_hmac = res;

	hmac(req);
	get_output(res, req.ctx.L, hash);
}

static void HMAC_sha2_256_single_test(const char *key, const char *message)
{
	size_t size_digest = 32;
	char expected[size_digest * 2 + 1];
	char actual[size_digest * 2 + 1];

	get_hmac(EVP_sha256, key, ft_strlen(key), message, ft_strlen(message), expected, size_digest);
	get_hmac_actual(HMAC_SHA2_256, key, message, actual);
	CU_ASSERT_STRING_EQUAL(actual, expected);
}

void HMAC_sha2_256_test()
{
	HMAC_sha2_256_single_test("", "");
	HMAC_sha2_256_single_test("", "a");
	HMAC_sha2_256_single_test("a", "");
	HMAC_sha2_256_single_test("a", "a");
	HMAC_sha2_256_single_test("key", "The quick brown fox jumps over the lazy dog");
	HMAC_sha2_256_single_test("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog", "message");
}

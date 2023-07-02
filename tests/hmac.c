#include "hmac.h"
#include "crypto.h"
#include "test.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>
#include <criterion/parameterized.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

typedef const EVP_MD *(*EVP_hash)(void);

struct hmac_test_params {
	char *key;
	char *msg;
};

static void get_hmac(EVP_hash func, const void *key, size_t key_len, const void *msg, size_t msg_len, char *hash,
					 size_t output) {
	unsigned char result[output];
	HMAC(func(), key, (int) key_len, msg, msg_len, result, NULL);

	get_output(result, output, hash);
}

static void get_hmac_actual(enum hmac_algorithm alg, const char *key, const char *msg, char *hash) {
	struct hmac_req req;
	req.ctx = hmac_setup(alg);

	uint8_t res[req.ctx.L];

	req.key			= (uint8_t *) key;
	req.key_len		= strlen(key);
	req.message		= (uint8_t *) msg;
	req.message_len = strlen(msg);
	req.res_hmac	= res;

	hmac(req);
	get_output(res, (int) req.ctx.L, hash);
}

char *test_copy(char *str) {
	size_t len = strlen(str);
	char  *tmp = cr_calloc(len, sizeof(char));

	strcpy(tmp, str);

	return tmp;
}

void cleanup_params(struct criterion_test_params *cr_params) {
	struct hmac_test_params *params = (struct hmac_test_params *)cr_params->params;

	for (size_t i = 0; i < cr_params->size; i++) {
		cr_free(params[i].key);
		cr_free(params[i].msg);
	}
}

ParameterizedTestParameters(hmac, sha2_256) {
	static struct hmac_test_params params[] = {
		{
			.key = "",
			.msg = "",
		 },
		{
			.key = "",
			.msg = "a",
		 },
		{
			.key = "a",
			.msg = "",
		 },
		{
			.key = "a",
			.msg = "a",
		 },
		{
			.key = "key",
			.msg = "The quick brown fox jumps over the lazy dog",
		 },
		{
			.key = "The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog",
			.msg = "message",
		 },
	};
	static bool is_init = true;

	size_t		nb_params = sizeof params / sizeof *params;

	if (is_init) {
		is_init = false;

		for (size_t i = 0; i < nb_params; i++) {
			params[i].key = test_copy(params[i].key);
			params[i].msg = test_copy(params[i].msg);
		}
	}

	return cr_make_param_array(struct hmac_test_params, params, nb_params, cleanup_params);
}

ParameterizedTest(struct hmac_test_params *param, hmac, sha2_256) {
	size_t size_digest = 32;
	char   expected[size_digest * 2 + 1];
	char   actual[size_digest * 2 + 1];

	char  *key	   = param->key;
	char  *message = param->msg;

	get_hmac(EVP_sha256, key, strlen(key), message, strlen(message), expected, size_digest);
	get_hmac_actual(HMAC_SHA2_256, key, message, actual);
	cr_expect(eq(str, actual, expected, "expected %s, got %s", expected, actual));
}
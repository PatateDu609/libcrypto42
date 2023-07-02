#include "crypto.h"
#include "test.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>
#include <openssl/evp.h>
#include <string.h>

const char *digest_test_strings[NB_DIGEST_TEST_STRINGS] = {
	"",
	"a",
	"abc",
	"message digest",
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	"The quick brown fox jumps over the lazy dog",
	"The quick brown fox jumps over the lazy dog.",
	"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.",
};

const char *digest_test_filenames[NB_DIGEST_TEST_FILES] = {
	"/etc/passwd",
	"src/tests/digest.c",
	"src/tests/resources/empty",
	"src/tests/resources/basic",
	"src/tests/resources/big_file",
	"src/tests/resources/bigger_file",
	"src/tests/resources/huge_file",
};

static void get_hash(const EVP_MD *md, char *hash, const char *msg) {
	unsigned char *result = calloc(EVP_MD_size(md), sizeof *result);
	cr_assert(not(eq(ptr, result, NULL)));


	cr_assert(eq(i32, EVP_Digest((const uint8_t *) msg, strlen(msg), result, NULL, md, NULL), 1));
	get_output(result, EVP_MD_size(md), hash);
	free(result);
}

static void get_hash_file(const EVP_MD *md, char *hash, const char *filename) {
	FILE  *file	 = fopen(filename, "r");
	size_t bytes = 0;

	if (!file)
		return;

	char		   buffer[4096];
	unsigned char *result = calloc(EVP_MD_size(md), sizeof *result);
	cr_assert(not(eq(ptr, result, NULL)));


	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	cr_assert(eq(i32, EVP_DigestInit_ex(ctx, md, NULL), 1, "couldn't initialize context"));

	while ((bytes = fread(buffer, 1, sizeof buffer, file)) > 0)
		cr_assert(eq(i32, EVP_DigestUpdate(ctx, buffer, bytes), 1));
	cr_assert(eq(i32, EVP_DigestFinal_ex(ctx, result, NULL), 1));

	fclose(file);
	get_output(result, EVP_MD_size(md), hash);

	EVP_MD_CTX_free(ctx);
}

void run_digest_string_test(const EVP_MD *md, const char *arg, char *(*mine)(const char *) ) {
	char *expected = calloc(2 * EVP_MD_size(md) + 1, sizeof *expected);
	cr_assert(not(eq(ptr, expected, NULL)));

	char *actual = mine(arg);

	get_hash(md, expected, arg);
	cr_expect(eq(str, expected, actual, "expected %s, got %s", expected, actual));

	free(actual);
	free(expected);
}

void run_digest_file_test(const EVP_MD *md, const char *filename, char *(*mine)(const char *) ) {
	char *expected = calloc(2 * EVP_MD_size(md) + 1, sizeof *expected);
	cr_assert(not(eq(ptr, expected, NULL)));

	char *actual = mine(filename);
	cr_assert(not(eq(ptr, actual, NULL)));

	get_hash_file(md, expected, filename);
	cr_expect(eq(str, expected, actual, "expected %s, got %s", expected, actual));

	free(actual);
	free(expected);
}
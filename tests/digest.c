#include "crypto.h"
#include "test.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>
#include <openssl/evp.h>
#include <string.h>

static const char *test_strings[] = {
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

static const char *test_filenames[] = {
	"tests/resources/empty",
	"tests/digest.c",
	"/etc/passwd",
	"tests/resources/basic",
	"tests/resources/big_file",
	"tests/resources/bigger_file",
	"tests/resources/huge_file",
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

static void do_string_test(const EVP_MD *md, char *(*mine)(const char *) ) {
	char *expected = calloc(2 * EVP_MD_size(md) + 1, sizeof *expected);
	cr_assert(not(eq(ptr, expected, NULL)));

	char *actual;

	for (size_t i = 0, nb = sizeof test_strings / sizeof *test_strings; i < nb; i++) {
		const char *str = test_strings[i];

		actual = mine(str);
		get_hash(md, expected, str);
		cr_expect(eq(str, expected, actual, "expected %s, got %s", expected, actual));
		free(actual);
	}
	free(expected);
}

static void do_file_test(const EVP_MD *md, char *(*mine)(const char *) ) {
	char *expected = calloc(2 * EVP_MD_size(md) + 1, sizeof *expected);
	cr_assert(not(eq(ptr, expected, NULL)));

	char *actual;

	for (size_t i = 0, nb = sizeof test_filenames / sizeof *test_filenames; i < nb; i++) {
		const char *filename = test_filenames[i];

		actual = mine(filename);
		get_hash_file(md, expected, filename);
		cr_expect(eq(str, expected, actual, "expected %s, got %s", expected, actual));
		free(actual);
	}
	free(expected);
}

// MD5 tests

Test(md5, strings) {
	do_string_test(EVP_md5(), md5);
}

Test(md5, files) {
	do_file_test(EVP_md5(), md5_file);
}

// SHA224 tests

Test(sha224, strings) {
	do_string_test(EVP_sha224(), sha2_224);
}

Test(sha224, files) {
	do_file_test(EVP_sha224(), sha2_224_file);
}

// SHA256 tests

Test(sha256, strings) {
	do_string_test(EVP_sha256(), sha2_256);
}

Test(sha256, files) {
	do_file_test(EVP_sha256(), sha2_256_file);
}

// SHA384 tests

Test(sha384, strings) {
	do_string_test(EVP_sha384(), sha2_384);
}

Test(sha384, files) {
	do_file_test(EVP_sha384(), sha2_384_file);
}

// SHA512 tests

Test(sha512, strings) {
	do_string_test(EVP_sha512(), sha2_512);
}

Test(sha512, files) {
	do_file_test(EVP_sha512(), sha2_512_file);
}

// SHA512_224 tests

Test(sha512_224, strings) {
	do_string_test(EVP_sha512_224(), sha2_512_224);
}

Test(sha512_224, files) {
	do_file_test(EVP_sha512_224(), sha2_512_224_file);
}

// SHA512_256 tests

Test(sha512_256, strings) {
	do_string_test(EVP_sha512_256(), sha2_512_256);
}

Test(sha512_256, files) {
	do_file_test(EVP_sha512_256(), sha2_512_256_file);
}
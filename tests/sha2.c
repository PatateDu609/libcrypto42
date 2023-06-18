#include "tests.h"
#include <CUnit/Basic.h>
#include <openssl/sha.h>
#include <stdlib.h>

static void get_hash(char *hash, unsigned char *(*SHA)(const unsigned char *, size_t, unsigned char *), const char *msg, size_t output)
{
	unsigned char result[output];

	SHA((const unsigned char *)msg, strlen(msg), result);

	get_output(result, output, hash);
}

#define get_hash_file_SHA(alg, sha_ctx, size_digest) \
	__attribute__((unused)) static void get_hash_file_sha##alg(char *hash, const char *filename) \
	{ \
		FILE *file = fopen(filename, "r+"); \
		size_t bytes = 0; \
		if (!file) \
			return; \
		char buffer[4096]; \
		unsigned char result[size_digest]; \
		SHA##sha_ctx##_CTX ctx; \
		SHA##alg##_Init(&ctx); \
		while ((bytes = fread(buffer, 1, sizeof buffer, file)) > 0) \
			SHA##alg##_Update(&ctx, buffer, bytes); \
		SHA##alg##_Final(result, &ctx); \
		fclose(file); \
		get_output(result, size_digest, hash); \
	}

get_hash_file_SHA(224, 256, SHA224_DIGEST_LENGTH)
get_hash_file_SHA(256, 256, SHA256_DIGEST_LENGTH)
get_hash_file_SHA(384, 512, SHA384_DIGEST_LENGTH)
get_hash_file_SHA(512, 512, SHA512_DIGEST_LENGTH)

#define SHA_STRING_TEST(alg, sha_ctx, size_digest, msg, name) \
	SHA_STRING_TEST_PROTO(alg, name) \
	{\
		char expected[size_digest * 2 + 1]; \
		char *actual = sha2_##alg(msg); \
		get_hash(expected, SHA##alg, msg, size_digest); \
		CU_ASSERT_STRING_EQUAL(expected, actual); \
		free(actual); \
	}

#define SHA_FILE_TEST(alg, sha_ctx, size_digest, filename, name) \
	SHA_FILE_TEST_PROTO(alg, name) \
	{\
		char *actual = sha2_##alg##_file(filename); \
		char expected[size_digest * 2 + 1]; \
		get_hash_file_sha##alg(expected, filename); \
		CU_ASSERT_STRING_EQUAL(expected, actual); \
		free(actual); \
	}

#define SHA_TEST_SUITE(alg, sha_ctx, size_digest) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "", empty_string) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "a", a) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "abc", abc) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "message digest", message_digest) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "abcdefghijklmnopqrstuvwxyz", alphabet) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", alnum) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", num2) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "The quick brown fox jumps over the lazy dog", lorem_ipsum) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "The quick brown fox jumps over the lazy dog.", lorem_ipsum_edit) \
	SHA_STRING_TEST(alg, sha_ctx, size_digest, "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.", lorem_ipsum_double) \
	\
	SHA_FILE_TEST(alg, sha_ctx, size_digest, "tests/resources/empty", empty) \
	SHA_FILE_TEST(alg, sha_ctx, size_digest, "tests/md5.c", test_md5) \
	SHA_FILE_TEST(alg, sha_ctx, size_digest, "/etc/passwd", etc_passwd) \
	SHA_FILE_TEST(alg, sha_ctx, size_digest, "tests/resources/basic", basic) \
	SHA_FILE_TEST(alg, sha_ctx, size_digest, "tests/resources/big_file", big_file) \
	SHA_FILE_TEST(alg, sha_ctx, size_digest, "tests/resources/bigger_file", bigger_file) \
	SHA_FILE_TEST(alg, sha_ctx, size_digest, "tests/resources/huge_file", huge_file)


SHA_TEST_SUITE(224, 256, SHA224_DIGEST_LENGTH)
SHA_TEST_SUITE(256, 256, SHA256_DIGEST_LENGTH)

SHA_TEST_SUITE(384, 512, SHA384_DIGEST_LENGTH)
SHA_TEST_SUITE(512, 512, SHA512_DIGEST_LENGTH)

#include "tests.h"
#include <CUnit/Basic.h>
#include <openssl/md5.h>
#include <stdlib.h>

static void get_output(const unsigned char *result, char *hash)
{
	// output
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		snprintf(&hash[i * 2], 3, "%02x", result[i]);
	}
}

static void get_hash(char *hash, const char *msg)
{
	unsigned char result[MD5_DIGEST_LENGTH];

	MD5((const unsigned char *)msg, strlen(msg), result);

	get_output(result, hash);
}

static void get_hash_file(char *hash, const char *filename)
{
	FILE *file = fopen(filename, "r");
	size_t bytes = 0;

	if (!file)
		return;

	char buffer[4096];
	unsigned char result[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;
	MD5_Init(&ctx);

	while ((bytes = fread(buffer, 1, sizeof buffer, file)) > 0)
		MD5_Update(&ctx, buffer, bytes);
	MD5_Final(result, &ctx);
	fclose(file);
	get_output(result, hash);
}

#define MD5_STRING_TEST(str, name) \
	MD5_STRING_TEST_PROTO(name) \
	{\
		char expected[MD5_DIGEST_LENGTH * 2 + 1]; \
		char *actual = md5(str); \
		get_hash(expected, str); \
		CU_ASSERT_STRING_EQUAL(expected, actual); \
		free(actual); \
	}

#define MD5_FILE_TEST(filename, name) \
	MD5_FILE_TEST_PROTO(name) \
	{\
		char *actual = md5_file(filename); \
		char expected[MD5_DIGEST_LENGTH * 2 + 1]; \
		get_hash_file(expected, filename); \
		CU_ASSERT_STRING_EQUAL(expected, actual); \
		free(actual); \
	}

MD5_STRING_TEST("", empty_string)
MD5_STRING_TEST("a", a)
MD5_STRING_TEST("abc", abc)
MD5_STRING_TEST("message digest", message_digest)
MD5_STRING_TEST("abcdefghijklmnopqrstuvwxyz", alphabet)
MD5_STRING_TEST("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", alnum)
MD5_STRING_TEST("12345678901234567890123456789012345678901234567890123456789012345678901234567890", num2)
MD5_STRING_TEST("The quick brown fox jumps over the lazy dog", lorem_ipsum)
MD5_STRING_TEST("The quick brown fox jumps over the lazy dog.", lorem_ipsum_edit)
MD5_STRING_TEST("The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.", lorem_ipsum_double)

MD5_FILE_TEST("tests/resources/empty", empty)
MD5_FILE_TEST("tests/md5.c", test_md5)
MD5_FILE_TEST("/etc/passwd", etc_passwd)
MD5_FILE_TEST("tests/resources/basic", basic)
MD5_FILE_TEST("tests/resources/big_file", big_file)
MD5_FILE_TEST("tests/resources/bigger_file", bigger_file)
MD5_FILE_TEST("tests/resources/huge_file", huge_file)

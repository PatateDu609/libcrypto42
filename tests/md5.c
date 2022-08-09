#include "tests.h"
#include <CUnit/Basic.h>
#include <openssl/md5.h>
#include <stdlib.h>

void get_hash(char *hash, const char *msg)
{
	int i;
	unsigned char result[MD5_DIGEST_LENGTH];

	MD5((const unsigned char *)msg, strlen(msg), result);

	// output
	for(i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		snprintf(&hash[i * 2], 3, "%02x", result[i]);
	}
}

void md5_basic(void)
{
	char expected[MD5_DIGEST_LENGTH * 2 + 1];
	char *strs[] = {
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

	int size = sizeof strs / sizeof *strs;
	for (int i = 0; i < size; i++) {
		char *mine = md5(strs[i]);
		get_hash(expected, strs[i]);

		CU_ASSERT_STRING_EQUAL(mine, expected);
		free(mine);
	}
}

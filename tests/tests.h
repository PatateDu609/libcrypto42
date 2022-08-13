/**
 * @file tests.h
 * @author Ghali Boucetta (gboucett@student.42,fr)
 * @brief Header file to manage all tests.
 * @date 2022-08-09
 */

#ifndef TESTS_H
#define TESTS_H

#include "crypto.h"
#include <stdio.h>

#define CAT(a, b) CAT2(a, b)
#define CAT2(a, b) a##b

#define MERGE(a, b) a##_##b

#define MD5_STRING_TEST_PROTO(name) void CAT(md5_string_, name)(void)
#define MD5_FILE_TEST_PROTO(name) void CAT(md5_file_, name)(void)
#define SHA_STRING_TEST_PROTO(alg, name) void CAT(sha##alg##_string_, name)(void)
#define SHA_FILE_TEST_PROTO(alg, name) void CAT(sha##alg##_file_, name)(void)

#define DECLARE_TEST(suite, str, name) \
	if (CU_add_test(suite, str, MERGE(suite, name)) == NULL) { \
		CU_cleanup_registry(); \
		return CU_get_error(); \
	}

#define DECLARE_SUITE(suite, str, setup, tear_down) \
	if ((suite = CU_add_suite(str, setup, tear_down)) == NULL) { \
		CU_cleanup_registry(); \
		return CU_get_error(); \
	}

#define FILL_STR_SUITE(suite)	\
	DECLARE_TEST(suite, "empty_string", empty_string); \
	DECLARE_TEST(suite, "a", a); \
	DECLARE_TEST(suite, "abc", abc); \
	DECLARE_TEST(suite, "message_digest", message_digest); \
	DECLARE_TEST(suite, "alphabet", alphabet); \
	DECLARE_TEST(suite, "alnum", alnum); \
	DECLARE_TEST(suite, "num2", num2); \
	DECLARE_TEST(suite, "lorem_ipsum", lorem_ipsum); \
	DECLARE_TEST(suite, "lorem_ipsum_edit", lorem_ipsum_edit); \
	DECLARE_TEST(suite, "lorem_ipsum_double", lorem_ipsum_double); \

#define FILL_FILE_SUITE(suite)	\
	DECLARE_TEST(suite, "test_md5", test_md5); \
	DECLARE_TEST(suite, "etc_passwd", etc_passwd); \
	DECLARE_TEST(suite, "empty", empty); \
	DECLARE_TEST(suite, "test_md5", test_md5); \
	DECLARE_TEST(suite, "etc_passwd", etc_passwd); \
	DECLARE_TEST(suite, "basic", basic); \
	DECLARE_TEST(suite, "big_file", big_file); \
	DECLARE_TEST(suite, "bigger_file", bigger_file); \
	DECLARE_TEST(suite, "huge_file", huge_file); \



#define SHA_TEST_SUITE_PROTO(alg) \
	SHA_STRING_TEST_PROTO(alg, empty_string);  \
	SHA_STRING_TEST_PROTO(alg, a); \
	SHA_STRING_TEST_PROTO(alg, abc); \
	SHA_STRING_TEST_PROTO(alg, message_digest); \
	SHA_STRING_TEST_PROTO(alg, alphabet); \
	SHA_STRING_TEST_PROTO(alg, alnum); \
	SHA_STRING_TEST_PROTO(alg, num2); \
	SHA_STRING_TEST_PROTO(alg, lorem_ipsum); \
	SHA_STRING_TEST_PROTO(alg, lorem_ipsum_edit); \
	SHA_STRING_TEST_PROTO(alg, lorem_ipsum_double); \
	\
	SHA_FILE_TEST_PROTO(alg, empty); \
	SHA_FILE_TEST_PROTO(alg, test_md5); \
	SHA_FILE_TEST_PROTO(alg, etc_passwd); \
	SHA_FILE_TEST_PROTO(alg, basic); \
	SHA_FILE_TEST_PROTO(alg, big_file); \
	SHA_FILE_TEST_PROTO(alg, bigger_file); \
	SHA_FILE_TEST_PROTO(alg, huge_file);

MD5_STRING_TEST_PROTO(empty_string);
MD5_STRING_TEST_PROTO(a);
MD5_STRING_TEST_PROTO(abc);
MD5_STRING_TEST_PROTO(message_digest);
MD5_STRING_TEST_PROTO(alphabet);
MD5_STRING_TEST_PROTO(alnum);
MD5_STRING_TEST_PROTO(num2);
MD5_STRING_TEST_PROTO(lorem_ipsum);
MD5_STRING_TEST_PROTO(lorem_ipsum_edit);
MD5_STRING_TEST_PROTO(lorem_ipsum_double);

MD5_FILE_TEST_PROTO(empty);
MD5_FILE_TEST_PROTO(test_md5);
MD5_FILE_TEST_PROTO(etc_passwd);
MD5_FILE_TEST_PROTO(basic);
MD5_FILE_TEST_PROTO(big_file);
MD5_FILE_TEST_PROTO(bigger_file);
MD5_FILE_TEST_PROTO(huge_file);

SHA_TEST_SUITE_PROTO(224)
SHA_TEST_SUITE_PROTO(256)
SHA_TEST_SUITE_PROTO(384)
SHA_TEST_SUITE_PROTO(512)

static inline void get_output(const unsigned char *result, int digest_len, char *hash)
{
	for(int i = 0; i < digest_len; i++)
	{
		snprintf(&hash[i * 2], 3, "%02x", result[i]);
	}
}

void HMAC_sha2_256_test(void);
void pbkdf_test_32_1(void);
void pbkdf_test_32_2(void);
void pbkdf_test_32_4096(void);
void pbkdf_test_32_16777216(void);
void pbkdf_test_40_4096(void);
void pbkdf_test_16_4096(void);

#endif

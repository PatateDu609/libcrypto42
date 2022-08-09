/**
 * @file tests.h
 * @author Ghali Boucetta (gboucett@student.42,fr)
 * @brief Header file to manage all tests.
 * @date 2022-08-09
 */

#ifndef TESTS_H
#define TESTS_H

#include "crypto.h"

#define CAT(a, b) a ## b

#define MERGE(a, b) a##_##b
#define MD5_STRING_TEST_PROTO(name) void CAT(md5_string_, name)(void)
#define MD5_FILE_TEST_PROTO(name) void CAT(md5_file_, name)(void)

#define DECLARE_TEST(suite, str, name) \
	if (CU_add_test(suite, str, MERGE(suite, name)) == NULL) { \
		CU_cleanup_registry(); \
		return CU_get_error(); \
	}

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

#endif

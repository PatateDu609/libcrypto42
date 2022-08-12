#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "tests.h"

int main(void)
{
	CU_pSuite md5_string = NULL;
	CU_pSuite md5_file = NULL;
	CU_pSuite sha256_string = NULL;
	CU_pSuite sha224_string = NULL;
	CU_pSuite sha384_string = NULL;
	CU_pSuite sha512_string = NULL;

	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	DECLARE_SUITE(md5_string, "MD5 string", NULL, NULL);
	DECLARE_SUITE(md5_file, "MD5 file", NULL, NULL);
	DECLARE_SUITE(sha256_string, "SHA256 string", NULL, NULL);
	DECLARE_SUITE(sha224_string, "SHA224 string", NULL, NULL);
	DECLARE_SUITE(sha384_string, "SHA384 string", NULL, NULL);
	DECLARE_SUITE(sha512_string, "SHA512 string", NULL, NULL);

	FILL_STR_SUITE(md5_string);

	// DECLARE_TEST(md5_string, "empty_string", empty_string);
	// DECLARE_TEST(md5_string, "a", a);
	// DECLARE_TEST(md5_string, "abc", abc);
	// DECLARE_TEST(md5_string, "message_digest", message_digest);
	// DECLARE_TEST(md5_string, "alphabet", alphabet);
	// DECLARE_TEST(md5_string, "alnum", alnum);
	// DECLARE_TEST(md5_string, "num2", num2);
	// DECLARE_TEST(md5_string, "lorem_ipsum", lorem_ipsum);
	// DECLARE_TEST(md5_string, "lorem_ipsum_edit", lorem_ipsum_edit);
	// DECLARE_TEST(md5_string, "lorem_ipsum_double", lorem_ipsum_double);

	DECLARE_TEST(md5_file, "test_md5", test_md5);
	DECLARE_TEST(md5_file, "etc_passwd", etc_passwd);
	DECLARE_TEST(md5_file, "empty", empty);
	DECLARE_TEST(md5_file, "test_md5", test_md5);
	DECLARE_TEST(md5_file, "etc_passwd", etc_passwd);
	DECLARE_TEST(md5_file, "basic", basic);
	DECLARE_TEST(md5_file, "big_file", big_file);
	DECLARE_TEST(md5_file, "bigger_file", bigger_file);
	DECLARE_TEST(md5_file, "huge_file", huge_file);

	FILL_STR_SUITE(sha256_string);
	FILL_STR_SUITE(sha224_string);
	FILL_STR_SUITE(sha384_string);
	FILL_STR_SUITE(sha512_string);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_suite(sha256_string);

	int ret = CU_get_number_of_failure_records();
	CU_cleanup_registry();
	return ret;
}

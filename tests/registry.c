#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "tests.h"

int main(void)
{
	CU_pSuite md5_string = NULL;
	CU_pSuite md5_file = NULL;

	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	if ((md5_string = CU_add_suite("md5_string", NULL, NULL)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if ((md5_file = CU_add_suite("md5_file", NULL, NULL)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	DECLARE_TEST(md5_string, "empty_string", empty_string);
	DECLARE_TEST(md5_string, "a", a);
	DECLARE_TEST(md5_string, "abc", abc);
	DECLARE_TEST(md5_string, "message_digest", message_digest);
	DECLARE_TEST(md5_string, "alphabet", alphabet);
	DECLARE_TEST(md5_string, "alnum", alnum);
	DECLARE_TEST(md5_string, "num2", num2);
	DECLARE_TEST(md5_string, "lorem_ipsum", lorem_ipsum);
	DECLARE_TEST(md5_string, "lorem_ipsum_edit", lorem_ipsum_edit);
	DECLARE_TEST(md5_string, "lorem_ipsum_double", lorem_ipsum_double);

	DECLARE_TEST(md5_file, "test_md5", test_md5);
	DECLARE_TEST(md5_file, "etc_passwd", etc_passwd);
	DECLARE_TEST(md5_file, "empty", empty);
	DECLARE_TEST(md5_file, "test_md5", test_md5);
	DECLARE_TEST(md5_file, "etc_passwd", etc_passwd);
	DECLARE_TEST(md5_file, "basic", basic);
	DECLARE_TEST(md5_file, "big_file", big_file);
	DECLARE_TEST(md5_file, "bigger_file", bigger_file);
	DECLARE_TEST(md5_file, "huge_file", huge_file);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	int ret = CU_get_number_of_failure_records();
	CU_cleanup_registry();
	return ret;
}

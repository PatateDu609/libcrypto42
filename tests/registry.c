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
	CU_pSuite sha256_file = NULL;
	CU_pSuite sha224_file = NULL;
	CU_pSuite sha384_file = NULL;
	CU_pSuite sha512_file = NULL;

	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	DECLARE_SUITE(md5_string, "MD5 string", NULL, NULL);
	DECLARE_SUITE(md5_file, "MD5 file", NULL, NULL);

	DECLARE_SUITE(sha224_string, "SHA224 string", NULL, NULL);
	DECLARE_SUITE(sha224_file, "SHA224 file", NULL, NULL);

	DECLARE_SUITE(sha256_string, "SHA256 string", NULL, NULL);
	DECLARE_SUITE(sha256_file, "SHA256 file", NULL, NULL);

	DECLARE_SUITE(sha384_string, "SHA384 string", NULL, NULL);
	DECLARE_SUITE(sha384_file, "SHA384 file", NULL, NULL);

	DECLARE_SUITE(sha512_string, "SHA512 string", NULL, NULL);
	DECLARE_SUITE(sha512_file, "SHA512 file", NULL, NULL);

	FILL_STR_SUITE(md5_string);
	FILL_FILE_SUITE(md5_file);

	FILL_STR_SUITE(sha224_string);
	FILL_FILE_SUITE(sha224_file);

	FILL_STR_SUITE(sha256_string);
	FILL_FILE_SUITE(sha256_file);


	FILL_STR_SUITE(sha384_string);
	FILL_FILE_SUITE(sha384_file);

	FILL_STR_SUITE(sha512_string);
	FILL_FILE_SUITE(sha512_file);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();

	int ret = CU_get_number_of_failure_records();
	CU_cleanup_registry();
	return ret;
}

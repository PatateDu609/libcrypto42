#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "tests.h"

int main(void)
{
	CU_pSuite md5 = NULL;

	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	if ((md5 = CU_add_suite("md5", NULL, NULL)) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (CU_add_test(md5, "md5", md5_basic) == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	int ret = CU_get_number_of_failure_records();
	CU_cleanup_registry();
	return ret;
}
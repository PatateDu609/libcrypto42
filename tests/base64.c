#include "tests.h"
#include "common.h"
#include "CUnit/Basic.h"

void base64_test_encode(void)
{
	char *tests[][2] = {
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foob", "Zm9vYg=="},
		{"fooba", "Zm9vYmE="},
		{"foobar", "Zm9vYmFy"},
	};

	for (size_t i = 0; i < sizeof tests / sizeof *tests; i++)
	{
		char *res = base64_encode((uint8_t *)tests[i][0], strlen(tests[i][0]));

		CU_ASSERT_STRING_EQUAL(res, tests[i][1]);

		free(res);
	}
}

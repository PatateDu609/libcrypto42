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

void base64_test_decode(void)
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
		size_t len;
		uint8_t *res = base64_decode(tests[i][1], &len);

		CU_ASSERT_EQUAL(len, strlen(tests[i][0]));
		CU_ASSERT_EQUAL(memcmp(res, tests[i][0], len), 0);

		free(res);
	}
}

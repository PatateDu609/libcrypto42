#include "common.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>

static char *test_strings[][2] = {
	{"",		  ""		 },
	{ "f",	   "Zg=="	  },
	{ "fo",		"Zm8="	   },
	{ "foo",	 "Zm9v"	},
	{ "foob",	  "Zm9vYg=="},
	{ "fooba",  "Zm9vYmE="},
	{ "foobar", "Zm9vYmFy"},
};

Test(base64, encode) {
	for (size_t i = 0; i < sizeof test_strings / sizeof *test_strings; i++) {
		char *res = base64_encode((uint8_t *) test_strings[i][0], strlen(test_strings[i][0]));

		cr_expect(eq(str, res, test_strings[i][1], "expected %s, got %s", test_strings[i][1], res));

		free(res);
	}
}

Test(base64, decode) {
	for (size_t i = 0; i < sizeof test_strings / sizeof *test_strings; i++) {
		char		 *str = test_strings[i][1];
		size_t		  len;
		uint8_t		 *res = base64_decode(str, &len);

		struct cr_mem expected_mem = { .data = test_strings[i][0], .size = strlen(test_strings[i][0]) };
		struct cr_mem actual_mem   = { .data = res, .size = len };

		cr_expect(eq(mem, actual_mem, expected_mem));

		free(res);
	}
}

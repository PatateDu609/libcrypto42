#include "crypto.h"
#include "test.h"
#include <criterion/criterion.h>
#include <criterion/parameterized.h>

ParameterizedTestParameters(md5, strings) {
	static char *duped[NB_DIGEST_TEST_STRINGS];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_strings, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char *param, md5, strings) {
	run_digest_string_test(EVP_md5(), param, md5);
}

ParameterizedTestParameters(md5, files) {
	static char *duped[NB_DIGEST_TEST_FILES];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_filenames, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, md5, files) {
	run_digest_file_test(EVP_md5(), *param, md5_file);
}
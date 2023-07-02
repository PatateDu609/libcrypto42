#include "crypto.h"
#include "test.h"
#include <criterion/criterion.h>
#include <criterion/parameterized.h>


ParameterizedTestParameters(sha2_224, strings) {
	static char *duped[NB_DIGEST_TEST_STRINGS];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_strings, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_224, strings) {
	run_digest_string_test(EVP_sha224(), *param, sha2_224);
}

ParameterizedTestParameters(sha2_224, files) {
	static char *duped[NB_DIGEST_TEST_FILES];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_filenames, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_224, files) {
	run_digest_file_test(EVP_sha224(), *param, sha2_224_file);
}


ParameterizedTestParameters(sha2_256, strings) {
	static char *duped[NB_DIGEST_TEST_STRINGS];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_strings, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_256, strings) {
	run_digest_string_test(EVP_sha256(), *param, sha2_256);
}

ParameterizedTestParameters(sha2_256, files) {
	static char *duped[NB_DIGEST_TEST_FILES];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_filenames, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_256, files) {
	run_digest_file_test(EVP_sha256(), *param, sha2_256_file);
}


ParameterizedTestParameters(sha2_384, strings) {
	static char *duped[NB_DIGEST_TEST_STRINGS];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_strings, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_384, strings) {
	run_digest_string_test(EVP_sha384(), *param, sha2_384);
}

ParameterizedTestParameters(sha2_384, files) {
	static char *duped[NB_DIGEST_TEST_FILES];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_filenames, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_384, files) {
	run_digest_file_test(EVP_sha384(), *param, sha2_384_file);
}


ParameterizedTestParameters(sha2_512, strings) {
	static char *duped[NB_DIGEST_TEST_STRINGS];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_strings, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_512, strings) {
	run_digest_string_test(EVP_sha512(), *param, sha2_512);
}

ParameterizedTestParameters(sha2_512, files) {
	static char *duped[NB_DIGEST_TEST_FILES];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_filenames, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_512, files) {
	run_digest_file_test(EVP_sha512(), *param, sha2_512_file);
}


ParameterizedTestParameters(sha2_512_224, strings) {
	static char *duped[NB_DIGEST_TEST_STRINGS];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_strings, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_512_224, strings) {
	run_digest_string_test(EVP_sha512_224(), *param, sha2_512_224);
}

ParameterizedTestParameters(sha2_512_224, files) {
	static char *duped[NB_DIGEST_TEST_FILES];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_filenames, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_512_224, files) {
	run_digest_file_test(EVP_sha512_224(), *param, sha2_512_224_file);
}


ParameterizedTestParameters(sha2_512_256, strings) {
	static char *duped[NB_DIGEST_TEST_STRINGS];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_strings, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_512_256, strings) {
	run_digest_string_test(EVP_sha512_256(), *param, sha2_512_256);
}

ParameterizedTestParameters(sha2_512_256, files) {
	static char *duped[NB_DIGEST_TEST_FILES];
	size_t		 size	  = sizeof duped / sizeof *duped;
	static bool	 is_first = true;

	if (is_first) {
		is_first = false;

		dupe_str_array(digest_test_filenames, size, duped);
	}

	return cr_make_param_array(char *, duped, size, free_str_array);
}

ParameterizedTest(char **param, sha2_512_256, files) {
	run_digest_file_test(EVP_sha512_256(), *param, sha2_512_256_file);
}

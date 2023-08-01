#include "crypto.h"
#include "digest.hh"

class MD5_Tests : public DigestTests {
public:
	typedef DigestTests::digest_bytes_func sha2_bytes_func;
	typedef DigestTests::digest_file_func  sha2_file_func;

	const EVP_MD                          *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_md5();
	}

	sha2_bytes_func get_digest_func() const final {// NOLINT(modernize-use-nodiscard)
		return md5_bytes;
	}

	sha2_file_func get_digest_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return md5_file;
	}
};

INSTANTIATE_TEST_SUITE_P(file_tests, MD5_Tests, testing::ValuesIn(range_strings));
INSTANTIATE_TEST_SUITE_P(string_tests, MD5_Tests, testing::ValuesIn(range_files));

TEST_P(MD5_Tests, tests) {
	run_test();
}
#include "crypto.h"
#include "test.hh"
#include <array>
#include <fstream>
#include <gtest/gtest.h>
#include "digest.hh"

namespace fs = std::filesystem;

class SHA2_224_Tests : public DigestTests {
public:
	typedef DigestTests::digest_bytes_func sha2_bytes_func;
	typedef DigestTests::digest_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha224();
	}

	sha2_bytes_func get_digest_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_224_bytes;
	}

	sha2_file_func get_digest_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_224_file;
	}
};

class SHA2_256_Tests : public DigestTests {
public:
	typedef DigestTests::digest_bytes_func sha2_bytes_func;
	typedef DigestTests::digest_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha256();
	}

	sha2_bytes_func get_digest_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_256_bytes;
	}

	sha2_file_func get_digest_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_256_file;
	}
};

class SHA2_384_Tests : public DigestTests {
public:
	typedef DigestTests::digest_bytes_func sha2_bytes_func;
	typedef DigestTests::digest_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha384();
	}

	sha2_bytes_func get_digest_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_384_bytes;
	}

	sha2_file_func get_digest_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_384_file;
	}
};

class SHA2_512_Tests : public DigestTests {
protected:
	typedef DigestTests::digest_bytes_func sha2_bytes_func;
	typedef DigestTests::digest_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha512();
	}

	sha2_bytes_func get_digest_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_bytes;
	}

	sha2_file_func get_digest_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_file;
	}
};

class SHA2_512_224_Tests : public DigestTests {
public:
	typedef DigestTests::digest_bytes_func sha2_bytes_func;
	typedef DigestTests::digest_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha512_224();
	}

	sha2_bytes_func get_digest_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_224_bytes;
	}

	sha2_file_func get_digest_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_224_file;
	}
};

class SHA2_512_256_Tests : public DigestTests {
public:
	typedef DigestTests::digest_bytes_func sha2_bytes_func;
	typedef DigestTests::digest_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha512_256();
	}

	sha2_bytes_func get_digest_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_256_bytes;
	}

	sha2_file_func get_digest_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_256_file;
	}
};

INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_224_Tests, testing::ValuesIn(range_strings));
INSTANTIATE_TEST_SUITE_P(file_tests, SHA2_224_Tests, testing::ValuesIn(range_files));

INSTANTIATE_TEST_SUITE_P(file_tests, SHA2_256_Tests, testing::ValuesIn(range_strings));
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_256_Tests, testing::ValuesIn(range_files));

INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_384_Tests, testing::ValuesIn(range_strings));
INSTANTIATE_TEST_SUITE_P(file_tests, SHA2_384_Tests, testing::ValuesIn(range_files));

INSTANTIATE_TEST_SUITE_P(file_tests, SHA2_512_Tests, testing::ValuesIn(range_strings));
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_512_Tests, testing::ValuesIn(range_files));

INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_512_224_Tests, testing::ValuesIn(range_strings));
INSTANTIATE_TEST_SUITE_P(file_tests, SHA2_512_224_Tests, testing::ValuesIn(range_files));

INSTANTIATE_TEST_SUITE_P(file_tests, SHA2_512_256_Tests, testing::ValuesIn(range_strings));
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_512_256_Tests, testing::ValuesIn(range_files));

TEST_P(SHA2_224_Tests, tests) {
	run_test();
}

TEST_P(SHA2_256_Tests, tests) {
	run_test();
}

TEST_P(SHA2_384_Tests, tests) {
	run_test();
}

TEST_P(SHA2_512_Tests, tests) {
	run_test();
}

TEST_P(SHA2_512_224_Tests, tests) {
	run_test();
}

TEST_P(SHA2_512_256_Tests, tests) {
	run_test();
}
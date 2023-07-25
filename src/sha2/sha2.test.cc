#include "crypto.h"
#include "test.hh"
#include <array>
#include <fstream>
#include <gtest/gtest.h>
#include <openssl/err.h>
#include <vector>

namespace fs = std::filesystem;

static std::vector<TestParamsIdx> range_files;
static std::vector<TestParamsIdx> range_strings;

void                              set_params_range() {
    range_files.reserve(NB_FILE_TESTS);
    range_strings.reserve(NB_STRING_TESTS);

    for (size_t files_idx = 0, strings_idx = 0;
         files_idx < range_files.capacity() || strings_idx < range_strings.capacity(); files_idx++, strings_idx++) {
        if (files_idx >= range_files.capacity())
            files_idx = range_files.capacity();
        else
            range_files.emplace_back(files_idx, true);

        if (strings_idx >= range_strings.capacity())
            strings_idx = range_strings.capacity();
        else
            range_strings.emplace_back(strings_idx, false);
    }
}

class SHA2_Tests : public testing::TestWithParam<TestParamsIdx> {
protected:
	typedef char *(*sha2_bytes_func)(const uint8_t *, size_t);
	typedef char *(*sha2_file_func)(const char *);

	virtual const EVP_MD   *get_evp() const            = 0;// NOLINT(modernize-use-nodiscard)
	virtual sha2_bytes_func get_sha2_func() const      = 0;// NOLINT(modernize-use-nodiscard)
	virtual sha2_file_func  get_sha2_file_func() const = 0;// NOLINT(modernize-use-nodiscard)

	void                    run_test() {
        auto        paramIdx = GetParam();
        const auto &params   = paramIdx.get_linked_test();
        ASSERT_NE(params, nullptr);

        if (params->is_file)
            run_file_test(get_evp(), get_sha2_file_func(), params->filename);
        else
            run_string_test(get_evp(), get_sha2_func(), params->string);
	}

private:
	static void run_file_test(const EVP_MD *md, sha2_file_func func, const fs::path &filename) {
		char *actual_mem = func(filename.c_str());
		ASSERT_NE(actual_mem, nullptr);

		std::string actual(actual_mem);

		std::string expected(2 * EVP_MD_size(md), '0');
		get_hash_file(md, expected, filename);
		EXPECT_EQ(expected, actual);

		free(actual_mem);
	}

	static void run_string_test(const EVP_MD *md, sha2_bytes_func func, const std::vector<uint8_t> &string) {
		const uint8_t *msg = string.data();
		char          *actual_mem;
		if (msg == nullptr)
			actual_mem = func((const uint8_t *) "", 0);
		else
			actual_mem = func(msg, string.size());
		ASSERT_NE(actual_mem, nullptr);

		std::string expected(2 * EVP_MD_size(md), '0');
		get_hash(md, expected, string);

		std::string actual(actual_mem);
		ASSERT_EQ(expected, actual);

		free(actual_mem);
	}

	static void get_hash(const EVP_MD *md, std::string &expected, const std::vector<uint8_t> &msg) {
		std::vector<uint8_t> result(EVP_MD_size(md), 0);

		ASSERT_EQ(EVP_Digest(msg.data(), msg.size(), result.data(), nullptr, md, nullptr), 1);
		get_output(result.data(), EVP_MD_size(md), expected);
	}

	static void get_hash_file(const EVP_MD *md, std::string &expected, const fs::path &filename) {
		std::ifstream ifs(filename, std::ios::binary);
		if (!ifs)
			return;

		std::array<char, 4096> buffer{};
		buffer.fill(0);
		std::vector<uint8_t> result(EVP_MD_size(md), 0);

		EVP_MD_CTX          *ctx = EVP_MD_CTX_new();
		ASSERT_NE(ctx, nullptr);
		ASSERT_EQ(EVP_DigestInit_ex(ctx, md, NULL), 1);

		while (!ifs.eof() && !ifs.fail()) {
			ifs.read(buffer.data(), buffer.size());

			ASSERT_EQ(EVP_DigestUpdate(ctx, buffer.data(), ifs.gcount()), 1);
		}

		ASSERT_EQ(EVP_DigestFinal_ex(ctx, result.data(), nullptr), 1);

		ifs.close();
		get_output(result.data(), EVP_MD_size(md), expected);

		EVP_MD_CTX_free(ctx);
	}

public:
	~SHA2_Tests() override = default;

	void SetUp() override {}

	void TearDown() override {}
};

class SHA2_224_Tests : public SHA2_Tests {
public:
	typedef SHA2_Tests::sha2_bytes_func sha2_bytes_func;
	typedef SHA2_Tests::sha2_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha224();
	}

	sha2_bytes_func get_sha2_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_224_bytes;
	}

	sha2_file_func get_sha2_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_224_file;
	}
};

class SHA2_256_Tests : public SHA2_Tests {
public:
	typedef SHA2_Tests::sha2_bytes_func sha2_bytes_func;
	typedef SHA2_Tests::sha2_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha256();
	}

	sha2_bytes_func get_sha2_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_256_bytes;
	}

	sha2_file_func get_sha2_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_256_file;
	}
};

class SHA2_384_Tests : public SHA2_Tests {
public:
	typedef SHA2_Tests::sha2_bytes_func sha2_bytes_func;
	typedef SHA2_Tests::sha2_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha384();
	}

	sha2_bytes_func get_sha2_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_384_bytes;
	}

	sha2_file_func get_sha2_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_384_file;
	}
};

class SHA2_512_Tests : public SHA2_Tests {
protected:
	typedef SHA2_Tests::sha2_bytes_func sha2_bytes_func;
	typedef SHA2_Tests::sha2_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha512();
	}

	sha2_bytes_func get_sha2_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_bytes;
	}

	sha2_file_func get_sha2_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_file;
	}
};

class SHA2_512_224_Tests : public SHA2_Tests {
public:
	typedef SHA2_Tests::sha2_bytes_func sha2_bytes_func;
	typedef SHA2_Tests::sha2_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha512_224();
	}

	sha2_bytes_func get_sha2_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_224_bytes;
	}

	sha2_file_func get_sha2_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_224_file;
	}
};

class SHA2_512_256_Tests : public SHA2_Tests {
public:
	typedef SHA2_Tests::sha2_bytes_func sha2_bytes_func;
	typedef SHA2_Tests::sha2_file_func  sha2_file_func;

	const EVP_MD                       *get_evp() const final {// NOLINT(modernize-use-nodiscard)
        return EVP_sha512_256();
	}

	sha2_bytes_func get_sha2_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_256_bytes;
	}

	sha2_file_func get_sha2_file_func() const final {// NOLINT(modernize-use-nodiscard)
		return sha2_512_256_file;
	}
};

auto name_generator = [](const testing::TestParamInfo<TestParamsIdx> &info) {
	TestParamsIdx params = info.param;
	return params.get_test_name(info);
};

INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_224_Tests, testing::ValuesIn(range_strings), name_generator);
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_256_Tests, testing::ValuesIn(range_strings), name_generator);
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_384_Tests, testing::ValuesIn(range_strings), name_generator);
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_512_Tests, testing::ValuesIn(range_strings), name_generator);
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_512_224_Tests, testing::ValuesIn(range_strings), name_generator);
INSTANTIATE_TEST_SUITE_P(string_tests, SHA2_512_256_Tests, testing::ValuesIn(range_strings), name_generator);
INSTANTIATE_TEST_SUITE_P(file_tests, SHA2_224_Tests, testing::ValuesIn(range_files), name_generator);

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
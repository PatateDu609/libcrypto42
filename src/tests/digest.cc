#include "digest.hh"
#include "crypto.h"
#include "test.hh"
#include <fstream>

std::vector<TestParamsIdx> range_files;
std::vector<TestParamsIdx> range_strings;

void                       set_params_range() {
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

void DigestTests::run_test() {
	auto        paramIdx = GetParam();
	const auto &params   = paramIdx.get_linked_test();
	ASSERT_NE(params, nullptr);

	if (params->is_file)
		run_file_test(get_evp(), get_digest_file_func(), params->filename);
	else
		run_string_test(get_evp(), get_digest_func(), params->string);
}

void DigestTests::run_file_test(const EVP_MD *md, digest_file_func func, const fs::path &filename) {
	char *actual_mem = func(filename.c_str());
	ASSERT_NE(actual_mem, nullptr);

	std::string actual(actual_mem);

	std::string expected(2 * EVP_MD_size(md), '0');
	get_hash_file(md, expected, filename);
	EXPECT_EQ(expected, actual);

	free(actual_mem);
}

void DigestTests::run_string_test(const EVP_MD *md, DigestTests::digest_bytes_func func,
                                  const std::vector<uint8_t> &string) {
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

void DigestTests::get_hash(const EVP_MD *md, std::string &expected, const std::vector<uint8_t> &msg) {
	std::vector<uint8_t> result(EVP_MD_size(md), 0);

	ASSERT_EQ(EVP_Digest(msg.data(), msg.size(), result.data(), nullptr, md, nullptr), 1);
	get_output(result.data(), EVP_MD_size(md), expected);
}

void DigestTests::get_hash_file(const EVP_MD *md, std::string &expected, const fs::path &filename) {
	std::ifstream ifs(filename, std::ios::binary);
	if (!ifs)
		return;

	std::array<char, 4096> buffer{};
	buffer.fill(0);
	std::vector<uint8_t> result(EVP_MD_size(md), 0);

	EVP_MD_CTX          *ctx = EVP_MD_CTX_new();
	ASSERT_NE(ctx, nullptr);
	ASSERT_EQ(EVP_DigestInit_ex(ctx, md, nullptr), 1);

	while (!ifs.eof() && !ifs.fail()) {
		ifs.read(buffer.data(), buffer.size());

		ASSERT_EQ(EVP_DigestUpdate(ctx, buffer.data(), ifs.gcount()), 1);
	}

	ASSERT_EQ(EVP_DigestFinal_ex(ctx, result.data(), nullptr), 1);

	ifs.close();
	get_output(result.data(), EVP_MD_size(md), expected);

	EVP_MD_CTX_free(ctx);
}

void DigestTests::SetUp() {}

void DigestTests::TearDown() {}
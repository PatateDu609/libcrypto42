#ifndef LIBCRYPTO42_DIGEST_HH
#define LIBCRYPTO42_DIGEST_HH

#include "test.hh"
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>

extern std::vector<TestParamsIdx> range_files;
extern std::vector<TestParamsIdx> range_strings;
void                              set_params_range();

class DigestTests : public testing::TestWithParam<TestParamsIdx> {
protected:
	typedef char *(*digest_bytes_func)(const uint8_t *, size_t);
	typedef char *(*digest_file_func)(const char *);

	virtual const EVP_MD     *get_evp() const              = 0;// NOLINT(modernize-use-nodiscard)
	virtual digest_bytes_func get_digest_func() const      = 0;// NOLINT(modernize-use-nodiscard)
	virtual digest_file_func  get_digest_file_func() const = 0;// NOLINT(modernize-use-nodiscard)

	void                      run_test();

private:
	static void run_file_test(const EVP_MD *md, digest_file_func func, const fs::path &filename);
	static void run_string_test(const EVP_MD *md, digest_bytes_func func, const std::vector<uint8_t> &string);
	static void get_hash(const EVP_MD *md, std::string &expected, const std::vector<uint8_t> &msg);
	static void get_hash_file(const EVP_MD *md, std::string &expected, const fs::path &filename);

public:
	~DigestTests() override = default;

	void SetUp() override;

	void TearDown() override;
};

#endif// LIBCRYPTO42_DIGEST_HH

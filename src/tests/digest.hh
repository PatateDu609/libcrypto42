#ifndef LIBCRYPTO42_DIGEST_HH
#define LIBCRYPTO42_DIGEST_HH

#include "test.hh"
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>

extern std::vector<TestParamsIdx> range_files;
extern std::vector<TestParamsIdx> range_strings;

class CryptoTests : public testing::TestWithParam<TestParamsIdx> {
protected:
	virtual const EVP_MD *get_evp() const = 0;// NOLINT(modernize-use-nodiscard)
	virtual void          run_test()      = 0;

public:
	void SetUp() final;
	void TearDown() final;
};

class DigestTests : public CryptoTests {
protected:
	typedef char *(*digest_bytes_func)(const uint8_t *, size_t);
	typedef char *(*digest_file_func)(const char *);

	virtual digest_bytes_func get_digest_func() const      = 0;// NOLINT(modernize-use-nodiscard)
	virtual digest_file_func  get_digest_file_func() const = 0;// NOLINT(modernize-use-nodiscard)

private:
	static void run_file_test(const EVP_MD *md, digest_file_func func, const fs::path &filename);
	static void run_string_test(const EVP_MD *md, digest_bytes_func func, const std::vector<uint8_t> &string);
	static void get_hash(const EVP_MD *md, std::string &expected, const std::vector<uint8_t> &msg);
	static void get_hash_file(const EVP_MD *md, std::string &expected, const fs::path &filename);

protected:
	void run_test() final;

public:
	~DigestTests() override = default;
};

#endif// LIBCRYPTO42_DIGEST_HH

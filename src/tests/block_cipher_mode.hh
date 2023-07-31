#ifndef LIBCRYPTO42_BLOCK_CIPHER_MODE_HH
#define LIBCRYPTO42_BLOCK_CIPHER_MODE_HH

#include "../block_cipher_modes/internal.h"
#include <gtest/gtest.h>
#include <iostream>
#include <openssl/evp.h>
#include <string>
#include <vector>

class BlockCipherTestParams {
public:
	BlockCipherTestParams(enum cipher_mode mode, enum block_cipher type, size_t plaintext_size);

private:
	static std::string      get_alg(enum cipher_mode mode, enum block_cipher type);

	bool                    is_legacy() const;

	EVP_CIPHER             *load_evp() const;

	struct block_cipher_ctx block_ctx;
	const std::string       evp_alg;

	std::vector<uint8_t>    plaintext;
	std::vector<uint8_t>    key;
	std::vector<uint8_t>    iv;

	friend class BlockCipherModeTests;

	friend std::ostream &operator<<(std::ostream &os, const BlockCipherTestParams &param);
};

class BlockCipherModeTests : public testing::TestWithParam<BlockCipherTestParams> {
protected:
	typedef uint8_t *(block_cipher_func) (struct cipher_ctx *);

	EVP_CIPHER     *evp;
	EVP_CIPHER_CTX *evp_ctx;
	int             evp_blk_len;

public:
	BlockCipherModeTests();
	~BlockCipherModeTests() override = default;

	void SetUp() override;
	void TearDown() override;

protected:
	virtual block_cipher_func *get_block_cipher_func_cipher() const   = 0;
	virtual block_cipher_func *get_block_cipher_func_decipher() const = 0;

	void                       run_cipher_test();
	void                       run_decipher_test();

private:
	void                 destroy_ctx();
	void                 destroy_evp();

	std::vector<uint8_t> get_actual_result_cipher();
	std::vector<uint8_t> get_expected_result_cipher();

	std::vector<uint8_t> get_actual_result_decipher(const std::vector<uint8_t> &ciphertext);
	std::vector<uint8_t> get_expected_result_decipher(const std::vector<uint8_t> &ciphertext);
};

#endif// LIBCRYPTO42_BLOCK_CIPHER_MODE_HH

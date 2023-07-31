#include "block_cipher_mode.hh"
#include "cipher.h"
#include <gtest/gtest.h>
#include <map>
#include <string>

#define CREATE_CBC_TEST(alg, size) BlockCipherTestParams(CIPHER_MODE_CBC, alg, size)

class CBCTests : public BlockCipherModeTests {
protected:
	block_cipher_func *get_block_cipher_func_cipher() const final {
		return CBC_encrypt;
	}

	block_cipher_func *get_block_cipher_func_decipher() const final {
		return CBC_decrypt;
	}

public:
	~CBCTests() override = default;
};

static const std::vector<BlockCipherTestParams> cbc_aes128_params{
	CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 0),   CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 1),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 8),   CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 16),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 26),  CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 31),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 32),  CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 73),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 79),  CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 128),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES128, 512),
};

static const std::vector<BlockCipherTestParams> cbc_aes192_params{
	CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 0),   CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 1),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 8),   CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 16),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 26),  CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 31),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 32),  CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 73),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 79),  CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 128),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES192, 512),
};

static const std::vector<BlockCipherTestParams> cbc_aes256_params{
	CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 0),   CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 1),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 8),   CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 16),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 26),  CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 31),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 32),  CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 73),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 79),  CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 128),
	CREATE_CBC_TEST(BLOCK_CIPHER_AES256, 512),
};

INSTANTIATE_TEST_SUITE_P(aes128, CBCTests, testing::ValuesIn(cbc_aes128_params));
INSTANTIATE_TEST_SUITE_P(aes192, CBCTests, testing::ValuesIn(cbc_aes192_params));
INSTANTIATE_TEST_SUITE_P(aes256, CBCTests, testing::ValuesIn(cbc_aes256_params));

TEST_P(CBCTests, cipher) {
	run_cipher_test();
}

TEST_P(CBCTests, decipher) {
	run_decipher_test();
}
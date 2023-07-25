#include "cipher.h"
#include <gtest/gtest.h>

TEST(DES, cipher) {
	uint64_t key = 0b0001001100110100010101110111100110011011101111001101111111110001;

	uint64_t blk      = 0x0123456789ABCDEF;
	uint64_t expected = 0x85E813540F0AB405;
	uint64_t actual   = des_encrypt(blk, key);

	EXPECT_EQ(actual, expected);
}

TEST(DES, decipher) {
	uint64_t key = 0b0001001100110100010101110111100110011011101111001101111111110001;

	uint64_t ciphered = 0x85E813540F0AB405;
	uint64_t expected = 0x0123456789ABCDEF;
	uint64_t actual   = des_decrypt(ciphered, key);

	EXPECT_EQ(actual, expected);
}
#include "cipher.h"
#include <gtest/gtest.h>

TEST(DES, cipher) {
	std::vector<uint8_t> key{ 0b00010011, 0b00110100, 0b01010111, 0b01111001,
		                      0b10011011, 0b10111100, 0b11011111, 0b11110001 };

	std::vector<uint8_t> blk{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

	std::vector<uint8_t> expected{ 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };

	uint8_t             *actual = des_encrypt(blk.data(), key.data());

	std::vector<uint8_t> actual_vec(actual, actual + blk.size());
	free(actual);
	EXPECT_EQ(actual_vec, expected);
}

TEST(DES, decipher) {
	std::vector<uint8_t> key{ 0b00010011, 0b00110100, 0b01010111, 0b01111001,
		                      0b10011011, 0b10111100, 0b11011111, 0b11110001 };

	std::vector<uint8_t> ciphered{ 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };
	std::vector<uint8_t> expected{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

	uint8_t             *actual = des_decrypt(ciphered.data(), key.data());

	std::vector<uint8_t> actual_vec(actual, actual + ciphered.size());
	free(actual);
	EXPECT_EQ(actual_vec, expected);
}
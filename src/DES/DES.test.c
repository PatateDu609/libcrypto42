#include "cipher.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>

Test(DES, cipher) {
	uint64_t key = 0b0001001100110100010101110111100110011011101111001101111111110001;

	uint64_t blk	  = 0x0123456789ABCDEF;
	uint64_t expected = 0x85E813540F0AB405;
	uint64_t actual	  = des_encrypt(blk, key);

	cr_expect(eq(i64, actual, expected));
}

Test(DES, decipher) {
	uint64_t key = 0b0001001100110100010101110111100110011011101111001101111111110001;

	uint64_t ciphered  = 0x85E813540F0AB405;
	uint64_t expected = 0x0123456789ABCDEF;
	uint64_t actual	  = des_decrypt(ciphered, key);

	cr_expect(eq(i64, actual, expected));
}
#include "cipher.h"

static uint8_t *tdes_ede_encrypt(uint8_t *block, const uint8_t *k1, const uint8_t *k2, const uint8_t *k3) {
	uint8_t *t1, *t2, *t3;

	t1 = des_encrypt(block, k1);
	if (!t1)
		return NULL;

	t2 = des_decrypt(t1, k2);
	free(t1);
	if (!t2)
		return NULL;

	t3 = des_encrypt(t2, k3);
	free(t2);
	return t3;
}

static uint8_t *tdes_ede_decrypt(uint8_t *block, const uint8_t *k1, const uint8_t *k2, const uint8_t *k3) {
	uint8_t *t1, *t2, *t3;

	t1 = des_decrypt(block, k3);
	if (!t1)
		return NULL;

	t2 = des_encrypt(t1, k2);
	free(t1);
	if (!t2)
		return NULL;

	t3 = des_decrypt(t2, k1);
	free(t2);
	return t3;
}

uint8_t *tdes_ede3_encrypt(uint8_t *block, const uint8_t *key) {
	return tdes_ede_encrypt(block, key, key + 8, key + 16);
}

uint8_t *tdes_ede2_encrypt(uint8_t *block, const uint8_t *key) {
	return tdes_ede_encrypt(block, key, key + 8, key);
}

uint8_t *tdes_ede3_decrypt(uint8_t *block, const uint8_t *key) {
	return tdes_ede_decrypt(block, key, key + 8, key + 16);
}

uint8_t *tdes_ede2_decrypt(uint8_t *block, const uint8_t *key) {
	return tdes_ede_decrypt(block, key, key + 8, key);
}
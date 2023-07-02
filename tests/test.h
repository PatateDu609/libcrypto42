#ifndef LIBCRYPTO42_TEST_H
#define LIBCRYPTO42_TEST_H

#include <stdio.h>

static inline void get_output(const unsigned char *result, int digest_len, char *hash) {
	for (int i = 0; i < digest_len; i++) {
		snprintf(&hash[i * 2], 3, "%02x", result[i]);
	}
}

#endif// LIBCRYPTO42_TEST_H

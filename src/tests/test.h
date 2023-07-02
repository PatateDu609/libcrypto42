#ifndef LIBCRYPTO42_TEST_H
#define LIBCRYPTO42_TEST_H

#include <criterion/parameterized.h>
#include <openssl/evp.h>
#include <stdio.h>

static inline void get_output(const unsigned char *result, int digest_len, char *hash) {
	for (int i = 0; i < digest_len; i++) {
		snprintf(&hash[i * 2], 3, "%02x", result[i]);
	}
}

#define NB_DIGEST_TEST_STRINGS 10
#define NB_DIGEST_TEST_FILES 7

extern const char *digest_test_strings[NB_DIGEST_TEST_STRINGS];
extern const char *digest_test_filenames[NB_DIGEST_TEST_FILES];

struct digest_params {
	char *str;
};


void run_digest_string_test(const EVP_MD *md, const char *arg, char *(*mine)(const char *) );
void run_digest_file_test(const EVP_MD *md, const char *filename, char *(*mine)(const char *) );

void dupe_str_array(const char **arr, size_t len, char **target);
void free_str_array(struct criterion_test_params *ctp);

#endif// LIBCRYPTO42_TEST_H

#ifndef LIBCRYPTO42_TEST_H
#define LIBCRYPTO42_TEST_H

#include <cstdio>
#include <openssl/evp.h>

#include <filesystem>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <vector>

extern std::random_device prng;
extern std::mt19937_64	  prng_engine;

static inline void		  get_output(const unsigned char *result, int digest_len, std::string &str) {
	   std::ostringstream oss;

	   oss << std::hex << std::setw(2) << std::setfill('0');

	   for (int i = 0; i < digest_len; i++) {
		   oss << (int) result[0];
	   }

	   str = oss.str();
}

extern std::vector<std::filesystem::path>		test_filenames;
extern std::vector<std::basic_string<uint8_t> > test_strings;

void run_digest_string_test(const EVP_MD *md, const char *arg, char *(*mine)(const char *) );
void run_digest_file_test(const EVP_MD *md, const char *filename, char *(*mine)(const char *) );

#endif// LIBCRYPTO42_TEST_H

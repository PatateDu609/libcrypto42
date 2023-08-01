#include "cipher.h"
#include "internal.h"
#include "random.hh"
#include <gtest/gtest.h>
#include <iostream>
#include <map>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>

#define NB_AES_TEST 64

static std::map<enum aes_type, std::string> aes_type_translator{
	std::make_pair(AES128, "AES128"),
	std::make_pair(AES192, "AES192"),
	std::make_pair(AES256, "AES256"),
};

struct AES_TestParams {
	typedef uint8_t *(aes_func) (uint8_t *, const uint8_t *);

	enum aes_type                           type;
	std::array<uint8_t, AES_BLK_SIZE_BYTES> raw;
	std::vector<uint8_t>                    key;

	const char                             *evp_alg;
	aes_func                               *enc_func;
	aes_func                               *dec_func;

	explicit AES_TestParams(enum aes_type t)
		: type(t), raw(), key(), evp_alg(nullptr), enc_func(nullptr), dec_func(nullptr) {
		using rng::get_random_data;

		auto raw_data = get_random_data(raw.size());
		std::move(raw_data.begin(), raw_data.end(), raw.begin());

		switch (t) {
		case AES128:
			key      = get_random_data(AES128_KEY_SIZE_BYTES);
			enc_func = aes128_encrypt;
			dec_func = aes128_decrypt;
			evp_alg  = "AES-128-ECB";
			break;
		case AES192:
			key      = get_random_data(AES192_KEY_SIZE_BYTES);
			enc_func = aes192_encrypt;
			dec_func = aes192_decrypt;
			evp_alg  = "AES-192-ECB";
			break;
		case AES256:
			key      = get_random_data(AES256_KEY_SIZE_BYTES);
			enc_func = aes256_encrypt;
			dec_func = aes256_decrypt;
			evp_alg  = "AES-256-ECB";
			break;
		}
	}
};

std::ostream &operator<<(std::ostream &os, const AES_TestParams &params) {
	static std::map<AES_TestParams::aes_func *, std::string> my_function_translator{
		std::make_pair(aes128_encrypt, "aes128_encrypt"), std::make_pair(aes128_decrypt, "aes128_decrypt"),
		std::make_pair(aes192_encrypt, "aes192_encrypt"), std::make_pair(aes192_decrypt, "aes192_decrypt"),
		std::make_pair(aes256_encrypt, "aes256_encrypt"), std::make_pair(aes256_decrypt, "aes256_decrypt"),
	};

	os << aes_type_translator[params.type] << ", evp alg = " << params.evp_alg;
	os << ", my functions: encrypt = " << my_function_translator[params.enc_func];
	os << ", decrypt = " << my_function_translator[params.dec_func];
	return os;
}

class AES_Tests : public testing::TestWithParam<AES_TestParams> {
private:
	void destroy_ctx() {
		if (ctx) {
			EVP_CIPHER_CTX_free(ctx);
			ctx         = nullptr;
			evp_blk_len = 0;
		}
	}

	void destroy_evp() {
		if (evp) {
			EVP_CIPHER_free(evp);
			evp = nullptr;
		}
	}

protected:
	EVP_CIPHER     *evp;
	EVP_CIPHER_CTX *ctx;
	int             evp_blk_len;

public:
	AES_Tests() : evp(nullptr), ctx(nullptr), evp_blk_len(0) {}

	~AES_Tests() override {
		destroy_ctx();
	}

	void SetUp() override {
		destroy_ctx();
		destroy_evp();

		const char *evp_alg = GetParam().evp_alg;

		if (!(evp = EVP_CIPHER_fetch(nullptr, evp_alg, nullptr))) {
			uint64_t err = ERR_get_error();
			std::cerr << "error: couldn't fetch algorithm \"" << evp_alg << "\": " << ERR_lib_error_string(err) << ": "
					  << ERR_reason_error_string(err) << std::endl;
			exit(EXIT_FAILURE);
		}
		ASSERT_NE(evp, nullptr);

		ctx = EVP_CIPHER_CTX_new();
		ASSERT_NE(ctx, nullptr);

		evp_blk_len = EVP_CIPHER_get_block_size(evp);
		ASSERT_EQ(evp_blk_len, AES_BLK_SIZE_BYTES);
	}

	void TearDown() override {
		destroy_evp();
		destroy_ctx();
	}
};

const static auto &name_generator = [](const testing::TestParamInfo<AES_TestParams> &info) {
	std::ostringstream oss;

	oss << aes_type_translator[info.param.type] << "_" << info.index;

	return oss.str();
};

static const std::vector<AES_TestParams> params128(NB_AES_TEST, AES_TestParams(AES128));
static const std::vector<AES_TestParams> params192(NB_AES_TEST, AES_TestParams(AES192));
static const std::vector<AES_TestParams> params256(NB_AES_TEST, AES_TestParams(AES256));

INSTANTIATE_TEST_SUITE_P(aes128, AES_Tests, testing::ValuesIn(params128), name_generator);
INSTANTIATE_TEST_SUITE_P(aes192, AES_Tests, testing::ValuesIn(params192), name_generator);
INSTANTIATE_TEST_SUITE_P(aes256, AES_Tests, testing::ValuesIn(params256), name_generator);

TEST_P(AES_Tests, encrypt) {
	auto                     param        = GetParam();
	int                      expected_len = evp_blk_len;
	std::shared_ptr<uint8_t> actual_data(param.enc_func(param.raw.data(), param.key.data()), free);

	auto                     expected_data = (uint8_t *) OPENSSL_malloc(expected_len);

	EVP_EncryptInit_ex2(ctx, evp, param.key.data(), nullptr, nullptr);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	EVP_EncryptUpdate(ctx, expected_data, &expected_len, param.raw.data(), evp_blk_len);
	EVP_EncryptFinal_ex(ctx, expected_data, &expected_len);

	std::vector<uint8_t> expected(expected_data, expected_data + evp_blk_len);
	std::vector<uint8_t> actual(actual_data.get(), actual_data.get() + AES_BLK_SIZE_BYTES);
	EXPECT_EQ(expected, actual);

	OPENSSL_free(expected_data);
}

TEST_P(AES_Tests, decrypt) {
	auto                     param        = GetParam();
	int                      expected_len = evp_blk_len;
	std::shared_ptr<uint8_t> actual_data(param.dec_func(param.raw.data(), param.key.data()), free);

	auto                     expected_data = (uint8_t *) OPENSSL_malloc(expected_len);

	EVP_DecryptInit_ex2(ctx, evp, param.key.data(), nullptr, nullptr);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	EVP_DecryptUpdate(ctx, expected_data, &expected_len, param.raw.data(), evp_blk_len);
	EVP_DecryptFinal_ex(ctx, expected_data, &expected_len);

	std::vector<uint8_t> expected(expected_data, expected_data + evp_blk_len);
	std::vector<uint8_t> actual(actual_data.get(), actual_data.get() + AES_BLK_SIZE_BYTES);
	EXPECT_EQ(expected, actual);

	OPENSSL_free(expected_data);
}

typedef uint8_t *(do_aes) (uint8_t *, const uint8_t *);
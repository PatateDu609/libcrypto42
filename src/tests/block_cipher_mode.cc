#include "block_cipher_mode.hh"
#include "crypto.h"
#include "random.hh"
#include <map>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <sstream>

static std::map<enum block_cipher, std::string> block_cipher_translator{
	{BLOCK_CIPHER_AES128,     "AES128"   },
    { BLOCK_CIPHER_AES192,    "AES192"   },
    { BLOCK_CIPHER_AES256,    "AES256"   },
	{ BLOCK_CIPHER_DES,       "DES"      },
    { BLOCK_CIPHER_3DES_EDE2, "3DES_EDE2"},
    { BLOCK_CIPHER_3DES_EDE3, "3DES_EDE3"},
};

__unused static OSSL_PROVIDER *OSSL_legacy  = OSSL_PROVIDER_load(nullptr, "legacy");
__unused static OSSL_PROVIDER *OSSL_default = OSSL_PROVIDER_load(nullptr, "default");

BlockCipherTestParams::BlockCipherTestParams(enum cipher_mode mode, enum block_cipher type, size_t plaintext_size)
	: block_ctx(setup_algo(type)), evp_alg(get_alg(mode, type)), plaintext(), key() {
	using rng::get_random_data;

	plaintext = get_random_data(plaintext_size);
	key       = get_random_data(block_ctx.key_size);

	if (mode != CIPHER_MODE_ECB)
		iv = get_random_data(block_ctx.blk_size);
}

std::string BlockCipherTestParams::get_alg(enum cipher_mode mode, enum block_cipher type) {
	std::ostringstream oss;
	switch (type) {
	case BLOCK_CIPHER_AES128:
		oss << "AES-128";
		break;
	case BLOCK_CIPHER_AES192:
		oss << "AES-192";
		break;
	case BLOCK_CIPHER_AES256:
		oss << "AES-256";
		break;
	default:
		throw std::invalid_argument("unexpected block_cipher type: " + block_cipher_translator[type]);
	}

	switch (mode) {
	case CIPHER_MODE_CBC:
		oss << "-CBC";
		break;
	case CIPHER_MODE_ECB:
		oss << "-ECB";
		break;
	}
	return oss.str();
}

bool BlockCipherTestParams::is_legacy() const {
	enum block_cipher type = block_ctx.type;

	return type == BLOCK_CIPHER_DES;
}

EVP_CIPHER *BlockCipherTestParams::load_evp() const {
	EVP_CIPHER *evp;
	const char *properties = is_legacy() ? "provider=legacy" : nullptr;

	evp = EVP_CIPHER_fetch(nullptr, evp_alg.c_str(), properties);
	if (!evp) {
		uint64_t err = ERR_get_error();
		std::cerr << "error: couldn't fetch algorithm \"" << evp_alg << "\": " << ERR_lib_error_string(err) << ": "
				  << ERR_reason_error_string(err) << std::endl;
		exit(EXIT_FAILURE);
	}

	return evp;
}

std::ostream &operator<<(std::ostream &os, const BlockCipherTestParams &param) {
	os << "type = " << block_cipher_translator[param.block_ctx.type] << ", ";
	os << "evp_alg = " << param.evp_alg << ", ";
	os << "plaintext_size = " << param.plaintext.size() << ", ";
	os << "has IV ? " << (param.iv.empty() ? "No" : "Yes");
	return os;
}

void BlockCipherModeTests::destroy_ctx() {
	if (evp_ctx) {
		EVP_CIPHER_CTX_free(evp_ctx);
		evp_ctx     = nullptr;
		evp_blk_len = 0;
	}
}

void BlockCipherModeTests::destroy_evp() {
	if (evp) {
		EVP_CIPHER_free(evp);
		evp = nullptr;
	}
}

std::vector<uint8_t> BlockCipherModeTests::get_actual_result_cipher() {
	auto     param = GetParam();

	uint8_t *plaintext = nullptr;
	if (!param.plaintext.empty()) {
		plaintext = static_cast<uint8_t *>(calloc(param.plaintext.size(), sizeof param.plaintext[0]));

		if (plaintext == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(plaintext, param.plaintext.data(), param.plaintext.size() * sizeof param.plaintext[0]);
	}

	struct cipher_ctx ctx {};
	ctx.algo          = param.block_ctx;
	ctx.key_len       = param.key.size();
	ctx.key           = param.key.data();
	ctx.plaintext_len = param.plaintext.size();
	ctx.plaintext     = plaintext;

	auto func = get_block_cipher_func_cipher();
	if (func(&ctx) == nullptr)
		throw std::runtime_error("got NULL from encrypt function");
	if (ctx.plaintext != plaintext)
		plaintext = ctx.plaintext;

	std::vector<uint8_t> ciphertext(ctx.ciphertext, ctx.ciphertext + ctx.ciphertext_len);
	free(ctx.ciphertext);
	free(plaintext);
	return ciphertext;
}

std::vector<uint8_t> BlockCipherModeTests::get_actual_result_decipher(const std::vector<uint8_t> &ciphertext) {
	auto     param = GetParam();

	uint8_t *ciphertext_copy = nullptr;
	if (!ciphertext.empty()) {
		ciphertext_copy = static_cast<uint8_t *>(calloc(ciphertext.size(), sizeof(uint8_t)));

		if (ciphertext_copy == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(ciphertext_copy, ciphertext.data(), ciphertext.size() * sizeof(uint8_t));
	}

	struct cipher_ctx ctx {};
	ctx.algo           = param.block_ctx;
	ctx.key_len        = param.key.size();
	ctx.key            = param.key.data();
	ctx.ciphertext_len = ciphertext.size();
	ctx.ciphertext     = ciphertext_copy;

	auto     func = get_block_cipher_func_decipher();
	uint8_t *ret  = func(&ctx);
	if (ret == nullptr && ctx.ciphertext && ctx.ciphertext_len && ctx.ciphertext_len != param.block_ctx.blk_size)
		throw std::runtime_error("got NULL from decrypt function");
	if (ctx.ciphertext != ciphertext_copy)
		ciphertext_copy = ctx.ciphertext;
	if (!ctx.plaintext_len) {
		free(ciphertext_copy);
		return {};
	}

	std::vector<uint8_t> plaintext(ctx.plaintext, ctx.plaintext + ctx.plaintext_len);
	free(ctx.plaintext);
	free(ciphertext_copy);
	return plaintext;
}

std::vector<uint8_t> BlockCipherModeTests::get_expected_result_cipher() {
	auto   param        = GetParam();
	int    expected_len = (int) param.plaintext.size();
	size_t size;

	size_t rem           = expected_len % evp_blk_len;
	auto   expected_data = static_cast<uint8_t *>(malloc(expected_len + (evp_blk_len - rem)));
	if (expected_data == nullptr)
		throw std::runtime_error("couldn't allocate memory");

	EVP_EncryptInit_ex2(evp_ctx, evp, param.key.data(), nullptr, nullptr);

	EVP_EncryptUpdate(evp_ctx, expected_data, &expected_len, param.plaintext.data(), expected_len);
	size = expected_len;

	EVP_EncryptFinal_ex(evp_ctx, expected_data + expected_len, &expected_len);
	size += expected_len;

	std::vector<uint8_t> expected(expected_data, expected_data + size);
	free(expected_data);
	return expected;
}

std::vector<uint8_t> BlockCipherModeTests::get_expected_result_decipher(const std::vector<uint8_t> &ciphertext) {
	auto   param        = GetParam();
	int    expected_len = (int) ciphertext.size();
	size_t size;

	auto   expected_data = static_cast<uint8_t *>(OPENSSL_malloc(expected_len ? expected_len * 20 : evp_blk_len * 2));
	if (expected_data == nullptr)
		throw std::runtime_error("couldn't allocate memory");

	EVP_DecryptInit_ex2(evp_ctx, evp, param.key.data(), nullptr, nullptr);

	EVP_DecryptUpdate(evp_ctx, expected_data, &expected_len, ciphertext.data(), expected_len);
	size = expected_len;

	EVP_DecryptFinal_ex(evp_ctx, expected_data + expected_len, &expected_len);
	size += expected_len;

	std::vector<uint8_t> expected(expected_data, expected_data + size);
	OPENSSL_free(expected_data);
	return expected;
}

BlockCipherModeTests::BlockCipherModeTests() : evp(nullptr), evp_ctx(nullptr), evp_blk_len(0) {}

void BlockCipherModeTests::SetUp() {
	destroy_ctx();
	destroy_evp();

	evp = GetParam().load_evp();
	ASSERT_NE(evp, nullptr);

	evp_ctx = EVP_CIPHER_CTX_new();
	ASSERT_NE(evp_ctx, nullptr);

	evp_blk_len = EVP_CIPHER_get_block_size(evp);
	ASSERT_EQ(evp_blk_len, AES_BLK_SIZE_BYTES);
}

void BlockCipherModeTests::TearDown() {
	ASSERT_NO_FATAL_FAILURE(destroy_evp());
	ASSERT_NO_FATAL_FAILURE(destroy_ctx());
}

void BlockCipherModeTests::run_cipher_test() {
	std::vector<uint8_t> actual, expected;
	ASSERT_NO_THROW(actual = get_actual_result_cipher());
	ASSERT_NO_THROW(expected = get_expected_result_cipher());

	EXPECT_EQ(actual, expected);
}

void BlockCipherModeTests::run_decipher_test() {
	std::vector<uint8_t> ciphertext = get_expected_result_cipher();

	std::vector<uint8_t> actual, expected;
	ASSERT_NO_THROW(actual = get_actual_result_decipher(ciphertext));
	ASSERT_NO_THROW(expected = get_expected_result_decipher(ciphertext));

	EXPECT_EQ(actual, expected);
}
#include "block_cipher_mode.hh"
#include "crypto.h"
#include "random.hh"
#include <map>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <sstream>

static std::map<enum block_cipher, std::string> block_cipher_translator{
	{BLOCK_CIPHER_AES128,          "AES128"        },
	{ BLOCK_CIPHER_AES128_ECB,     "AES128-ECB"    },
	{ BLOCK_CIPHER_AES128_CBC,     "AES128-CBC"    },
	{ BLOCK_CIPHER_AES128_CFB,     "AES128-CFB"    },
	{ BLOCK_CIPHER_AES128_CFB1,    "AES128-CFB1"   },
	{ BLOCK_CIPHER_AES128_CFB8,    "AES128-CFB8"   },
	{ BLOCK_CIPHER_AES128_OFB,     "AES128-OFB"    },

	{ BLOCK_CIPHER_AES192,         "AES192"        },
	{ BLOCK_CIPHER_AES192_ECB,     "AES192-ECB"    },
	{ BLOCK_CIPHER_AES192_CBC,     "AES192-CBC"    },
	{ BLOCK_CIPHER_AES192_CFB,     "AES192-CFB"    },
	{ BLOCK_CIPHER_AES192_CFB1,    "AES192-CFB1"   },
	{ BLOCK_CIPHER_AES192_CFB8,    "AES192-CFB8"   },
	{ BLOCK_CIPHER_AES192_OFB,     "AES192-OFB"    },

	{ BLOCK_CIPHER_AES256,         "AES256"        },
	{ BLOCK_CIPHER_AES256_ECB,     "AES256-ECB"    },
	{ BLOCK_CIPHER_AES256_CBC,     "AES256-CBC"    },
	{ BLOCK_CIPHER_AES256_CFB,     "AES256-CFB"    },
	{ BLOCK_CIPHER_AES256_CFB1,    "AES256-CFB1"   },
	{ BLOCK_CIPHER_AES256_CFB8,    "AES256-CFB8"   },
	{ BLOCK_CIPHER_AES256_OFB,     "AES256-OFB"    },

	{ BLOCK_CIPHER_DES,            "DES"           },
	{ BLOCK_CIPHER_DES_ECB,        "DES-ECB"       },
	{ BLOCK_CIPHER_DES_CBC,        "DES-CBC"       },
	{ BLOCK_CIPHER_DES_CFB,        "DES-CFB"       },
	{ BLOCK_CIPHER_DES_CFB1,       "DES-CFB1"      },
	{ BLOCK_CIPHER_DES_CFB8,       "DES-CFB8"      },
	{ BLOCK_CIPHER_DES_OFB,        "DES-OFB"       },

	{ BLOCK_CIPHER_3DES_EDE2,      "3DES_EDE2"     },
	{ BLOCK_CIPHER_3DES_EDE2_ECB,  "3DES_EDE2-ECB" },
	{ BLOCK_CIPHER_3DES_EDE2_CBC,  "3DES_EDE2-CBC" },
	{ BLOCK_CIPHER_3DES_EDE2_CFB,  "3DES_EDE2-CFB" },
	{ BLOCK_CIPHER_3DES_EDE2_CFB1, "3DES_EDE2-CFB1"},
	{ BLOCK_CIPHER_3DES_EDE2_CFB8, "3DES_EDE2-CFB8"},
	{ BLOCK_CIPHER_3DES_EDE2_OFB,  "3DES_EDE2-OFB" },

	{ BLOCK_CIPHER_3DES_EDE3,      "3DES_EDE3"     },
	{ BLOCK_CIPHER_3DES_EDE3_ECB,  "3DES_EDE3-ECB" },
	{ BLOCK_CIPHER_3DES_EDE3_CBC,  "3DES_EDE3-CBC" },
	{ BLOCK_CIPHER_3DES_EDE3_CFB,  "3DES_EDE3-CFB" },
	{ BLOCK_CIPHER_3DES_EDE3_CFB1, "3DES_EDE3-CFB1"},
	{ BLOCK_CIPHER_3DES_EDE3_CFB8, "3DES_EDE3-CFB8"},
	{ BLOCK_CIPHER_3DES_EDE3_OFB,  "3DES_EDE3-OFB" },
};

__unused static OSSL_PROVIDER *OSSL_legacy  = OSSL_PROVIDER_load(nullptr, "legacy");
__unused static OSSL_PROVIDER *OSSL_default = OSSL_PROVIDER_load(nullptr, "default");

static enum block_cipher       mix_cipher_mode_and_operation_mode(enum cipher_mode mode, enum block_cipher type) {
    static std::map<enum block_cipher, enum block_cipher> translator_ecb {
			  {BLOCK_CIPHER_DES,        BLOCK_CIPHER_DES_ECB      },
			  { BLOCK_CIPHER_3DES_EDE2, BLOCK_CIPHER_3DES_EDE2_ECB},
			  { BLOCK_CIPHER_3DES_EDE3, BLOCK_CIPHER_3DES_EDE3_ECB},
			  { BLOCK_CIPHER_AES128,    BLOCK_CIPHER_AES128_ECB   },
			  { BLOCK_CIPHER_AES192,    BLOCK_CIPHER_AES192_ECB   },
			  { BLOCK_CIPHER_AES256,    BLOCK_CIPHER_AES256_ECB   },
    };

    static std::map<enum block_cipher, enum block_cipher> translator_cbc {
			  {BLOCK_CIPHER_DES,        BLOCK_CIPHER_DES_CBC      },
			  { BLOCK_CIPHER_3DES_EDE2, BLOCK_CIPHER_3DES_EDE2_CBC},
			  { BLOCK_CIPHER_3DES_EDE3, BLOCK_CIPHER_3DES_EDE3_CBC},
			  { BLOCK_CIPHER_AES128,    BLOCK_CIPHER_AES128_CBC   },
			  { BLOCK_CIPHER_AES192,    BLOCK_CIPHER_AES192_CBC   },
			  { BLOCK_CIPHER_AES256,    BLOCK_CIPHER_AES256_CBC   },
    };

    static std::map<enum block_cipher, enum block_cipher> translator_cfb {
			  {BLOCK_CIPHER_DES,        BLOCK_CIPHER_DES_CFB      },
			  { BLOCK_CIPHER_3DES_EDE2, BLOCK_CIPHER_3DES_EDE2_CFB},
			  { BLOCK_CIPHER_3DES_EDE3, BLOCK_CIPHER_3DES_EDE3_CFB},
			  { BLOCK_CIPHER_AES128,    BLOCK_CIPHER_AES128_CFB   },
			  { BLOCK_CIPHER_AES192,    BLOCK_CIPHER_AES192_CFB   },
			  { BLOCK_CIPHER_AES256,    BLOCK_CIPHER_AES256_CFB   },
    };

    static std::map<enum block_cipher, enum block_cipher> translator_cfb1 {
			  {BLOCK_CIPHER_DES,        BLOCK_CIPHER_DES_CFB1      },
			  { BLOCK_CIPHER_3DES_EDE2, BLOCK_CIPHER_3DES_EDE2_CFB1},
			  { BLOCK_CIPHER_3DES_EDE3, BLOCK_CIPHER_3DES_EDE3_CFB1},
			  { BLOCK_CIPHER_AES128,    BLOCK_CIPHER_AES128_CFB1   },
			  { BLOCK_CIPHER_AES192,    BLOCK_CIPHER_AES192_CFB1   },
			  { BLOCK_CIPHER_AES256,    BLOCK_CIPHER_AES256_CFB1   },
    };

    static std::map<enum block_cipher, enum block_cipher> translator_cfb8 {
			  {BLOCK_CIPHER_DES,        BLOCK_CIPHER_DES_CFB8      },
			  { BLOCK_CIPHER_3DES_EDE2, BLOCK_CIPHER_3DES_EDE2_CFB8},
			  { BLOCK_CIPHER_3DES_EDE3, BLOCK_CIPHER_3DES_EDE3_CFB8},
			  { BLOCK_CIPHER_AES128,    BLOCK_CIPHER_AES128_CFB8   },
			  { BLOCK_CIPHER_AES192,    BLOCK_CIPHER_AES192_CFB8   },
			  { BLOCK_CIPHER_AES256,    BLOCK_CIPHER_AES256_CFB8   },
    };

    static std::map<enum block_cipher, enum block_cipher> translator_ofb {
			  {BLOCK_CIPHER_DES,        BLOCK_CIPHER_DES_OFB      },
			  { BLOCK_CIPHER_3DES_EDE2, BLOCK_CIPHER_3DES_EDE2_OFB},
			  { BLOCK_CIPHER_3DES_EDE3, BLOCK_CIPHER_3DES_EDE3_OFB},
			  { BLOCK_CIPHER_AES128,    BLOCK_CIPHER_AES128_OFB   },
			  { BLOCK_CIPHER_AES192,    BLOCK_CIPHER_AES192_OFB   },
			  { BLOCK_CIPHER_AES256,    BLOCK_CIPHER_AES256_OFB   },
    };

    static std::map<enum block_cipher, enum block_cipher> translator_ctr {
			  { BLOCK_CIPHER_3DES_EDE2, BLOCK_CIPHER_3DES_EDE2_CTR},
			  { BLOCK_CIPHER_3DES_EDE3, BLOCK_CIPHER_3DES_EDE3_CTR},
			  { BLOCK_CIPHER_AES128,    BLOCK_CIPHER_AES128_CTR   },
			  { BLOCK_CIPHER_AES192,    BLOCK_CIPHER_AES192_CTR   },
			  { BLOCK_CIPHER_AES256,    BLOCK_CIPHER_AES256_CTR   },
    };

    switch (mode) {
    case CIPHER_MODE_ECB:
        return translator_ecb[type];
    case CIPHER_MODE_CBC:
        return translator_cbc[type];
    case CIPHER_MODE_CFB:
        return translator_cfb[type];
    case CIPHER_MODE_CFB1:
        return translator_cfb1[type];
    case CIPHER_MODE_CFB8:
        return translator_cfb8[type];
    case CIPHER_MODE_OFB:
        return translator_ofb[type];
    case CIPHER_MODE_CTR:
        return translator_ctr[type];
    }
}

BlockCipherTestParams::BlockCipherTestParams(enum cipher_mode mode, enum block_cipher type, size_t plaintext_size)
	: block_ctx(setup_algo(mix_cipher_mode_and_operation_mode(mode, type))), evp_alg(get_alg(mode, type)), plaintext(),
	  key(), iv(), true_expected() {
	using rng::get_random_data;

	plaintext  = get_random_data(plaintext_size);
	key        = get_random_data(block_ctx.key_size);
	this->mode = mode;

	if (mode == CIPHER_MODE_CTR)
		nonce = get_random_data(block_ctx.blk_size);
	else if (mode != CIPHER_MODE_ECB)
		iv = get_random_data(block_ctx.blk_size);
}

BlockCipherTestParams::BlockCipherTestParams(enum cipher_mode mode, enum block_cipher type, std::vector<uint8_t> key,
                                             std::vector<uint8_t> plaintext, std::vector<uint8_t> iv,
                                             std::vector<uint8_t> true_expected)
	: BlockCipherTestParams(mode, type, 0) {
	this->plaintext     = plaintext;
	this->key           = key;
	this->iv            = iv;
	this->true_expected = true_expected;
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
	case BLOCK_CIPHER_DES:
		oss << "DES";
		break;
	case BLOCK_CIPHER_3DES_EDE2:
		oss << "DES-EDE";
		break;
	case BLOCK_CIPHER_3DES_EDE3:
		oss << "DES-EDE3";
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
	case CIPHER_MODE_OFB:
		oss << "-OFB";
		break;
	case CIPHER_MODE_CFB:
		oss << "-CFB";
		break;
	case CIPHER_MODE_CFB1:
		oss << "-CFB1";
		break;
	case CIPHER_MODE_CFB8:
		oss << "-CFB8";
		break;
	case CIPHER_MODE_CTR:
		oss << "-CTR";
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
				  << ERR_reason_error_string(err) << '\n';
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

	if (!param.iv.empty()) {
		ctx.iv_len = param.iv.size();
		ctx.iv     = static_cast<uint8_t *>(calloc(param.iv.size(), sizeof param.iv[0]));

		if (ctx.iv == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(ctx.iv, param.iv.data(), param.iv.size() * sizeof param.iv[0]);
	}

	if (!param.nonce.empty()) {
		ctx.nonce_len = param.nonce.size();
		ctx.nonce     = static_cast<uint8_t *>(calloc(param.nonce.size(), sizeof param.nonce[0]));

		if (ctx.nonce == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(ctx.nonce, param.nonce.data(), param.nonce.size() * sizeof param.nonce[0]);
	}

	auto     func = get_block_cipher_func_cipher();
	auto     mode = block_cipher_get_mode(ctx.algo.type);
	uint8_t *ret  = func(&ctx);
	EXPECT_EQ(ret, ctx.ciphertext);
	if (ret == nullptr &&
	    !(ctx.plaintext_len == 0 && (mode == CIPHER_MODE_CFB || mode == CIPHER_MODE_CFB1 || mode == CIPHER_MODE_CFB8 ||
	                                 mode == CIPHER_MODE_OFB || mode == CIPHER_MODE_CTR)))
		throw std::runtime_error("got NULL from encrypt function");
	if (ctx.plaintext != plaintext)
		plaintext = ctx.plaintext;

	std::vector<uint8_t> ciphertext(ctx.ciphertext, ctx.ciphertext + ctx.ciphertext_len);
	free(ctx.ciphertext);
	free(ctx.iv);
	free(ctx.nonce);
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

	if (!param.iv.empty()) {
		ctx.iv_len = param.iv.size();
		ctx.iv     = static_cast<uint8_t *>(calloc(param.iv.size(), sizeof param.iv[0]));

		if (ctx.iv == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(ctx.iv, param.iv.data(), param.iv.size() * sizeof param.iv[0]);
	}

	if (!param.nonce.empty()) {
		ctx.nonce_len = param.nonce.size();
		ctx.nonce     = static_cast<uint8_t *>(calloc(param.nonce.size(), sizeof param.nonce[0]));

		if (ctx.nonce == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(ctx.nonce, param.nonce.data(), param.nonce.size() * sizeof param.nonce[0]);
	}

	auto     func = get_block_cipher_func_decipher();
	uint8_t *ret  = func(&ctx);
	EXPECT_EQ(ret, ctx.plaintext);
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
	free(ctx.iv);
	free(ctx.nonce);
	free(ciphertext_copy);
	return plaintext;
}

std::vector<uint8_t> BlockCipherModeTests::get_expected_result_cipher() {
	auto   param        = GetParam();
	int    expected_len = (int) param.plaintext.size();
	size_t size;

	size_t blk_len       = evp_blk_len == 1 ? 16 * evp_blk_len : evp_blk_len;
	size_t rem           = expected_len % blk_len;
	auto   expected_data = static_cast<uint8_t *>(malloc(expected_len + (evp_blk_len - rem)));
	if (expected_data == nullptr)
		throw std::runtime_error("couldn't allocate memory");

	uint8_t *iv = nullptr;
	if (!param.iv.empty()) {
		iv = static_cast<uint8_t *>(calloc(param.iv.size(), sizeof param.iv[0]));

		if (iv == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(iv, param.iv.data(), param.iv.size() * sizeof param.iv[0]);
	} else if (!param.nonce.empty()) {
		iv = static_cast<uint8_t *>(calloc(param.nonce.size(), sizeof param.nonce[0]));

		if (iv == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(iv, param.nonce.data(), param.nonce.size() * sizeof param.nonce[0]);
	}

	EVP_EncryptInit_ex2(evp_ctx, evp, param.key.data(), iv, nullptr);

	EVP_EncryptUpdate(evp_ctx, expected_data, &expected_len, param.plaintext.data(),
	                  static_cast<int>(param.plaintext.size()));
	size = expected_len;

	EVP_EncryptFinal_ex(evp_ctx, expected_data + expected_len, &expected_len);
	size += expected_len;

	std::vector<uint8_t> expected(expected_data, expected_data + size);
	free(expected_data);
	free(iv);
	return expected;
}

std::vector<uint8_t> BlockCipherModeTests::get_expected_result_decipher(const std::vector<uint8_t> &ciphertext) {
	auto   param        = GetParam();
	int    expected_len = (int) ciphertext.size();
	size_t size;

	auto   expected_data = static_cast<uint8_t *>(OPENSSL_malloc(expected_len ? expected_len * 20 : evp_blk_len * 2));
	if (expected_data == nullptr)
		throw std::runtime_error("couldn't allocate memory");

	uint8_t *iv = nullptr;
	if (!param.iv.empty()) {
		iv = static_cast<uint8_t *>(calloc(param.iv.size(), sizeof param.iv[0]));

		if (iv == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(iv, param.iv.data(), param.iv.size() * sizeof param.iv[0]);
	} else if (!param.nonce.empty()) {
		iv = static_cast<uint8_t *>(calloc(param.nonce.size(), sizeof param.nonce[0]));

		if (iv == nullptr)
			throw std::runtime_error("couldn't allocate memory: " + std::string(strerror(errno)));
		memcpy(iv, param.nonce.data(), param.nonce.size() * sizeof param.nonce[0]);
	}

	EVP_DecryptInit_ex2(evp_ctx, evp, param.key.data(), iv, nullptr);

	EVP_DecryptUpdate(evp_ctx, expected_data, &expected_len, ciphertext.data(), expected_len);
	size = expected_len;

	EVP_DecryptFinal_ex(evp_ctx, expected_data + expected_len, &expected_len);
	size += expected_len;

	std::vector<uint8_t> expected(expected_data, expected_data + size);
	OPENSSL_free(expected_data);
	free(iv);
	return expected;
}

BlockCipherModeTests::BlockCipherModeTests() : evp(nullptr), evp_ctx(nullptr), evp_blk_len(0) {}

void BlockCipherModeTests::SetUp() {
	destroy_ctx();
	destroy_evp();

	auto param = GetParam();

	evp = param.load_evp();
	ASSERT_NE(evp, nullptr);

	evp_ctx = EVP_CIPHER_CTX_new();
	ASSERT_NE(evp_ctx, nullptr);

	evp_blk_len = EVP_CIPHER_get_block_size(evp);
	if (param.mode == CIPHER_MODE_ECB || param.mode == CIPHER_MODE_CBC)
		ASSERT_EQ(evp_blk_len, static_cast<int>(param.block_ctx.blk_size));
}

void BlockCipherModeTests::TearDown() {
	ASSERT_NO_FATAL_FAILURE(destroy_evp());
	ASSERT_NO_FATAL_FAILURE(destroy_ctx());
}

void BlockCipherModeTests::run_cipher_test() {
	std::vector<uint8_t> actual, expected, true_expected;
	ASSERT_NO_THROW(actual = get_actual_result_cipher());

	true_expected = GetParam().true_expected;

	if (!true_expected.empty())
		EXPECT_EQ(actual, true_expected);
	else {
		ASSERT_NO_THROW(expected = get_expected_result_cipher());
		EXPECT_EQ(actual, expected);
	}
}

void BlockCipherModeTests::run_decipher_test() {
	std::vector<uint8_t> ciphertext = get_expected_result_cipher();

	std::vector<uint8_t> actual, expected, true_expected;
	ASSERT_NO_THROW(actual = get_actual_result_decipher(ciphertext));

	true_expected = GetParam().true_expected;

	if (!true_expected.empty())
		EXPECT_EQ(actual, true_expected);
	else {
		ASSERT_NO_THROW(expected = get_expected_result_decipher(ciphertext));
		EXPECT_EQ(actual, expected);
	}
}
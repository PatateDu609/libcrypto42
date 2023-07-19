#include "hmac.h"
#include "test.h"
#include <gtest/gtest.h>
#include <openssl/hmac.h>
#include <string>

typedef const EVP_MD *(*EVP_hash)();

struct HMACTestParams {
	std::string key;
	std::string msg;

	HMACTestParams(std::string k, std::string m) : key(std::move(k)), msg(std::move(m)) {}
};

std::ostream &operator<<(std::ostream &os, const HMACTestParams &params) {
	os << "key = " << (params.key.empty() ? "(empty)" : params.key) << ", ";
	os << "msg = " << (params.msg.empty() ? "(empty)" : params.msg);

	return os;
}

static void get_hmac(EVP_hash func, const std::string &key, const std::string &msg, std::string &hash, size_t output) {
	unsigned char result[output];
	HMAC(func(), key.c_str(), (int) key.length(), (uint8_t *) msg.c_str(), msg.length(), result, nullptr);

	get_output(result, (int) output, hash);
}

static void get_hmac_actual(enum hmac_algorithm alg, const std::string &key, const std::string &msg,
							std::string &hash) {
	struct hmac_req req {};
	req.ctx = hmac_setup(alg);

	uint8_t res[req.ctx.L];

	req.key			= (uint8_t *) key.c_str();
	req.key_len		= key.length();
	req.message		= (uint8_t *) msg.c_str();
	req.message_len = msg.length();
	req.res_hmac	= res;

	hmac(req);
	get_output(res, (int) req.ctx.L, hash);
}

class HMACTests : public testing::TestWithParam<HMACTestParams> {
protected:
	virtual size_t		   get_size_digest()	   = 0;
	virtual EVP_hash	   get_evp_hash_function() = 0;
	virtual hmac_algorithm get_hmac_algorithm()	   = 0;

	void				   do_test() {
		  HMACTestParams params = GetParam();

		  const size_t	 size_digest = get_size_digest();
		  std::string	 expected;
		  std::string	 actual;

		  std::string	 key = params.key;
		  std::string	 msg = params.msg;

		  get_hmac(get_evp_hash_function(), key, msg, expected, size_digest);
		  get_hmac_actual(get_hmac_algorithm(), key, msg, actual);

		  EXPECT_EQ(expected, actual);
	}
};

class HMAC_MD5_Tests : public HMACTests {
protected:
	size_t get_size_digest() final {
		return 16;
	}

	EVP_hash get_evp_hash_function() final {
		return EVP_md5;
	}

	hmac_algorithm get_hmac_algorithm() final {
		return HMAC_MD5;
	}
};

class HMAC_SHA2_224_Tests : public HMACTests {
protected:
	size_t get_size_digest() final {
		return 28;
	}

	EVP_hash get_evp_hash_function() final {
		return EVP_sha224;
	}

	hmac_algorithm get_hmac_algorithm() final {
		return HMAC_SHA2_224;
	}
};

class HMAC_SHA2_256_Tests : public HMACTests {
protected:
	size_t get_size_digest() final {
		return 32;
	}

	EVP_hash get_evp_hash_function() final {
		return EVP_sha256;
	}

	hmac_algorithm get_hmac_algorithm() final {
		return HMAC_SHA2_256;
	}
};

class HMAC_SHA2_384_Tests : public HMACTests {
protected:
	size_t get_size_digest() final {
		return 48;
	}

	EVP_hash get_evp_hash_function() final {
		return EVP_sha384;
	}

	hmac_algorithm get_hmac_algorithm() final {
		return HMAC_SHA2_384;
	}
};

class HMAC_SHA2_512_Tests : public HMACTests {
protected:
	size_t get_size_digest() final {
		return 64;
	}

	EVP_hash get_evp_hash_function() final {
		return EVP_sha512;
	}

	hmac_algorithm get_hmac_algorithm() final {
		return HMAC_SHA2_512;
	}
};

class HMAC_SHA2_512_224_Tests : public HMACTests {
protected:
	size_t get_size_digest() final {
		return 28;
	}

	EVP_hash get_evp_hash_function() final {
		return EVP_sha512_224;
	}

	hmac_algorithm get_hmac_algorithm() final {
		return HMAC_SHA2_512_224;
	}
};
class HMAC_SHA2_512_256_Tests : public HMACTests {
protected:
	size_t get_size_digest() final {
		return 32;
	}

	EVP_hash get_evp_hash_function() final {
		return EVP_sha512_256;
	}

	hmac_algorithm get_hmac_algorithm() final {
		return HMAC_SHA2_512_256;
	}
};

const static std::vector<HMACTestParams> tests{
	HMACTestParams("", ""),
	HMACTestParams("", "a"),
	HMACTestParams("a", ""),
	HMACTestParams("a", "a"),
	HMACTestParams("key", "The quick brown fox jumps over the lazy dog"),
	HMACTestParams("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog", "message"),
};

const auto name_generator = [](const testing::TestParamInfo<HMACTests::ParamType>& info) {
	return "bonjour" + std::to_string(info.index);
};

INSTANTIATE_TEST_SUITE_P(HMAC_MD5, HMAC_MD5_Tests, testing::ValuesIn(tests), name_generator);
INSTANTIATE_TEST_SUITE_P(HMAC_SHA2_224, HMAC_SHA2_224_Tests, testing::ValuesIn(tests), name_generator);
INSTANTIATE_TEST_SUITE_P(HMAC_SHA2_256, HMAC_SHA2_256_Tests, testing::ValuesIn(tests), name_generator);
INSTANTIATE_TEST_SUITE_P(HMAC_SHA2_384, HMAC_SHA2_384_Tests, testing::ValuesIn(tests), name_generator);
INSTANTIATE_TEST_SUITE_P(HMAC_SHA2_512, HMAC_SHA2_512_Tests, testing::ValuesIn(tests), name_generator);
INSTANTIATE_TEST_SUITE_P(HMAC_SHA2_512_224, HMAC_SHA2_512_224_Tests, testing::ValuesIn(tests), name_generator);
INSTANTIATE_TEST_SUITE_P(HMAC_SHA2_512_256, HMAC_SHA2_512_256_Tests, testing::ValuesIn(tests), name_generator);

TEST_P(HMAC_MD5_Tests, tests) {
	do_test();
}

TEST_P(HMAC_SHA2_224_Tests, tests) {
	do_test();
}

TEST_P(HMAC_SHA2_256_Tests, tests) {
	do_test();
}

TEST_P(HMAC_SHA2_384_Tests, tests) {
	do_test();
}

TEST_P(HMAC_SHA2_512_Tests, tests) {
	do_test();
}

TEST_P(HMAC_SHA2_512_224_Tests, tests) {
	do_test();
}

TEST_P(HMAC_SHA2_512_256_Tests, tests) {
	do_test();
}
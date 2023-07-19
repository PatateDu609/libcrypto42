#include "common.h"
#include <array>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

struct Base64TestParams {
	std::string encoded;
	std::string decoded;

	Base64TestParams(std::string e, std::string d) : encoded(std::move(e)), decoded(std::move(d)) {}
};

std::ostream &operator<<(std::ostream &os, const Base64TestParams &params) {
	os << "encoded = " << (params.encoded.empty() ? "(empty)" : params.encoded) << ", ";
	os << "decoded = " << (params.decoded.empty() ? "(empty)" : params.decoded);

	return os;
}

class Base64Tests : public ::testing::Test, public ::testing::WithParamInterface<Base64TestParams> {};

const Base64TestParams array[] = {
	Base64TestParams("", ""),
	Base64TestParams("Zg==", "f"),
	Base64TestParams("Zm8=", "fo"),
	Base64TestParams("Zm9v", "foo"),
	Base64TestParams("Zm9vYg==", "foob"),
	Base64TestParams("Zm9vYmE=", "fooba"),
	Base64TestParams("Zm9vYmFy", "foobar"),
};

INSTANTIATE_TEST_SUITE_P(Base64, Base64Tests, testing::ValuesIn(array));

TEST_P(Base64Tests, encode) {
	Base64TestParams param = GetParam();

	char			*actual = base64_encode((uint8_t *) param.decoded.c_str(), param.decoded.length());

	std::string		 actual_str = actual;

	EXPECT_EQ(actual_str, param.encoded);

	free(actual);
}

TEST_P(Base64Tests, decode) {
	Base64TestParams	 param = GetParam();

	size_t				 actual_len;
	uint8_t				*actual = base64_decode(param.encoded.c_str(), &actual_len);

	std::vector<uint8_t> actual_vec(actual, actual + actual_len);
	std::vector<uint8_t> expected_vec(param.decoded.begin(), param.decoded.end());

	EXPECT_TRUE(actual_vec == expected_vec);

	free(actual);
}

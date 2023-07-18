#include "common.h"
#include <array>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

struct Base64TestParam {
	std::string encoded;
	std::string decoded;

	Base64TestParam(std::string e, std::string d) : encoded(std::move(e)), decoded(std::move(d)) {}
};


class Base64Tests : public ::testing::Test, public ::testing::WithParamInterface<Base64TestParam> {};

const Base64TestParam array[] = {
	Base64TestParam("", ""),
	Base64TestParam("Zg==", "f"),
	Base64TestParam("Zm8=", "fo"),
	Base64TestParam("Zm9v", "foo"),
	Base64TestParam("Zm9vYg==", "foob"),
	Base64TestParam("Zm9vYmE=", "fooba"),
	Base64TestParam("Zm9vYmFy", "foobar"),
};

INSTANTIATE_TEST_SUITE_P(Base64, Base64Tests, testing::ValuesIn(array));

TEST_P(Base64Tests, encode) {
	Base64TestParam param = GetParam();

	char		   *actual = base64_encode((uint8_t*)param.decoded.c_str(), param.decoded.length());

	std::string actual_str = actual;

	EXPECT_EQ(actual_str, param.encoded);

	free(actual);
}

TEST_P(Base64Tests, decode) {
	Base64TestParam param = GetParam();

	size_t			actual_len;
	uint8_t		   *actual = base64_decode(param.encoded.c_str(), &actual_len);

	std::vector<uint8_t> actual_vec(actual, actual + actual_len);
	std::vector<uint8_t> expected_vec(param.decoded.begin(), param.decoded.end());

	EXPECT_TRUE(actual_vec == expected_vec);

	free(actual);
}

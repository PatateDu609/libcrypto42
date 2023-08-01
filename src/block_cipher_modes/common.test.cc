#include "internal.h"
#include "random.hh"
#include "test.hh"
#include <ctime>
#include <gtest/gtest.h>

struct PaddingTestParams {
	size_t               len;
	uint8_t              blk_size;
	uint8_t              expected_padding;

	std::vector<uint8_t> data;

	PaddingTestParams(size_t length, size_t size, uint8_t expected)
		: len(length), blk_size(size), expected_padding(expected) {
		data = rng::get_random_data(len);
	}
};

std::ostream &operator<<(std::ostream &os, const PaddingTestParams &params) {
	os << "len = " << params.len;
	os << ", blk size = " << (int) params.blk_size;
	os << ", expected padding = " << (int) params.expected_padding;

	return os;
}

static const std::vector<PaddingTestParams> params{
	PaddingTestParams(5, 8, 3),   PaddingTestParams(8, 8, 8),    PaddingTestParams(12, 8, 4),
	PaddingTestParams(4, 16, 12), PaddingTestParams(16, 16, 16), PaddingTestParams(35, 16, 13),
};

class PaddingTests : public testing::TestWithParam<PaddingTestParams> {
public:
	~PaddingTests() override = default;

	void SetUp() override {}

	void TearDown() override {}
};

INSTANTIATE_TEST_SUITE_P(params, PaddingTests, testing::ValuesIn(params));

TEST_P(PaddingTests, pad) {
	const auto &param = GetParam();

	size_t      len       = param.data.size();
	auto        plaintext = static_cast<uint8_t *>(calloc(len, sizeof(uint8_t)));
	memcpy(plaintext, param.data.data(), len * sizeof *plaintext);

	uint8_t *ret = pad(plaintext, &len, param.blk_size);
	ASSERT_NE(ret, nullptr);

	EXPECT_EQ(len % static_cast<size_t>(param.blk_size), 0UL);
	EXPECT_EQ(ret[len - 1], param.expected_padding);

	free(ret);
}

TEST_P(PaddingTests, pad_unpad) {
	const auto &param = GetParam();

	size_t      len          = param.data.size();
	size_t      memcpy_n_val = len * sizeof(uint8_t);

	auto        plaintext = static_cast<uint8_t *>(calloc(len, sizeof(uint8_t)));
	memcpy(plaintext, param.data.data(), memcpy_n_val);
	auto copy_plaintext = static_cast<uint8_t *>(calloc(len, sizeof(uint8_t)));
	memcpy(copy_plaintext, param.data.data(), memcpy_n_val);

	uint8_t *ret = pad(plaintext, &len, param.blk_size);
	ASSERT_NE(ret, nullptr);

	EXPECT_EQ(len % static_cast<size_t>(param.blk_size), 0UL);
	EXPECT_EQ(ret[len - 1], param.expected_padding);

	uint8_t *ret_unpad = unpad(ret, &len);
	ASSERT_NE(ret_unpad, nullptr);

	ASSERT_EQ(len, param.len);

	std::vector<uint8_t> actual(ret_unpad, ret_unpad + len);
	std::vector<uint8_t> expected(copy_plaintext, copy_plaintext + param.len);
	EXPECT_EQ(actual, expected);

	free(ret);
}
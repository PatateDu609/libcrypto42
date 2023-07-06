#include "internal.h"
#include <criterion/criterion.h>
#include <criterion/new/assert.h>
#include <criterion/parameterized.h>
#include <time.h>

struct padding_param {
	size_t	len;
	uint8_t blk_size;
	uint8_t expected_padding;
};

#define PADDING_PARAMS 6
static struct padding_param params[PADDING_PARAMS] = {
	{
		.len			  = 5,
		.blk_size		  = 8,
		.expected_padding = 3,
	 },
	{
		.len			  = 8,
		.blk_size		  = 8,
		.expected_padding = 8,
	 },
	{
		.len			  = 12,
		.blk_size		  = 8,
		.expected_padding = 4,
	 },
	{
		.len			  = 4,
		.blk_size		  = 16,
		.expected_padding = 12,
	 },
	{
		.len			  = 16,
		.blk_size		  = 16,
		.expected_padding = 16,
	 },
	{
		.len			  = 35,
		.blk_size		  = 16,
		.expected_padding = 13,
	 }
};

static void setup_padding_suite(void) {
	srand(((uint32_t) time(NULL) ^ getpid()) >> (getpid() % 32));
}

TestSuite(padding, .init = setup_padding_suite);

static uint8_t *gen_i8_arr(size_t len) {
	uint8_t *arr = calloc(len, sizeof *arr);

	for (size_t i = 0; i < len; i++) {
		arr[i] = rand() % 256;// NOLINT(cert-msc50-cpp)
	}

	return arr;
}

ParameterizedTestParameters(padding, pad) {
	return cr_make_param_array(struct padding_param, params, PADDING_PARAMS);
}

ParameterizedTest(struct padding_param *param, padding, pad) {
	size_t	 len = param->len;

	uint8_t *plaintext = gen_i8_arr(len);
	uint8_t *ret	   = pad(plaintext, &len, param->blk_size);
	cr_assert(ne(ptr, ret, NULL));

	cr_expect(eq(i32, len % param->blk_size, 0));
	cr_expect(eq(i32, ret[len - 1], param->expected_padding));

	free(ret);
}

ParameterizedTestParameters(padding, unpad) {
	return cr_make_param_array(struct padding_param, params, PADDING_PARAMS);
}

ParameterizedTest(struct padding_param *param, padding, unpad) {
	size_t	 len = param->len;

	uint8_t *plaintext = gen_i8_arr(len), *copy_plaintext = calloc(len, sizeof *copy_plaintext);
	memcpy(copy_plaintext, plaintext, len * sizeof *copy_plaintext);

	uint8_t *ret = pad(plaintext, &len, param->blk_size);
	cr_assert(ne(ptr, ret, NULL));

	cr_assert(eq(i32, len % param->blk_size, 0));
	cr_assert(eq(i32, ret[len - 1], param->expected_padding));

	uint8_t *ret_unpad = unpad(ret, &len);
	cr_assert(ne(ptr, ret_unpad, NULL));

	cr_assert(eq(sz, len, param->len));
	cr_expect(eq(u8[param->len], ret_unpad, copy_plaintext));

	free(ret);
}
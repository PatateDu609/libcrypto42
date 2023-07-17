#include "test.h"
#include <criterion/criterion.h>
#include <criterion/parameterized.h>
#include <string.h>

void dupe_str_array(const char **arr, size_t len, char **target) {
	for (size_t i = 0; i < len; i++) {
		target[i] = cr_calloc(strlen(arr[i]), sizeof(char));
		strcpy(target[i], arr[i]);
	}
}

void free_str_array(struct criterion_test_params *ctp) {
	char **arr = (char **) ctp->params;

	for (size_t i = 0; i < ctp->length; i++)
		cr_free(arr[i]);
}

uint8_t *gen_u8_arr(size_t len, bool param_mode) {
	uint8_t *arr = (param_mode ? cr_calloc : calloc)(len, sizeof *arr);

	for (size_t i = 0; i < len; i++) {
		arr[i] = rand() % UINT8_MAX;// NOLINT(cert-msc50-cpp)
	}

	return arr;
}

uint32_t *gen_u32_arr(size_t len, bool param_mode) {
	uint32_t *arr = (param_mode ? cr_calloc : calloc)(len, sizeof *arr);

	for (size_t i = 0; i < len; i++) {
		arr[i] = rand() % UINT32_MAX;// NOLINT(cert-msc50-cpp)
	}

	return arr;
}

void *memdup(const void *src, size_t size, bool param_mode) {
	void *dst = (param_mode ? cr_calloc : calloc)(size, 1);

	memcpy(dst, src, size);
	return dst;
}
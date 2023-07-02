#include "test.h"
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
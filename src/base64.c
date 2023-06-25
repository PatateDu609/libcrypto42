/**
 * @file base64.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Implementation of base64 conversion.
 * @date 2022-08-14
 *
 * @note This implementation uses the one described in the RFC4648 section 4.
 * @see https://datatracker.ietf.org/doc/html/rfc4648#section-4
 */

#include "common.h"
#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define BASE64_CHAR_SET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

char *base64_encode(const uint8_t *bytes, size_t len) {
	char  *set  = BASE64_CHAR_SET;
	size_t flen = (size_t)ceil((double)len / 3.) * 4;
	char  *res  = malloc((flen + 1) * sizeof *res);

	size_t j    = 0;
	for (size_t i = 0; i < len; i += 3) {
		uint8_t index = (bytes[i] & 0b11111100) >> 2;
		res[j++]      = set[index];

		if (i + 1 == len) {
			res[j++] = set[(bytes[i] & 0b00000011) << 4];
			break;
		}
		index    = ((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4);
		res[j++] = set[index];

		if (i + 2 == len) {
			res[j++] = set[(bytes[i + 1] & 0b00001111) << 2];
			break;
		}
		index    = ((bytes[i + 1] & 0b00001111) << 2) | ((bytes[i + 2] & 0b11000000) >> 6);
		res[j++] = set[index];

		index    = bytes[i + 2] & 0b00111111;
		res[j++] = set[index];
	}
	for (; j < flen; j++) res[j] = '=';
	res[flen] = '\0';
	return res;
}

uint8_t *base64_decode(const char *str, size_t *flen) {
	char  *set     = BASE64_CHAR_SET;
	size_t len     = strlen(str);
	size_t padding = 0;

	// Count padding and check if the string is valid in the same time.
	for (size_t i = 0; i < len; i++) {
		if (str[i] == '=')
			padding++;
		else if (strchr(set, str[i]) == NULL || padding)// Invalid character or padding in the middle.
			return NULL;
	}
	if (padding > 2)// Invalid padding.
		return NULL;
	*flen        = (len / 4) * 3 - padding;

	// It is a raw array not a string. \0 can be part of the array and should not be used as a terminator
	uint8_t *res = malloc(*flen * sizeof *res);
	size_t   j   = 0;
	for (size_t i = 0; i < len - padding; i += 4) {
		uint8_t indices[4] = { strchr(set, str[i]) - set, strchr(set, str[i + 1]) - set, strchr(set, str[i + 2]) - set,
			                   strchr(set, str[i + 3]) - set };
		res[j++]           = (indices[0] << 2) | (indices[1] >> 4);
		if (i + 2 == len - padding)
			break;
		res[j++] = ((indices[1] & 0b00001111) << 4) | (indices[2] >> 2);
		if (i + 3 == len - padding)
			break;
		res[j++] = ((indices[2] & 0b00000011) << 6) | indices[3];
	}
	return res;
}

char *base64_encode_file(const char *filename) {
	FILE *file = filename ? fopen(filename, "r+") : stdin;
	if (file == NULL)
		return NULL;
	uint8_t buffer[528];// It is a common multiple of 3 and 4, so we do not have padding.

	size_t  flen = 0;
	size_t  ret;
	size_t  pos = 0;
	char   *res = NULL;
	while ((ret = fread(buffer, 1, sizeof buffer, file)) > 0) {
		char  *tmp     = base64_encode(buffer, ret);
		size_t tmp_len = strlen(tmp);
		flen += tmp_len;

		void *temp = realloc(res, (flen + 1) * sizeof *res);
		if (!temp)
			return NULL;
		res = temp;

		memcpy(res + pos, tmp, tmp_len);
		pos += tmp_len;
		free(tmp);
	}
	if (filename)
		fclose(file);
	res[flen] = '\0';
	return res;
}

uint8_t *base64_decode_file(const char *filename, size_t *flen) {
	FILE *file = filename ? fopen(filename, "r+") : stdin;
	if (file == NULL)
		return NULL;
	char line[128];// A line is exactly 64 characters long, but as a security measure we read 128.

	*flen        = 0;
	uint8_t *res = NULL;
	size_t   pos = 0;
	while (fgets(line, sizeof line, file)) {
		size_t len;
		line[strcspn(line, "\r\n")] = '\0';// Remove newline.
		uint8_t *tmp                = base64_decode(line, &len);
		if (tmp == NULL)
			return NULL;

		*flen += len;
		void *temp = realloc(res, (*flen + 1) * sizeof *res);
		if (!temp)
			return NULL;
		res = temp;

		memcpy(res + pos, tmp, len);
		pos += len;
	}
	if (filename)
		fclose(file);
	return res;
}
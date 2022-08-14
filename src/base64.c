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

char *base64_encode(const uint8_t *bytes, size_t len)
{
	char *set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t flen = ceil(len / 3.) * 4;
	char *res = malloc((flen + 1) * sizeof *res);

	size_t j = 0;
	for (size_t i = 0; i < len; i += 3)
	{
		uint8_t index = (bytes[i] & 0b11111100) >> 2;
		res[j++] = set[index];

		if (i + 1 == len)
		{
			res[j++] = set[(bytes[i] & 0b00000011) << 4];
			break;
		}
		index = ((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4);
		res[j++] = set[index];

		if (i + 2 == len)
		{
			res[j++] = set[(bytes[i + 1] & 0b00001111) << 2];
			break;
		}
		index = ((bytes[i + 1] & 0b00001111) << 2) | ((bytes[i + 2] & 0b11000000) >> 6);
		res[j++] = set[index];

		index = bytes[i + 2] & 0b00111111;
		res[j++] = set[index];
	}
	for (; j < flen; j++)
		res[j] = '=';
	res[flen] = '\0';
	return res;
}

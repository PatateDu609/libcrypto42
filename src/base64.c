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
#include <stdio.h>

char *base64_encode(uint8_t *bytes, size_t len)
{
	char *set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int remaining = (len % 3);
	int flen = (len / 3) * 4 + remaining;
	char *res = malloc((flen + 1) * sizeof *res);

	for (size_t i = 0, j = 0; i < len; i += 3, j += 4)
	{
		uint8_t index = (bytes[i] & 0b11111100) >> 2;
		res[j] = set[index];

		if (i + 1 == len)
		{
			res[j + 1] = '=';
			res[j + 2] = '=';
			break;
		}
		index = ((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4);
		res[j + 1] = set[index];

		if (i + 2 == len)
		{
			res[j + 1] = '=';
			break;
		}
		index = ((bytes[i + 1] & 0b00001111) << 2) | ((bytes[i + 2] & 0b11000000) >> 6);
		res[j + 2] = set[index];

		index = bytes[i + 2] & 0b00111111;
		res[j + 3] = set[index];
	}
	// while (remaining)
	// {
	// 	res[flen - remaining--] = '=';
	// }
	res[flen] = '\0';
	return res;
}

#include <string.h>
int main()
{
	char *in = "light work.";
	char *out = base64_encode((uint8_t *)in, strlen(in));

	printf("out = %s\n", out);
}

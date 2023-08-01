/**
 * @file pbkdf.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Implementation of PBKDF2 based on the RFC 2898.
 * @date 2022-08-13
 *
 * @see https://tools.ietf.org/html/rfc2898
 */

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include "pbkdf.h"
#include "common.h"

uint8_t *pbkdf2(struct pbkdf2_hmac_req req)
{
	struct hmac_req hmac_req;

	hmac_req.ctx = hmac_setup(req.algo);

	if (hmac_req.ctx.H == NULL || hmac_req.ctx.b == 0 || hmac_req.ctx.L == 0)
		return NULL;
	if (req.dklen > (uint64_t)(UINT32_MAX) * hmac_req.ctx.L)
	{
		fprintf(stderr, "Error: pbkdf2: dklen too large\n");
		return NULL;
	}
	hmac_req.key = req.password;
	hmac_req.key_len = req.password_len;

	uint8_t *dk = calloc(req.dklen, sizeof *dk);
	if (dk == NULL)
		return NULL;

	size_t l = (size_t)ceilf((float)req.dklen / (float)hmac_req.ctx.L);
	size_t r = req.dklen - (l - 1) * hmac_req.ctx.L;

	// Compute the current block of the derived key.
	for (size_t i = 1; i <= l; i++)
	{
		uint8_t t[hmac_req.ctx.L];
		memset(t, 0, hmac_req.ctx.L);

		uint32_t tmp_i = bswap_32(i);

		size_t len = (req.salt_len + 4 > hmac_req.ctx.L) ? req.salt_len + 4 : hmac_req.ctx.L;

		uint8_t u[len];
		memcpy(u, req.salt, req.salt_len);
		memcpy(u + req.salt_len, &tmp_i, 4);

		for (size_t j = 1; j <= req.iterations; j++)
		{
			uint8_t tmp_u[hmac_req.ctx.L];
			hmac_req.message = u;
			hmac_req.message_len = (j == 1) ? req.salt_len + 4 : hmac_req.ctx.L;
			hmac_req.res_hmac = tmp_u;
			hmac(hmac_req);

			for (size_t k = 0; k < hmac_req.ctx.L; k++)
				u[k] = tmp_u[k];
			for (size_t k = 0; k < hmac_req.ctx.L; k++)
				t[k] ^= u[k];
		}

		// Copy t to dk
		if (i == l)
			memcpy(dk + (i - 1) * hmac_req.ctx.L, t, r);
		else
			memcpy(dk + (i - 1) * hmac_req.ctx.L, t, hmac_req.ctx.L);
	}
	return dk;
}

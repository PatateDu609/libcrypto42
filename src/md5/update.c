/**
 * @file update.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Updates the md5 context with the given data.
 * @date 2022-08-08
 *
 * @see https://tools.ietf.org/html/rfc1321
 */

#include "internal.h"

#define ROUND1(a, b, c, d, f, g, i)                                                                                    \
	{                                                                                                                  \
		f = F(b, c, d);                                                                                                \
		g = i;                                                                                                         \
	}

#define ROUND2(a, b, c, d, f, g, i)                                                                                    \
	{                                                                                                                  \
		f = G(b, c, d);                                                                                                \
		g = (5 * i + 1) % 16;                                                                                          \
	}

#define ROUND3(a, b, c, d, f, g, i)                                                                                    \
	{                                                                                                                  \
		f = H(b, c, d);                                                                                                \
		g = (3 * i + 5) % 16;                                                                                          \
	}

#define ROUND4(a, b, c, d, f, g, i)                                                                                    \
	{                                                                                                                  \
		f = I(b, c, d);                                                                                                \
		g = (7 * i) % 16;                                                                                              \
	}

void md5_update(struct md5_ctx *ctx, const uint8_t *input) {
	uint32_t *data = (uint32_t *) input;
	uint32_t  a, b, c, d;

	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;

	for (int i = 0; i < 64; i++) {
		uint32_t f, g;

		if (0 <= i && i < 16)
			ROUND1(a, b, c, d, f, g, i)
		else if (16 <= i && i < 32)
			ROUND2(a, b, c, d, f, g, i)
		else if (32 <= i && i < 48)
			ROUND3(a, b, c, d, f, g, i)
		else
			ROUND4(a, b, c, d, f, g, i)

		f += a + ctx->buf[i] + data[g];
		a = d;
		d = c;
		c = b;
		b += ROTL(f, ctx->shift[i]);
	}

	ctx->a += a;
	ctx->b += b;
	ctx->c += c;
	ctx->d += d;
}
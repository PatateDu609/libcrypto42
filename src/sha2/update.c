/**
 * @file update.c
 * @author Ghali Boucetta (gboucett@student.42,fr)
 * @brief SHA-2 update implementation.
 * @date 2022-08-11
 */

#include "internal.h"
#include "common.h"

#define a0 ctx->state[0]
#define b0 ctx->state[1]
#define c0 ctx->state[2]
#define d0 ctx->state[3]
#define e0 ctx->state[4]
#define f0 ctx->state[5]
#define g0 ctx->state[6]
#define h0 ctx->state[7]

#define SSIG0(x) SSIG0_32(x)
#define SSIG1(x) SSIG1_32(x)
#define BSIG0(x) BSIG0_32(x)
#define BSIG1(x) BSIG1_32(x)

static void sha2_32_update(struct sha2_ctx_32 *ctx, uint32_t *blk)
{
	uint32_t a = a0, b = b0, c = c0, d = d0, e = e0, f = f0, g = g0, h = h0;

	uint32_t w[64];
	uint32_t t1, t2;

	for (size_t i = 0; i < 16; i++)
		w[i] = bswap_32(blk[i]);
	for (size_t i = 16; i < ctx->data.nb_rounds; i++)
		w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

	for (size_t i = 0; i < ctx->data.nb_rounds; i++)
	{
		t1 = h + BSIG1(e) + Ch(e, f, g) + ctx->cnsts[i] + w[i];
		t2 = BSIG0(a) + Ma(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	a0 += a;
	b0 += b;
	c0 += c;
	d0 += d;
	e0 += e;
	f0 += f;
	g0 += g;
	h0 += h;
}

#undef SSIG0
#undef SSIG1
#undef BSIG0
#undef BSIG1

#define SSIG0(x) SSIG0_64(x)
#define SSIG1(x) SSIG1_64(x)
#define BSIG0(x) BSIG0_64(x)
#define BSIG1(x) BSIG1_64(x)

static void sha2_64_update(struct sha2_ctx_64 *ctx, uint64_t *blk)
{
	uint64_t a = a0, b = b0, c = c0, d = d0, e = e0, f = f0, g = g0, h = h0;

	uint64_t w[80];
	uint64_t t1, t2;

	for (size_t i = 0; i < 16; i++)
		w[i] = bswap_64(blk[i]);
	for (size_t i = 16; i < ctx->data.nb_rounds; i++)
		w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

	for (size_t i = 0; i < ctx->data.nb_rounds; i++)
	{
		t1 = h + BSIG1(e) + Ch(e, f, g) + ctx->cnsts[i] + w[i];
		t2 = BSIG0(a) + Ma(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	a0 += a;
	b0 += b;
	c0 += c;
	d0 += d;
	e0 += e;
	f0 += f;
	g0 += g;
	h0 += h;
}

#undef SSIG0
#undef SSIG1
#undef BSIG0
#undef BSIG1

#undef a0
#undef b0
#undef c0
#undef d0
#undef e0
#undef f0
#undef g0
#undef h0

void sha2_update(struct sha2 *ctx, void *data)
{
	if (ctx->alg.alg == SHA2_ALG_256 || ctx->alg.alg == SHA2_ALG_224)
		sha2_32_update(ctx->ctx_32, (uint32_t *)data);
	else
		sha2_64_update(ctx->ctx_64, (uint64_t *)data);
}

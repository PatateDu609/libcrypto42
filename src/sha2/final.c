/**
 * @file final.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Get the final sha2 hash string
 * @date 2022-08-11
 */

#include "internal.h"
#include "libft.h"
#include "common.h"
#include <stdio.h>
#include <limits.h>

#define STRINGIFY(target, ctx, digest_size) \
	for (size_t i = 0; i < 8; i++) \
		ctx->state[i] = BSWAP32(ctx->state[i]); \
	for (size_t i = 0; i < (digest_size); i++) \
		snprintf(target + i * 2, 3, "%02x", ctx->hash[i]);

char *sha2_final(struct sha2 *ctx)
{
	char *str = malloc((ctx->alg.digest_size * 2 + 1) * sizeof *str);
	if (str == NULL)
		return NULL;

	if (ctx->alg.alg == SHA2_ALG_224 || ctx->alg.alg == SHA2_ALG_256)
	{
		STRINGIFY(str, ctx->ctx_32, ctx->alg.digest_size)
	}
	else
	{
		STRINGIFY(str, ctx->ctx_64, ctx->alg.digest_size)
	}

	return str;
}

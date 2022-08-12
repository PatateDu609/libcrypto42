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

#define STRINGIFY(target, ctx, digest_size, bswap) \
	for (size_t i = 0; i < 8; i++) \
		ctx->state[i] = bswap(ctx->state[i]); \
	for (size_t i = 0; i < (digest_size); i++) \
		snprintf(target + i * 2, 3, "%02x", ctx->hash[i]);

char *sha2_final(struct sha2 *ctx)
{
	char *str = malloc((ctx->alg.digest_size * 2 + 1) * sizeof *str);
	if (str == NULL)
		return NULL;

	if (ctx->alg.alg == SHA2_ALG_224 || ctx->alg.alg == SHA2_ALG_256)
	{
		STRINGIFY(str, ctx->ctx_32, ctx->alg.digest_size, bswap_32)

		ft_memset(ctx->ctx_32, 0, sizeof *ctx->ctx_32);
		free(ctx->ctx_32);
	}
	else
	{
		STRINGIFY(str, ctx->ctx_64, ctx->alg.digest_size, bswap_64)

		ft_memset(ctx->ctx_64, 0, sizeof *ctx->ctx_64);
		free(ctx->ctx_64);
	}

	ft_memset(ctx, 0, sizeof *ctx);

	return str;
}

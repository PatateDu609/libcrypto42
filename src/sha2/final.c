/**
 * @file final.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Get the final sha2 hash string
 * @date 2022-08-11
 */

#include "common.h"
#include "internal.h"
#include "libft.h"
#include <limits.h>
#include <stdio.h>

char *sha2_final(struct sha2 *ctx) {
	uint8_t digest[ctx->alg.digest_size];
	sha2_final_raw(ctx, digest);
	char *str = stringify_hash(digest, ctx->alg.digest_size);

	free(ctx->ctx_32);// It is an union so we can free either one but not both
	ft_memset(ctx, 0, sizeof *ctx);

	return str;
}

uint8_t *sha2_final_raw(struct sha2 *ctx, uint8_t *buf) {
	if (ctx->alg.alg == SHA2_ALG_224 || ctx->alg.alg == SHA2_ALG_256) {
		for (size_t i = 0; i < 8; i++) ctx->ctx_32->state[i] = bswap_32(ctx->ctx_32->state[i]);
		ft_memcpy(buf, ctx->ctx_32->state, ctx->alg.digest_size);
		ft_memset(ctx->ctx_32, 0, sizeof *ctx->ctx_32);
	} else {
		for (size_t i = 0; i < 8; i++) ctx->ctx_64->state[i] = bswap_64(ctx->ctx_64->state[i]);
		ft_memcpy(buf, ctx->ctx_64->state, ctx->alg.digest_size);

		ft_memset(ctx->ctx_64, 0, sizeof *ctx->ctx_64);
	}
	return buf;
}

/**
 * @file final.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Final function of the md5 workflow.
 * @date 2022-08-09
 */

#include "internal.h"
#include "libft.h"
#include <stdio.h>

char *md5_final(struct md5_ctx *ctx) {
	uint8_t buf[MD5_DIGEST_SIZE];

	md5_final_raw(ctx, buf);
	char *str = stringify_hash(buf, MD5_DIGEST_SIZE);

	// Setting the context to 0 to avoid exposing the internal state of the context.
	ft_memset(ctx, 0, sizeof *ctx);
	return str;
}

uint8_t *md5_final_raw(struct md5_ctx *ctx, uint8_t *output) {
	uint32_t *output_32 = (uint32_t *) output;
	output_32[0]        = ctx->a;
	output_32[1]        = ctx->b;
	output_32[2]        = ctx->c;
	output_32[3]        = ctx->d;

	return output;
}

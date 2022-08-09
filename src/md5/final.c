/**
 * @file final.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Final function of the md5 workflow.
 * @date 2022-08-09
 */

#include "libft.h"
#include "internal.h"
#include <stdio.h>

static void append_int(char *str, uint32_t tp)
{
	tp = BSWAP32(tp);
	snprintf(str, 9, "%08x", tp);
}

char *md5_final(struct md5_ctx *ctx)
{
	char *str = malloc(MD5_HASH_SIZE * sizeof *str);
	if (str == NULL)
		return NULL;

	append_int(str, ctx->a);
	append_int(str + 8, ctx->b);
	append_int(str + 16, ctx->c);
	append_int(str + 24, ctx->d);

	// Setting the context to 0 to avoid exposing the internal state of the context.
	ft_memset(ctx, 0, sizeof *ctx);
	return str;
}
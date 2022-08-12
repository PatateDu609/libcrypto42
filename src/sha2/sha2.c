/**
 * @file sha2.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief SHA-2 implementation
 * @date 2022-08-10
 */

#include "internal.h"
#include "crypto.h"
#include "common.h"
#include "libft.h"

#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>

static bool __intermediate_sha2_bytes(const struct msg *msg, struct sha2 *ctx)
{
	struct blk *blks = get_blocks(msg, ctx->alg.block_size, ctx->alg.wanted_size, true);
	if (blks == NULL)
		return false;

	size_t nb = blks->len / ctx->alg.block_size;
	for (size_t i = 0; i < nb; i++)
		sha2_update(ctx, blks->data + i * ctx->alg.block_size);

	free(blks->data);
	free(blks);
	return true;
}

char *sha2_bytes(enum SHA2_ALG alg, const uint8_t *bytes, size_t len)
{
	struct sha2 ctx;
	struct msg msg = { .data = bytes, .len = len, .is_last_part = true, .filesize = len };

	sha2_init(&ctx, alg);
	if (!__intermediate_sha2_bytes(&msg, &ctx))
	{
		ft_memset(&ctx, 0, sizeof(ctx));
		return NULL;
	}
	return sha2_final(&ctx);
}

char *sha2(enum SHA2_ALG alg, const char *input)
{
	uint8_t *bytes = (uint8_t *)input;
	size_t len = ft_strlen(input);

	return sha2_bytes(alg, bytes, len);
}

char *sha2_descriptor(enum SHA2_ALG alg, int fd)
{
	struct sha2 ctx;
	sha2_init(&ctx, alg);

	uint8_t buffer[4096];
	struct msg msg;

	msg.is_last_part = false;
	bool done_last = false;

	ssize_t ret;
	__uint128_t filesize = 0;
	for (ret = 0; (ret = read(fd, buffer, sizeof buffer)) > 0;)
	{
		msg.data = buffer;
		msg.len = ret;
		filesize += ret;

		if (ret < (ssize_t)sizeof buffer)
		{
			msg.filesize = filesize;
			msg.is_last_part = true;
			done_last = true;
		}

		if (!__intermediate_sha2_bytes(&msg, &ctx))
		{
			ft_memset(&ctx, 0, sizeof(ctx));
			return NULL;
		}
	}
	if (!done_last)
	{
		msg.filesize = filesize;
		msg.is_last_part = true;

		msg.data = (uint8_t *)"";
		msg.len = 0;
		if (!__intermediate_sha2_bytes(&msg, &ctx))
		{
			ft_memset(&ctx, 0, sizeof(ctx));
			return NULL;
		}
	}
	return sha2_final(&ctx);
}

char *sha2_file(enum SHA2_ALG alg, const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd == -1)
		return NULL;
	char *hash = sha2_descriptor(alg, fd);
	close(fd);
	return hash;
}

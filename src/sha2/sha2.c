/**
 * @file sha2.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief SHA-2 implementation
 * @date 2022-08-10
 */

#include "common.h"
#include "crypto.h"
#include "internal.h"
#include "libft.h"

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static size_t get_size(enum SHA2_ALG alg) {
	switch (alg) {
	case SHA2_ALG_224:
		return SHA2_224_DIGEST_SIZE;
	case SHA2_ALG_256:
		return SHA2_256_DIGEST_SIZE;
	case SHA2_ALG_384:
		return SHA2_384_DIGEST_SIZE;
	case SHA2_ALG_512:
		return SHA2_512_DIGEST_SIZE;
	case SHA2_ALG_512_224:
		return SHA2_512_224_DIGEST_SIZE;
	case SHA2_ALG_512_256:
		return SHA2_512_256_DIGEST_SIZE;
	default:
		return 0;
	}
}

static bool __intermediate_sha2_bytes(const struct msg *msg, struct sha2 *ctx) {
	struct blk *blks = get_blocks(msg, ctx->alg.block_size, ctx->alg.wanted_size, false);
	if (blks == NULL)
		return false;

	size_t nb = blks->len / ctx->alg.block_size;
	for (size_t i = 0; i < nb; i++)
		sha2_update(ctx, blks->data + i * ctx->alg.block_size);

	free(blks->data);
	free(blks);
	return true;
}

uint8_t *sha2_bytes_raw(enum SHA2_ALG alg, const uint8_t *bytes, size_t len, uint8_t *buf) {
	struct sha2 ctx;
	struct msg  msg = { .data = bytes, .len = len, .is_last_part = true, .filesize = len };

	sha2_init(&ctx, alg);
	if (!__intermediate_sha2_bytes(&msg, &ctx)) {
		ft_memset(&ctx, 0, sizeof(ctx));
		return NULL;
	}
	uint8_t *raw = sha2_final_raw(&ctx, buf);
	sha2_free(&ctx, alg);
	return raw;
}

char *sha2_bytes(enum SHA2_ALG alg, const uint8_t *bytes, size_t len) {
	size_t size = get_size(alg);
	if (size == 0)
		return NULL;

	uint8_t  buf[size];
	uint8_t *res = sha2_bytes_raw(alg, bytes, len, buf);
	if (res == NULL)
		return NULL;
	return stringify_hash(buf, sizeof buf);
}

uint8_t *sha2_raw(enum SHA2_ALG alg, const char *str, uint8_t *buf) {
	return sha2_bytes_raw(alg, (uint8_t *) str, strlen(str), buf);
}

char *sha2(enum SHA2_ALG alg, const char *input) {
	uint8_t *bytes = (uint8_t *) input;
	size_t   len   = strlen(input);

	return sha2_bytes(alg, bytes, len);
}

uint8_t *sha2_descriptor_raw(enum SHA2_ALG alg, int fd, uint8_t *buf) {
	struct sha2 ctx;
	sha2_init(&ctx, alg);

	uint8_t    buffer[4096];
	struct msg msg;

	msg.is_last_part      = false;
	bool        done_last = false;

	ssize_t     ret;
	__uint128_t filesize = 0;
	for (ret = 0; (ret = read(fd, buffer, sizeof buffer)) > 0;) {
		msg.data  = buffer;
		msg.len   = ret;
		filesize += ret;

		if (ret < (ssize_t) sizeof buffer) {
			msg.filesize     = filesize;
			msg.is_last_part = true;
			done_last        = true;
		}

		if (!__intermediate_sha2_bytes(&msg, &ctx)) {
			ft_memset(&ctx, 0, sizeof(ctx));
			return NULL;
		}
	}
	if (!done_last) {
		msg.filesize     = filesize;
		msg.is_last_part = true;

		msg.data = (uint8_t *) "";
		msg.len  = 0;
		if (!__intermediate_sha2_bytes(&msg, &ctx)) {
			ft_memset(&ctx, 0, sizeof(ctx));
			return NULL;
		}
	}

	uint8_t *raw = sha2_final_raw(&ctx, buf);
	sha2_free(&ctx, alg);
	return raw;
}

char *sha2_descriptor(enum SHA2_ALG alg, int fd) {
	size_t size = get_size(alg);
	if (size == 0)
		return NULL;

	uint8_t  buf[size];
	uint8_t *res = sha2_descriptor_raw(alg, fd, buf);
	if (res == NULL)
		return NULL;
	return stringify_hash(buf, sizeof buf);
}

uint8_t *sha2_file_raw(enum SHA2_ALG alg, const char *filename, uint8_t *buf) {
	int fd = open(filename, O_RDONLY);
	if (fd == -1)
		return NULL;
	uint8_t *res = sha2_descriptor_raw(alg, fd, buf);
	close(fd);
	return res;
}

char *sha2_file(enum SHA2_ALG alg, const char *path) {
	int fd = open(path, O_RDONLY);

	if (fd == -1)
		return NULL;
	char *hash = sha2_descriptor(alg, fd);
	close(fd);
	return hash;
}

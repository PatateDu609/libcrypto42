#define _GNU_SOURCE

#include "crypto.h"
#include "internal.h"
#include "libft.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

static bool __intermediate_md5_bytes(const struct msg *msg, struct md5_ctx *ctx) {
	struct blk *blks = get_blocks(msg, MD5_BLK_LEN, MD5_SIZE_LAST, true);
	if (blks == NULL)
		return false;

	size_t nb = blks->len / (MD5_BLK_LEN);
	for (size_t i = 0; i < nb; i++) md5_update(ctx, blks->data + (i * MD5_BLK_LEN));

	free(blks->data);
	free(blks);
	return true;
}

uint8_t *md5_bytes_raw(const uint8_t *bytes, size_t len, uint8_t *output) {
	struct md5_ctx ctx;
	struct msg     msg = { .data = bytes, .len = len, .is_last_part = true, .filesize = len };

	md5_init(&ctx);

	if (!__intermediate_md5_bytes(&msg, &ctx)) {
		ft_memset(&ctx, 0, sizeof ctx);
		return NULL;
	}

	return md5_final_raw(&ctx, output);
}

char *md5_bytes(const uint8_t *bytes, size_t len) {
	uint8_t buf[MD5_DIGEST_SIZE];
	md5_bytes_raw(bytes, len, buf);
	return stringify_hash(buf, MD5_DIGEST_SIZE);
}

uint8_t *md5_raw(const char *str, uint8_t *output) {
	return md5_bytes_raw((uint8_t *) str, strlen(str), output);
}

char *md5(const char *str) {
	uint8_t *bytes = (uint8_t *) str;
	size_t   len   = strlen(str);

	return md5_bytes(bytes, len);
}

uint8_t *md5_descriptor_raw(int fd, uint8_t *output) {
	struct md5_ctx ctx;

	md5_init(&ctx);

	uint8_t    buffer[4096];
	struct msg msg;

	msg.is_last_part      = false;

	bool        done_last = false;
	ssize_t     ret;
	__uint128_t filesize = 0;
	for (ret = 0; (ret = read(fd, buffer, sizeof buffer)) > 0;) {
		msg.data = buffer;
		msg.len  = ret;
		filesize += ret;

		if (ret < (ssize_t) sizeof buffer) {
			msg.filesize     = filesize;
			msg.is_last_part = true;
			done_last        = true;
		}

		if (!__intermediate_md5_bytes(&msg, &ctx)) {
			ft_memset(&ctx, 0, sizeof(ctx));
			return NULL;
		}
	}
	if (!done_last) {
		msg.filesize     = filesize;
		msg.is_last_part = true;

		msg.data         = (unsigned char *) "";
		msg.len          = 0;
		if (!__intermediate_md5_bytes(&msg, &ctx)) {
			ft_memset(&ctx, 0, sizeof(ctx));
			return NULL;
		}
	}
	return md5_final_raw(&ctx, output);
}

char *md5_descriptor(int fd) {
	uint8_t buf[MD5_DIGEST_SIZE];
	md5_descriptor_raw(fd, buf);
	return stringify_hash(buf, MD5_DIGEST_SIZE);
}

uint8_t *md5_file_raw(const char *filename, uint8_t *output) {
	int fd = open(filename, O_RDONLY);
	if (fd == -1)
		return NULL;
	uint8_t *out = md5_descriptor_raw(fd, output);
	close(fd);
	return out;
}

char *md5_file(const char *filename) {
	int fd = open(filename, O_RDONLY);
	if (fd == -1)
		return NULL;
	char *ret = md5_descriptor(fd);
	close(fd);
	return ret;
}

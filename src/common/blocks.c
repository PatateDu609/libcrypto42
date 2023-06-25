/**
 * @file blocks.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Functions to split data into blocks.
 * @date 2022-08-09
 */

#include "common.h"
#include "libft.h"
#include <stdio.h>

static void append_size(struct blk *blks, __uint128_t len, size_t wanted_size, bool le) {
#if __BYTE_ORDER == __LITTLE_ENDIAN

	if (le) {
		if (wanted_size == 8)
			*((uint64_t *) (blks->data + blks->len - 8)) = (uint64_t) len;
		else
			*((__uint128_t *) (blks->data + blks->len - 16)) = len;
	} else {
		if (wanted_size == 8) {
			uint64_t tmp = bswap_64((uint64_t) len);
			ft_memcpy(blks->data + blks->len - 8, &tmp, 8);
		} else {
			__uint128_t tmp = bswap_128(len);
			ft_memcpy(blks->data + blks->len - 16, &tmp, 16);
		}
	}

#elif __BYTE_ORDER == __BIG_ENDIAN

	if (le) {
		if (wanted_size == 8) {
			uint64_t tmp = bswap_64((uint64_t) len);
			ft_memcpy(blks->data + blks->len - 8, &tmp, 8);
		} else {
			__uint128_t tmp = bswap_128(len);
			ft_memcpy(blks->data + blks->len - 16, &tmp, 16);
		}
	} else {
		if (wanted_size == 8)
			*((uint64_t *) (blks->data + blks->len - 8)) = (uint64_t) len;
		else
			*((__uint128_t *) (blks->data + blks->len - 16)) = len;
	}

#endif
}

struct blk *get_blocks(const struct msg *data, size_t blk_len, size_t wanted_size, bool le) {
	struct blk *blocks = malloc(sizeof *blocks);

	if (blocks == NULL)
		return NULL;

	blocks->len = data->len / blk_len;
	if (data->is_last_part || data->len == 0)
		blocks->len++;
	if (data->len % blk_len >= (blk_len - wanted_size))
		blocks->len++;

	blocks->len *= blk_len;
	blocks->data = malloc(blocks->len * sizeof *blocks->data);
	if (blocks->data == NULL) {
		free(blocks);
		return NULL;
	}

	for (size_t i = 0; i < blocks->len; i++) {
		blocks->data[i] = (i < data->len) ? data->data[i] : 0;

		if (i == data->len && data->is_last_part)
			blocks->data[i] = 0x80;// 0b10000000 (first bit after the last byte of data is always set to 1)
	}

	if (data->is_last_part)
		append_size(blocks, data->filesize << 3, wanted_size, le);

	return blocks;
}

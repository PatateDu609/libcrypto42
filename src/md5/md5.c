#include "crypto.h"
#include "internal.h"

char *md5(char *str)
{
	struct md5_ctx ctx;
	struct msg *msg = str_to_msg(str);
	if (!msg)
		return NULL;

	md5_init(&ctx);

	struct blk *blks = get_blocks(msg, MD5_BLK_LEN, 8, true);
	if (!blks)
	{
		free(msg->data);
		free(msg);
		return NULL;
	}

	size_t nb = blks->len / MD5_BLK_LEN;
	for (size_t i = 0; i <= nb; i += MD5_BLK_LEN)
		md5_update(&ctx, blks->data + i);

	free(blks->data);
	free(blks);
	free(msg->data);
	free(msg);
	return md5_final(&ctx);
}
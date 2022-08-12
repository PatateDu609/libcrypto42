#include "hmac.h"
#include "common.h"
#include "crypto.h"
#include "libft.h"
#include <stdio.h>

int main()
{
	char *key = "key";
	char *message = "The quick brown fox jumps over the lazy dog";
	struct hmac_req req;
	req.ctx = hmac_setup(HMAC_SHA2_256);

	uint8_t res[req.ctx.L];

	req.key = (uint8_t *)key;
	req.key_len = ft_strlen(key);
	req.message = (uint8_t *)message;
	req.message_len = ft_strlen(message);
	req.res_hmac = res;

	hmac(req);
	char *req_str = stringify_hash(res, sizeof res);
	printf("%s\n", req_str);
}

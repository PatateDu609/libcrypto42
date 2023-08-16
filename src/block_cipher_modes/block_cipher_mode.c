#include "cipher.h"
#include "internal.h"

typedef uint8_t *(cipher_mode_func) (struct cipher_ctx *);

uint8_t *block_cipher(struct cipher_ctx *ctx) {
	enum cipher_mode         mode    = block_cipher_get_mode(ctx->algo.type);
	static cipher_mode_func *funcs[] = {
		[CIPHER_MODE_ECB] = ECB_encrypt,   [CIPHER_MODE_CBC] = CBC_encrypt,   [CIPHER_MODE_CFB] = full_CFB_encrypt,
		[CIPHER_MODE_CFB1] = CFB1_encrypt, [CIPHER_MODE_CFB8] = CFB8_encrypt, [CIPHER_MODE_OFB] = OFB_encrypt,
	};

	return funcs[mode](ctx);
}

uint8_t *block_decipher(struct cipher_ctx *ctx) {
	enum cipher_mode         mode    = block_cipher_get_mode(ctx->algo.type);
	static cipher_mode_func *funcs[] = {
		[CIPHER_MODE_ECB] = ECB_decrypt,   [CIPHER_MODE_CBC] = CBC_decrypt,   [CIPHER_MODE_CFB] = full_CFB_decrypt,
		[CIPHER_MODE_CFB1] = CFB1_decrypt, [CIPHER_MODE_CFB8] = CFB8_decrypt, [CIPHER_MODE_OFB] = OFB_decrypt,
	};

	return funcs[mode](ctx);
}

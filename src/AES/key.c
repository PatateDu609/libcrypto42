#include "internal.h"
#include <string.h>

static const uint32_t round_constants[10] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
	0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
};

void key_expansion(struct aes_ctx *alg, const uint32_t *key) {
	uint32_t *res = alg->key_schedule;
	memset(res, 0, AES_KEY_SCHEDULE_LENGTH * sizeof *res);

	enum aes_type type = alg->type;

	switch (type) {
	case AES256:
		res[7] = key[7];
		res[6] = key[6];
		__fallthrough;
	case AES192:
		res[5] = key[5];
		res[4] = key[4];
		__fallthrough;
	case AES128:
		res[3] = key[3];
		res[2] = key[2];
		res[1] = key[1];
		res[0] = key[0];
		break;
	default:
		fprintf(stderr, "fatal: got bad algorithm in AES key_expansion");
		exit(EXIT_FAILURE);
	}

	uint32_t        temp, Nk = alg->Nk, i_mod_Nk;
	const uint32_t *rcon = round_constants;

	if (type == AES256) {// Avoid condition repetition
		for (uint32_t i = Nk; i <= 4 * alg->Nr + 3; i++) {
			i_mod_Nk = i % Nk;
			temp     = res[i - 1];

			if (i_mod_Nk == 0)
				temp = sub_word(ROTL(temp, 8)) ^ *rcon++;
			else if (i_mod_Nk == 4)
				temp = sub_word(temp);

			res[i] = res[i - Nk] ^ temp;
		}
	} else {
		for (uint32_t i = Nk; i <= 4 * alg->Nr + 3; i++) {
			temp = res[i - 1];

			if (i % Nk == 0)
				temp = sub_word(ROTL(temp, 8)) ^ *rcon++;

			res[i] = res[i - Nk] ^ temp;
		}
	}
}

//int check_alg(struct aes_ctx *ctx, const uint32_t *key, uint32_t *expected) {
//	key_expansion(ctx, key);
//
//	int res = 0;
//	for (size_t i = 0, last = 4 * (ctx->Nr + 1); i < last; i++) {
//		if (expected[i] != ctx->key_schedule[i]) {
//			fprintf(stderr, "error on w%zu, expected %08x, got %08x\n", i, expected[i], ctx->key_schedule[i]);
//			res = 1;
//		}
//	}
//
//	return res;
//}
//
//int main() {
//	int res;
//	{
//		struct aes_ctx ctx = {
//			.type = AES128,
//			.Nr   = AES128_NB_ROUNDS,
//			.Nk   = AES128_KEY_SIZE,
//			.Nb   = AES_BLK_SIZE,
//		};
//		printf("Running AES128\n");
//
//		uint32_t key[]      = { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c };
//		uint32_t expected[] = {
//			0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, 0xf2c295f2,
//			0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f,
//			0xb671253b, 0xdb0bad00, 0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641,
//			0xca0093fd, 0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
//			0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
//		};
//		res = check_alg(&ctx, key, expected);
//		printf("AES128 %s\n\n", (res == 0) ? "OK" : "KO");
//	}
//
//	{
//		struct aes_ctx ctx = {
//			.type = AES192,
//			.Nr   = AES192_NB_ROUNDS,
//			.Nk   = AES192_KEY_SIZE,
//			.Nb   = AES_BLK_SIZE,
//		};
//		printf("Running AES192\n");
//
//		uint32_t key[]      = { 0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b };
//		uint32_t expected[] = {
//			0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5, 0xec12068e,
//			0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, 0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386,
//			0x485af057, 0x21efb14f, 0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6, 0xa25e7ed5, 0x83b1cf9a, 0x27f93943,
//			0x6a94f767, 0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
//			0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753, 0xca400538,
//			0x8fcc5006, 0x282d166a, 0xbc3ce7b5, 0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202,
//		};
//		int local_res = check_alg(&ctx, key, expected);
//		printf("AES192 %s\n\n", (local_res == 0) ? "OK" : "KO");
//		res |= local_res;
//	}
//
//	{
//		struct aes_ctx ctx = {
//			.type = AES256,
//			.Nr   = AES256_NB_ROUNDS,
//			.Nk   = AES256_KEY_SIZE,
//			.Nb   = AES_BLK_SIZE,
//		};
//		printf("Running AES256\n");
//
//		uint32_t key[]      = { 0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
//			                    0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4 };
//		uint32_t expected[] = {
//			0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4, 0x9ba35411,
//			0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917,
//			0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2,
//			0xfab8b464, 0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
//			0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, 0x5886ca5d,
//			0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34,
//			0x9adf6ace, 0xbd10190d, 0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
//		};
//
//		int local_res = check_alg(&ctx, key, expected);
//		printf("AES256 %s\n", (local_res == 0) ? "OK" : "KO");
//		res |= local_res;
//	}
//
//	return res;
//}
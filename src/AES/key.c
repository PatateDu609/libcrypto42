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
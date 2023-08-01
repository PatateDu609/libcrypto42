#ifndef LIBCRYPTO42_INTERNAL_H
#define LIBCRYPTO42_INTERNAL_H

#include "common.h"
#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES128_NB_ROUNDS 10
#define AES192_NB_ROUNDS 12
#define AES256_NB_ROUNDS 14

/// Key schedule generate 4 * (Nr + 1) words, where words is the biggest possible schedule, so Nr = 14.
#define AES_KEY_SCHEDULE_LENGTH 60

enum aes_type {
	AES128,
	AES192,
	AES256,
};

#define AES_MAX_KEY_SIZE AES256_KEY_SIZE
union aes_key {
	uint32_t w[AES_MAX_KEY_SIZE];
	uint8_t	 b[4 * AES_MAX_KEY_SIZE];
};
#undef AES_MAX_KEY_SIZE

union aes_data {
	uint32_t w[AES_BLK_SIZE];
	uint8_t	 b[4 * AES_BLK_SIZE];
};

struct aes_ctx {
	enum aes_type type;									/// Represents the alg type

	uint32_t	  Nk;									/// Key length (in bytes)
	uint32_t	  Nb;									/// Block size (in bytes)
	uint32_t	  Nr;									/// Number of rounds

	uint32_t	  key_schedule[AES_KEY_SCHEDULE_LENGTH];/// Key schedule of the algorithm
};

/**
 * @brief The key schedule procedure which generate a key for each round.
 *
 * @param alg Information about the current algorithm.
 * @param key The key from which to expand.
 *
 * @note This function is described by the FIPS 197, section 5.2.
 */
void	 key_expansion(struct aes_ctx *alg, const uint32_t *key);

/**
 * @brief This is the SUBWORD function that substitutes individual bytes in a given word
 *
 * @param word The input word
 *
 * @return The output word after processing
 *
 * @note This function is described by the FIPS 197, section 5.2, formula 5.11.
 */
uint32_t sub_word(uint32_t word);

/**
 * @brief This is the SUBBYTES function to perform an sbox operation on each byte of the state.
 *
 * @param data The state
 *
 * @note This function is described by the FIPS 197, section 5.1.1.
 */
void	 sub_bytes(union aes_data *data);

/**
 * @brief This is the INV_SUBBYTES function that reverses what SUBBYTES does.
 *
 * @param data The state.
 *
 * @note This function is described by the FIPS 197, section 5.3.2.
 */
void	 inv_sub_bytes(union aes_data *data);

/**
 * @brief This is the ShiftRows function that do a parametric shift on each row of the state.
 *
 * @param data The state.
 *
 * @note This function is described by the FIPS 197, section 5.1.2.
 */
void	 shift_rows(union aes_data *data);

/**
 * @brief This is the InvShiftRows function that reverses what ShiftRows does.
 *
 * @param data The state.
 *
 * @note This function is described in the FIPS 197, section 5.3.1.
 */
void	 inv_shift_rows(union aes_data *data);

/**
 * @brief This is the MixColumn function of the Rijndael cipher algorithm.
 *
 * @param data The state.
 *
 * @note This function is described by the FIPS 197, section 5.1.3.
 */
void	 mix_columns(union aes_data *data);

/**
 * This function is the InvMixColumns that reverses the output of the MixColumns function.
 *
 * @param data The state.
 *
 * @note This function is described by the FIPS 197, section 5.3.3.
 */
void	 inv_mix_columns(union aes_data *data);

/**
 * @brief This is the AddRoundKey function that combines the key schedule with the state.
 *
 * @param ctx The algorithm context, from which we get the key schedule.
 * @param data The state.
 * @param rnd The current round.
 *
 * @note This function is described by the FIPS 197, section 5.1.4
 */
void	 add_round_key(struct aes_ctx *ctx, union aes_data *data, uint8_t rnd);

#ifdef __cplusplus
};
#endif

#endif// LIBCRYPTO42_INTERNAL_H

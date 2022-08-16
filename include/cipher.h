/**
 * @file cipher.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief This file contains all needed to use block level ciphers.
 * It contains also the cipher modes.
 * @date 2022-08-14
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ********************** Cipher modes related functions ******************** */

/**
 * @brief Enumerate all available block cipher algorithms.
 */
enum block_cipher
{
	BLOCK_CIPHER_DES,	///< Data Encryption Standard
	BLOCK_CIPHER_TDES,	///< Triple DES (Not implemented yet)
	BLOCK_CIPHER_AES,	///< Advanced Encryption Standard (Not implemented yet)
};

struct block_cipher_ctx
{
	enum block_cipher algo;	///< The algorithm to use.
	uint8_t blk_size;		///< The block size of the algorithm.

	union
	{
		struct
		{
			uint64_t (*enc)(uint64_t, uint64_t);	///< The function to use to encrypt a block of 8 bytes.
			uint64_t (*dec)(uint64_t, uint64_t);	///< The function to use to decrypt a block of 8 bytes.
		} blk8;
		struct
		{
			__uint128_t (*enc)(__uint128_t, __uint128_t);	///< The function to use to encrypt a block of 16 bytes.
			__uint128_t (*dec)(__uint128_t, __uint128_t);	///< The function to use to decrypt a block of 16 bytes.
		} blk16;
	};
};

/**
 * @brief A context structure for block cipher modes.
 *
 * @note Depending on the cipher mode, some fields may be useless or at contrary they may be mandatory.
 */
struct cipher_ctx
{
	struct block_cipher_ctx algo;	///< The algorithm to use.

	uint8_t *key;					///< Key used for the cipher mode
	size_t key_len;					///< Key length in bytes

	uint8_t *iv;					///< Initialization vector used for the cipher mode
	size_t iv_len;					///< Initialization vector length in bytes

	uint8_t *plaintext;				///< Plaintext to be encrypted
	size_t plaintext_len;			///< Plaintext length in bytes

	uint8_t *ciphertext;			///< Ciphertext to be decrypted
	size_t cipher_len;				///< Ciphertext length in bytes
};

/**
 * @brief Setup the algorithm functor to use for the cipher mode.
 *
 * @param algo The algorithm to setup.
 *
 * @return Returns a pointer to the algorithm functor.
 */
struct block_cipher_ctx setup_algo(enum block_cipher algo);

/**
 * @brief Performs an ECB encryption on the given context.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t *ECB_encrypt(struct cipher_ctx *ctx);

/**
 * @brief Performs an ECB decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t *ECB_decrypt(struct cipher_ctx *ctx);

/**
 * @brief Performs an CBC encryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t *CBC_encrypt(struct cipher_ctx *ctx);

/**
 * @brief Performs an CBC decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */

/* ************************** DES related functions ************************* */

/**
 * @brief Encrypt a single block of 64 bits with the DES algorithm.
 *
 * @param block The block to encrypt.
 * @param key The key to use for the encryption.
 *
 * @return The encrypted block.
 *
 * @note This functions should be used with one of the cipher block modes.
 * @note The key must be given in its raw form (i.e. 64 bits), all the processing
 * is done by the function.
 */
uint64_t des_encrypt(uint64_t block, uint64_t key);

/**
 * @brief Decrypt a single block of 64 bits with the DES algorithm.
 *
 * @param block The block to decrypt.
 * @param key The key to use for the decryption.
 *
 * @return The decrypted block.
 *
 * @note This functions should be used with one of the cipher block modes.
 * @note The key must be given in its raw form (i.e. 64 bits), all the processing
 * is done by the function.
 */
uint64_t des_decrypt(uint64_t block, uint64_t key);

#endif /* CIPHER_H */

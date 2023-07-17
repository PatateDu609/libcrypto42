/**
 * @file cipher.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief This file contains all needed to use block level ciphers.
 * It contains also the cipher modes.
 * @date 2022-08-14
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLK_SIZE 4		 // size in words (== 128 bits)
#define AES_BLK_SIZE_BYTES 16// size in bytes (== 128 bits)

// This is counted in words (i.e. 4 bytes groups for AES128)
#define AES128_KEY_SIZE 4		// == 128 bits
#define AES128_KEY_SIZE_BYTES 16// == 128 bits
#define AES192_KEY_SIZE 6		// == 192 bits
#define AES192_KEY_SIZE_BYTES 24// == 192 bits
#define AES256_KEY_SIZE 8		// == 256 bits
#define AES256_KEY_SIZE_BYTES 32// == 256 bits

/* ********************** Cipher modes related functions ******************** */

/**
 * @brief Enumerate all available block cipher algorithms.
 */
enum block_cipher {
	BLOCK_CIPHER_DES,	   ///< Data Encryption Standard

	BLOCK_CIPHER_3DES_EDE2,///< Triple DES with 2 keys (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3,///< Triple DES with 3 keys (Not implemented yet)

	BLOCK_CIPHER_AES128,   ///< Advanced Encryption Standard with a 128 bits key
	BLOCK_CIPHER_AES192,   ///< Advanced Encryption Standard with a 192 bits key
	BLOCK_CIPHER_AES256,   ///< Advanced Encryption Standard with a 256 bits key
};

struct block_cipher_ctx {
	enum block_cipher type;
	size_t			  blk_size;
	size_t			  key_size;
};

/**
 * @brief A context structure for block cipher modes.
 *
 * @note Depending on the cipher mode, some fields may be useless or at contrary they may be mandatory.
 */
struct cipher_ctx {
	struct block_cipher_ctx algo;		   ///< The algorithm to use.

	uint8_t				   *key;		   ///< Key used for the cipher mode
	size_t					key_len;	   ///< Key length in bytes

	uint8_t				   *iv;			   ///< Initialization vector used for the cipher mode
	size_t					iv_len;		   ///< Initialization vector length in bytes

	uint8_t				   *plaintext;	   ///< Plaintext to be encrypted
	size_t					plaintext_len; ///< Plaintext length in bytes

	uint8_t				   *ciphertext;	   ///< Ciphertext to be decrypted
	size_t					ciphertext_len;///< Ciphertext length in bytes
};

/**
 * @brief Setup the algorithm description to use in this library..
 *
 * @param algo The algorithm to setup.
 *
 * @return Returns a struct containing information about the current algorithm..
 */
struct block_cipher_ctx setup_algo(enum block_cipher algo);

/**
 * @brief Performs an ECB encryption on the given context.
 *
 * @param ctx The context to use for the encryption.
 *
 * @return Returns a copy of the pointer given in the context for the ciphertext.
 */
uint8_t				   *ECB_encrypt(struct cipher_ctx *ctx);

/**
 * @brief Performs an ECB decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t				   *ECB_decrypt(struct cipher_ctx *ctx);

/**
 * @brief Performs an CBC encryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t				   *CBC_encrypt(struct cipher_ctx *ctx);

/**
 * @brief Performs an CBC decryption on the given context.
 *
 * @param ctx The context to use for the decryption.
 *
 * @return Returns a copy of the pointer given in the context for the plaintext.
 */
uint8_t				   *CBC_decrypt(struct cipher_ctx *ctx);

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
uint64_t				des_encrypt(uint64_t block, uint64_t key);

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
uint64_t				des_decrypt(uint64_t block, uint64_t key);

/* ************************** AES related functions ************************* */

/**
 * @brief Encrypt a single block of 128 bits using the AES algorithm with a key size of 128.
 *
 * @param blk The block to encrypt.
 * @param key The key to use for encryption, it must be 128 bits (16 bytes) long.
 *
 * @return The encrypted block.
 *
 * @note This functions should be used with one of the cipher block modes.
 *
 * @warning The value returned by this function must be freed.
 */
uint8_t				   *aes128_encrypt(uint8_t *blk, const uint8_t *key);

/**
 * @brief Encrypt a single block of 192 bits using the AES algorithm with a key size of 192.
 *
 * @param blk The block to encrypt.
 * @param key The key to use for encryption, it must be 192 bits (24 bytes) long.
 *
 * @return The encrypted block.
 *
 * @note This functions should be used with one of the cipher block modes.
 *
 * @warning The value returned by this function must be freed.
 */
uint8_t				   *aes192_encrypt(uint8_t *blk, const uint8_t *key);

/**
 * @brief Encrypt a single block of 256 bits using the AES algorithm with a key size of 256.
 *
 * @param blk The block to encrypt.
 * @param key The key to use for encryption, it must be 256 bits (32 bytes) long.
 *
 * @return The encrypted block.
 *
 * @note This functions should be used with one of the cipher block modes.
 *
 * @warning The value returned by this function must be freed.
 */
uint8_t				   *aes256_encrypt(uint8_t *blk, const uint8_t *key);


/**
 * @brief Decrypt a single block of 128 bits with the AES algorithm with a key size of 128.
 *
 * @param blk The block to decrypt.
 * @param key The key to use for the decryption, it must be 128 bits (16 bytes) long.
 *
 * @return The decrypted block.
 *
 * @note This function should only be used with one of the cipher block modes.
 *
 * @warning The value returned by this function must be freed.
 */
uint8_t				   *aes128_decrypt(uint8_t *blk, const uint8_t *key);

/**
 * @brief Decrypt a single block of 192 bits with the AES algorithm with a key size of 192.
 *
 * @param blk The block to decrypt.
 * @param key The key to use for the decryption, it must be 192 bits (24 bytes) long.
 *
 * @return The decrypted block.
 *
 * @note This function should only be used with one of the cipher block modes.
 *
 * @warning The value returned by this function must be freed.
 */
uint8_t				   *aes192_decrypt(uint8_t *blk, const uint8_t *key);

/**
 * @brief Decrypt a single block of 256 bits with the AES algorithm with a key size of 256.
 *
 * @param blk The block to decrypt.
 * @param key The key to use for the decryption, it must be 256 bits (32 bytes) long.
 *
 * @return The decrypted block.
 *
 * @note This function should only be used with one of the cipher block modes.
 *
 * @warning The value returned by this function must be freed.
 */
uint8_t				   *aes256_decrypt(uint8_t *blk, const uint8_t *key);

#endif /* CIPHER_H */

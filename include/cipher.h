/**
 * @file cipher.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief This file contains all needed to use block level ciphers.
 * It contains also the cipher modes.
 * @date 2022-08-14
 */

#ifndef CIPHER_H
#define CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLK_SIZE 4       // size in words (== 128 bits)
#define AES_BLK_SIZE_BYTES 16// size in bytes (== 128 bits)

// This is counted in words (i.e. 4 bytes groups for AES128)
#define AES128_KEY_SIZE 4       // == 128 bits
#define AES128_KEY_SIZE_BYTES 16// == 128 bits
#define AES192_KEY_SIZE 6       // == 192 bits
#define AES192_KEY_SIZE_BYTES 24// == 192 bits
#define AES256_KEY_SIZE 8       // == 256 bits
#define AES256_KEY_SIZE_BYTES 32// == 256 bits

/* ********************** Cipher modes related functions ******************** */

/**
 * @brief Enumerate all available block cipher algorithms.
 */
enum block_cipher {
	BLOCK_CIPHER_DES_ECB = 0x0,             ///< Data Encryption Standard using ECB cipher mode
	BLOCK_CIPHER_DES_CBC,                   ///< Data Encryption Standard using CBC cipher mode
	BLOCK_CIPHER_DES_CFB,                   ///< Data Encryption Standard using CFB cipher mode
	BLOCK_CIPHER_DES_CFB1,                  ///< Data Encryption Standard using CFB1 cipher mode
	BLOCK_CIPHER_DES_CFB8,                  ///< Data Encryption Standard using CFB8 cipher mode
	BLOCK_CIPHER_DES_OFB,                   ///< Data Encryption Standard using OFB cipher mode
	BLOCK_CIPHER_DES_CTR,                   ///< Data Encryption Standard using CTR cipher mode
	BLOCK_CIPHER_DES = BLOCK_CIPHER_DES_CBC,///< Data Encryption Standard (defaults to CBC mode)

	BLOCK_CIPHER_3DES_EDE2_ECB = 0x10,///< Triple DES with 2 keys using ECB cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE2_CBC,       ///< Triple DES with 2 keys using CBC cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE2_CFB,       ///< Triple DES with 2 keys using CFB cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE2_CFB1,      ///< Triple DES with 2 keys using CFB1 cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE2_CFB8,      ///< Triple DES with 2 keys using CFB8 cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE2_OFB,       ///< Triple DES with 2 keys using OFB cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE2_CTR,       ///< Triple DES with 2 keys using CTR cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE2 =
			BLOCK_CIPHER_3DES_EDE2_CBC,///< Triple DES with 2 keys (defaults to CBC mode) (Not implemented yet)

	BLOCK_CIPHER_3DES_EDE3_ECB = 0x20,///< Triple DES with 3 keys using ECB cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3_CBC,       ///< Triple DES with 3 keys using CBC cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3_CFB,       ///< Triple DES with 3 keys using CFB cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3_CFB1,      ///< Triple DES with 3 keys using CFB1 cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3_CFB8,      ///< Triple DES with 3 keys using CFB8 cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3_OFB,       ///< Triple DES with 3 keys using OFB cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3_CTR,       ///< Triple DES with 3 keys using CTR cipher mode (Not implemented yet)
	BLOCK_CIPHER_3DES_EDE3 =
			BLOCK_CIPHER_3DES_EDE3_CBC,///< Triple DES with 3 keys (defaults to CBC mode) (Not implemented yet)

	BLOCK_CIPHER_AES128_ECB = 0x30,///< Advanced Encryption Standard with a 128 bits key using ECB cipher mode
	BLOCK_CIPHER_AES128_CBC,       ///< Advanced Encryption Standard with a 128 bits key using CBC cipher mode
	BLOCK_CIPHER_AES128_CFB,       ///< Advanced Encryption Standard with a 128 bits key using CFB cipher mode
	BLOCK_CIPHER_AES128_CFB1,      ///< Advanced Encryption Standard with a 128 bits key using CFB1 cipher mode
	BLOCK_CIPHER_AES128_CFB8,      ///< Advanced Encryption Standard with a 128 bits key using CFB8 cipher mode
	BLOCK_CIPHER_AES128_OFB,       ///< Advanced Encryption Standard with a 128 bits key using OFB cipher mode
	BLOCK_CIPHER_AES128_CTR,       ///< Advanced Encryption Standard with a 128 bits key using CTR cipher mode
	BLOCK_CIPHER_AES128 =
			BLOCK_CIPHER_AES128_CBC,///< Advanced Encryption Standard with a 128 bits key (defaults to CBC mode)

	BLOCK_CIPHER_AES192_ECB = 0x40,///< Advanced Encryption Standard with a 192 bits key using ECB cipher mode
	BLOCK_CIPHER_AES192_CBC,       ///< Advanced Encryption Standard with a 192 bits key using CBC cipher mode
	BLOCK_CIPHER_AES192_CFB,       ///< Advanced Encryption Standard with a 192 bits key using CFB cipher mode
	BLOCK_CIPHER_AES192_CFB1,      ///< Advanced Encryption Standard with a 192 bits key using CFB1 cipher mode
	BLOCK_CIPHER_AES192_CFB8,      ///< Advanced Encryption Standard with a 192 bits key using CFB8 cipher mode
	BLOCK_CIPHER_AES192_OFB,       ///< Advanced Encryption Standard with a 192 bits key using OFB cipher mode
	BLOCK_CIPHER_AES192_CTR,       ///< Advanced Encryption Standard with a 192 bits key using CTR cipher mode
	BLOCK_CIPHER_AES192 =
			BLOCK_CIPHER_AES192_CBC,///< Advanced Encryption Standard with a 192 bits key (defaults to CBC mode)

	BLOCK_CIPHER_AES256_ECB = 0x50,///< Advanced Encryption Standard with a 256 bits key using ECB cipher mode
	BLOCK_CIPHER_AES256_CBC,       ///< Advanced Encryption Standard with a 256 bits key using CBC cipher mode
	BLOCK_CIPHER_AES256_CFB,       ///< Advanced Encryption Standard with a 256 bits key using CFB cipher mode
	BLOCK_CIPHER_AES256_CFB1,      ///< Advanced Encryption Standard with a 256 bits key using CFB1 cipher mode
	BLOCK_CIPHER_AES256_CFB8,      ///< Advanced Encryption Standard with a 256 bits key using CFB8 cipher mode
	BLOCK_CIPHER_AES256_OFB,       ///< Advanced Encryption Standard with a 256 bits key using OFB cipher mode
	BLOCK_CIPHER_AES256_CTR,       ///< Advanced Encryption Standard with a 256 bits key using CTR cipher mode
	BLOCK_CIPHER_AES256 =
			BLOCK_CIPHER_AES256_CBC,///< Advanced Encryption Standard with a 256 bits key (defaults to CBC mode)
};

struct block_cipher_ctx {
	enum block_cipher type;
	size_t            blk_size;
	size_t            key_size;
	size_t            mode_blk_size_bits;
};

/**
 * @brief A context structure for block cipher modes.
 *
 * @note Depending on the cipher mode, some fields may be useless or at contrary they may be mandatory.
 */
struct cipher_ctx {
	struct block_cipher_ctx algo;///< The algorithm to use.

	uint8_t                *key;    ///< Key used for the cipher mode
	size_t                  key_len;///< Key length in bytes

	uint8_t                *iv;    ///< Initialization vector used for the cipher mode
	size_t                  iv_len;///< Initialization vector length in bytes

	uint8_t                *nonce;    ///< Nonce (only used in the CTR encryption mode)
	size_t                  nonce_len;///< Nonce's length in bytes (only used in the CTR encryption mode)

	uint8_t                *plaintext;    ///< Plaintext to be encrypted
	size_t                  plaintext_len;///< Plaintext length in bytes

	uint8_t                *ciphertext;    ///< Ciphertext to be decrypted
	size_t                  ciphertext_len;///< Ciphertext length in bytes
};

uint8_t *block_cipher(struct cipher_ctx *ctx);
uint8_t *block_decipher(struct cipher_ctx *ctx);

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
uint8_t *aes128_encrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t *aes192_encrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t *aes256_encrypt(uint8_t *blk, const uint8_t *key);


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
uint8_t *aes128_decrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t *aes192_decrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t *aes256_decrypt(uint8_t *blk, const uint8_t *key);

#ifdef __cplusplus
};
#endif

#endif /* CIPHER_H */

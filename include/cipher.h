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
	BLOCK_CIPHER_DES_ECB  = 0b00000000,///< Data Encryption Standard using ECB cipher mode
	BLOCK_CIPHER_DES_CBC  = 0b10000010,///< Data Encryption Standard using CBC cipher mode (default cipher mode)
	BLOCK_CIPHER_DES_OFB  = 0b00000101,///< Data Encryption Standard using OFB cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_DES_CFB  = 0b00000111,///< Data Encryption Standard using CFB cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_DES_CFB1 = 0b00001001,///< Data Encryption Standard using CFB1 cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_DES_CFB8 = 0b00001011,///< Data Encryption Standard using CFB8 cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_DES      = BLOCK_CIPHER_DES_CBC,///< Data Encryption Standard (defaults to CBC cipher mode)

	BLOCK_CIPHER_AES128_ECB = 0b00010000,///< Advanced Encryption Standard with a 128 bits key using ECB cipher mode
	BLOCK_CIPHER_AES128_CBC =
			0b10010010,///< Advanced Encryption Standard with a 128 bits key using CBC cipher mode (default cipher mode)
	BLOCK_CIPHER_AES128_OFB  = 0b00010101,///< Advanced Encryption Standard with a 128 bits key using OFB cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES128_CFB  = 0b00010111,///< Advanced Encryption Standard with a 128 bits key using CFB cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES128_CFB1 = 0b00011001,///< Advanced Encryption Standard with a 128 bits key using CFB1 cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES128_CFB8 = 0b00011011,///< Advanced Encryption Standard with a 128 bits key using CFB8 cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES128_CTR  = 0b00011101,///< Advanced Encryption Standard with a 128 bits key using CTR cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES128 =
			BLOCK_CIPHER_AES128_CBC,///< Advanced Encryption Standard with a 128 bits key (defaults to CBC cipher mode)

	BLOCK_CIPHER_AES192_ECB = 0b00100000,///< Advanced Encryption Standard with a 192 bits key using ECB cipher mode
	BLOCK_CIPHER_AES192_CBC =
			0b10100010,///< Advanced Encryption Standard with a 192 bits key using CBC cipher mode (default cipher mode)
	BLOCK_CIPHER_AES192_OFB  = 0b00100101,///< Advanced Encryption Standard with a 192 bits key using OFB cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES192_CFB  = 0b00100111,///< Advanced Encryption Standard with a 192 bits key using CFB cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES192_CFB1 = 0b00101001,///< Advanced Encryption Standard with a 192 bits key using CFB1 cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES192_CFB8 = 0b00101011,///< Advanced Encryption Standard with a 192 bits key using CFB8 cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES192_CTR  = 0b00101101,///< Advanced Encryption Standard with a 192 bits key using CTR cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES192 =
			BLOCK_CIPHER_AES192_CBC,///< Advanced Encryption Standard with a 192 bits key (defaults to CBC cipher mode)

	BLOCK_CIPHER_AES256_ECB = 0b00110000,///< Advanced Encryption Standard with a 256 bits key using ECB cipher mode
	BLOCK_CIPHER_AES256_CBC =
			0b10110010,///< Advanced Encryption Standard with a 256 bits key using CBC cipher mode (default cipher mode)
	BLOCK_CIPHER_AES256_OFB  = 0b00110101,///< Advanced Encryption Standard with a 256 bits key using OFB cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES256_CFB  = 0b00110111,///< Advanced Encryption Standard with a 256 bits key using CFB cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES256_CFB1 = 0b00111001,///< Advanced Encryption Standard with a 256 bits key using CFB1 cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES256_CFB8 = 0b00111011,///< Advanced Encryption Standard with a 256 bits key using CFB8 cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES256_CTR  = 0b00111101,///< Advanced Encryption Standard with a 256 bits key using CTR cipher mode
	                                      ///< (acts as a stream cipher)
	BLOCK_CIPHER_AES256 =
			BLOCK_CIPHER_AES256_CBC,///< Advanced Encryption Standard with a 256 bits key (defaults to CBC cipher mode)

	BLOCK_CIPHER_3DES_EDE2_ECB = 0b01000000,///< Triple DES with 2 keys using ECB cipher mode
	BLOCK_CIPHER_3DES_EDE2_CBC = 0b11000010,///< Triple DES with 2 keys using CBC cipher mode (default cipher mode)
	BLOCK_CIPHER_3DES_EDE2_OFB = 0b01000101,///< Triple DES with 2 keys using OFB cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE2_CFB = 0b01000111,///< Triple DES with 2 keys using CFB cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE2_CFB1 =
			0b01001001,///< Triple DES with 2 keys using CFB1 cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE2_CFB8 =
			0b01001011,                     ///< Triple DES with 2 keys using CFB8 cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE2_CTR = 0b01001101,///< Triple DES with 2 keys using CTR cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE2     = BLOCK_CIPHER_3DES_EDE2_CBC,///< Triple DES with 2 keys (defaults to CBC cipher mode)

	BLOCK_CIPHER_3DES_EDE3_ECB = 0b01010000,///< Triple DES with 3 keys using ECB cipher mode
	BLOCK_CIPHER_3DES_EDE3_CBC = 0b11010010,///< Triple DES with 3 keys using CBC cipher mode (default cipher mode)
	BLOCK_CIPHER_3DES_EDE3_OFB = 0b01010101,///< Triple DES with 3 keys using OFB cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE3_CFB = 0b01010111,///< Triple DES with 3 keys using CFB cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE3_CFB1 =
			0b01011001,///< Triple DES with 3 keys using CFB1 cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE3_CFB8 =
			0b01011011,                     ///< Triple DES with 3 keys using CFB8 cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE3_CTR = 0b01011101,///< Triple DES with 3 keys using CTR cipher mode (acts as a stream cipher)
	BLOCK_CIPHER_3DES_EDE3     = BLOCK_CIPHER_3DES_EDE3_CBC,///< Triple DES with 3 keys (defaults to CBC cipher mode)
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

struct cipher_ctx *new_cipher_context(enum block_cipher algo);

uint8_t           *block_cipher(struct cipher_ctx *ctx);
uint8_t           *block_decipher(struct cipher_ctx *ctx);

/* ************************** DES related functions ************************* */

/**
 * @brief Encrypt a single block of 64 bits with the DES algorithm.
 *
 * @param block The block to encrypt.
 * @param key The key to use for the encryption.
 *
 * @return The encrypted block.
 *
 * @note These functions should be used with one of the cipher block modes.
 */
uint8_t           *des_encrypt(uint8_t *block, const uint8_t *key);

/**
 * @brief Decrypt a single block of 64 bits with the DES algorithm.
 *
 * @param block The block to decrypt.
 * @param key The key to use for the decryption.
 *
 * @return The decrypted block.
 *
 * @note These functions should be used with one of the cipher block modes.
 */
uint8_t           *des_decrypt(uint8_t *block, const uint8_t *key);

/* ************************* TDES related functions ************************* */


/**
 * @brief Encrypt a single block of 64 bits with the TDES algorithm in EDE mode (encrypt-decrypt-encrypt),
 * using 3 different keys.
 *
 * @param block The block to encrypt.
 * @param key The key to use for the encryption.
 *
 * @return The encrypted block.
 *
 * @note These functions should be used with one of the cipher block modes.
 * @note Keys must be given one after the other, without any padding.
 */
uint8_t           *tdes_ede3_encrypt(uint8_t *block, const uint8_t *key);

/**
 * @brief Encrypt a single block of 64 bits with the TDES algorithm in EDE mode (encrypt-decrypt-encrypt),
 * using 2 different keys.
 *
 * @param block The block to encrypt.
 * @param key The key to use for the encryption.
 *
 * @return The encrypted block.
 *
 * @note These functions should be used with one of the cipher block modes.
 * @note Keys must be given one after the other, without any padding.
 */
uint8_t           *tdes_ede2_encrypt(uint8_t *block, const uint8_t *key);

/**
 * @brief Decrypt a single block of 64 bits with the TDES algorithm in EDE mode (encrypt-decrypt-encrypt),
 * using 3 different keys.
 *
 * @param block The block to decrypt.
 * @param key The key to use for the decryption.
 *
 * @return The decrypted block.
 *
 * @note These functions should be used with one of the cipher block modes.
 * @note Keys must be given one after the other, without any padding.
 */
uint8_t           *tdes_ede3_decrypt(uint8_t *block, const uint8_t *key);

/**
 * @brief Decrypt a single block of 64 bits with the TDES algorithm in EDE mode (encrypt-decrypt-encrypt),
 * using 2 different keys.
 *
 * @param block The block to decrypt.
 * @param key The key to use for the decryption.
 *
 * @return The decrypted block.
 *
 * @note These functions should be used with one of the cipher block modes.
 * @note Keys must be given one after the other, without any padding.
 */
uint8_t           *tdes_ede2_decrypt(uint8_t *block, const uint8_t *key);

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
uint8_t           *aes128_encrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t           *aes192_encrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t           *aes256_encrypt(uint8_t *blk, const uint8_t *key);


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
uint8_t           *aes128_decrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t           *aes192_decrypt(uint8_t *blk, const uint8_t *key);

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
uint8_t           *aes256_decrypt(uint8_t *blk, const uint8_t *key);

#ifdef __cplusplus
};
#endif

#endif /* CIPHER_H */

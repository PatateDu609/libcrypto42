/**
 * @file cipher.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief This file contains all needed to use block level ciphers.
 * @date 2022-08-14
 *
 * @note This is not intended to be used directly, you should use them through
 * the cipher block processing modes, such as ECB, CBC, CFB, OFB, CTR, etc.
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

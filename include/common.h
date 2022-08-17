/**
 * @file common.h
 * @author Ghali Boucetta (gboucett@student.42,fr)
 * @brief Common definitions and functions
 * @date 2022-08-08
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <byteswap.h>

/**
 * @brief All possible errors for the library.
 */
enum crypto_error
{
	CRYPTO_SUCCESS = 0,					///< Success
	CRYPTO_CTX_NULL,					///< Context is NULL

	CRYPTO_KEY_NULL,					///< Key is NULL
	CRYPTO_KEY_LEN_ZERO,				///< Key length is zero
	CRYPTO_PLAINTEXT_NULL,				///< Plaintext is NULL
	CRYPTO_PLAINTEXT_LEN_ZERO,			///< Plaintext length is zero
	CRYPTO_CIPHERTEXT_NULL,				///< Ciphertext is NULL
	CRYPTO_CIPHERTEXT_LEN_ZERO,			///< Ciphertext length is zero
	CRYPTO_IV_NULL,						///< IV is NULL
	CRYPTO_IV_LEN_ZERO,					///< IV length is zero
	CRYPTO_NONCE_NULL,					///< Nonce is NULL
	CRYPTO_NONCE_LEN_ZERO,				///< Nonce length is zero

	CRYPTO_BLKSIZE_ZERO,				///< Block size is zero
	CRYPTO_BLKSIZE_INVALID,				///< Block size must be either 8 or 16
	CRYPTO_CIPHERTEXT_BLKSIZE_UNMATCH,	///< Ciphertext should be a multiple of the block size
	CRYPTO_IV_BLKSIZE_UNMATCH,			///< IV should be equal to the block size

	CRYPTO_ALGO_UNKNOWN,				///< Unknown algorithm
	CRYPTO_ALGO_INVALID_BLKSIZE,		///< Invalid block size for the algorithm
};

/**
 * @brief Stores errors from the library.
 */
extern enum crypto_error crypto42_errno;

#define SHL(x, n) ((x) << (n))
#define SHR(x, n) ((x) >> (n))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (sizeof(x) * 8 - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (sizeof(x) * 8 - (n))))

#define bswap_128(x) ((((__uint128_t)bswap_64(x)) << 64) | bswap_64(x >> 64))

#define __internal __attribute__((visibility("internal")))
#define __hidden __attribute__((visibility("hidden")))
#define __unused __attribute__((unused))
#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define __noreturn __attribute__((noreturn))
#define __pure __attribute__((pure))

/**
 * @brief A structure to represent the message split into blocks.
 *
 * @note It may not contain all the blocks as the file may not be read in full.
 */
struct blk
{
	uint8_t *data;	///< The data of the block.
	size_t len;		///< The length of the data.
};

/**
 * @brief A structure to represent a message.
 *
 * @note It may not contain all the data as the file may not be read in full.
 */
struct msg
{
	const uint8_t *data;	///< The data of the message.
	__uint128_t len;		///< The length of the data.
	__uint128_t filesize;	///< The size of the file.
	bool is_last_part;		///< True if the message is the last part of the file.
};

/**
 * @brief Split the given data into blocks.
 *
 * @param data The data to split.
 * @param blk_len The length of the blocks.
 * @param wanted_size The size of the size put at the end of the last block.
 * @param le If true, the size is wanted in little endian, else in big endian.
 *
 * @return A pointer to a structure containing the blocks.
 */
struct blk *get_blocks(const struct msg *data, size_t blk_len, size_t wanted_size, bool le) __hidden;

/**
 * @brief Ask for a password without printing it to the terminal.
 *
 * @param prompt The prompt to display.
 *
 * @return The password.
 * @note The returned string must be freed.
 */
char *askpass(const char *prompt);

/**
 * @brief Transforms a hex buffer into a string.
 *
 * @param buf The buffer to transform.
 * @param len The length of the buffer.
 * @return The transformed string.
 *
 * @warning The returned string must be freed.
 */
static inline char *stringify_hash(const uint8_t *buf, size_t len)
{
	char *str = malloc(len * 2 + 1);

	if (!str)
		return NULL;
	for (size_t i = 0; i < len; i++)
		snprintf(str + i * 2, 3, "%02x", buf[i]);
	return str;
}

/**
 * @brief Get a random unsigned 64-bit integer from the system.
 *
 * @return The random number.
 */
uint64_t get_random(void);

/**
 * @brief Get a random unsigned 64-bit integer in the given range.
 *
 * @param min The minimum value of the range.crypto_error
 * @param max The maximum value of the range.
 * @return The random number.
 */
uint64_t get_random_range(uint64_t min, uint64_t max);

/**
 * @brief Fill an array with random bytes
 *
 * @param ptr The array to fill.
 * @param length The length of the array.
 *
 * @return A pointer to the array.
 */
uint8_t *get_random_bytes_at(uint8_t *ptr, uint64_t length);

/**
 * @brief Get an array of random bytes.
 *
 * @param len The length of the array.
 * @return A pointer to the array.
 *
 * @warning The returned array must be freed.
 */
uint8_t *get_random_bytes(size_t len);

/**
 * @brief Fill a string with random characters.
 *
 * @param ptr The string to fill.
 * @param length The length of the string.
 *
 * @return char* The string itself.
 */
char *get_random_string_at(char *ptr, uint64_t length);

/**
 * @brief Get a string of random characters.
 *
 * @param len The length of the string.
 * @return The string.
 *
 * @warning The returned string must be freed.
 */
char *get_random_string(size_t len);

/**
 * @brief Get the random string from a given charset.
 *
 * @param charset The charset to use (must be terminated by '\0').
 * @param len The length of the string.
 * @return The string.
 *
 * @warning The returned string must be freed.
 * @note The charset may contain duplicates, but it will break the pseudo-uniformity
 * of the distribution.
 */
char *get_random_string_from(const char *charset, size_t len);

/**
 * @brief Encode a byte array in base64.
 *
 * @param data The data to encode.
 * @param len The length of the data.
 * @return The encoded string.
 *
 * @warning The returned string must be freed.
 */
char *base64_encode(const uint8_t *data, size_t len);

/**
 * @brief Encode a file in base64.
 *
 * @param filename The name of the file to encode.
 *
 * @return The encoded string.
 *
 * @warning The returned string must be freed.
 * @see base64_encode
 */
char *base64_encode_file(const char *filename);

/**
 * @brief Decode a base64 string.
 *
 * @param str The string to decode.
 * @param flen The length of the resulting data.
 *
 * @return The decoded data.
 * @warning The returned array must be freed.
 */
uint8_t *base64_decode(const char *str, size_t *flen);

/**
 * @brief Decode a base64 string from a file.
 *
 * @param filename The name of the file to decode.
 *
 * @return The decoded data.
 * @warning The returned array must be freed.
 * @see base64_decode
 */
uint8_t *base64_decode_file(const char *filename, size_t *flen);

/**
 * @brief Translate errors into human readable strings.
 *
 * @param err The error to translate.
 */
const char *crypto42_strerror(enum crypto_error err);

#endif

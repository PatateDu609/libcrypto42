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
 * @param min The minimum value of the range.
 * @param max The maximum value of the range.
 *
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

#endif

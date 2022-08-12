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

#endif

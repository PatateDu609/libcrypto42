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
#include <stdbool.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (sizeof(x) * 8 - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (sizeof(x) * 8 - (n))))

#define BSWAP16(x) ((ROTL(x, 8) & 0xFF00FF00) | (ROTR(x, 8) & 0x00FF00FF))

#define BSWAP32(x) (ROTL(x, 24) & 0xFF00FF00) | (ROTL(x, 8) & 0x00FF00FF) |\
					(ROTR(x, 8) & 0xFF00FF00) | (ROTR(x, 24) & 0x00FF00FF)

#define BSWAP64(x)	(ROTL(x, 56) & 0xFF00FF00) |\
					(ROTL(x, 40) & 0x00FF00FF) |\
					(ROTL(x, 24) & 0x0000FF00) |\
					(ROTL(x, 8) & 0x000000FF) |\
					(ROTR(x, 8) & 0xFF000000) |\
					(ROTR(x, 24) & 0x00FF0000) |\
					(ROTR(x, 40) & 0xFF000000) |\
					(ROTR(x, 56) & 0x000000FF)

#define BSWAP128(x) ((BSWAP64(x) << 64) | BSWAP64(x >> 64))

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
	uint8_t *data;			///< The data of the message.
	__uint128_t len;		///< The length of the data.
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
 * @brief Initialize a message structure from a string.
 *
 * @param str The string to initialize the message with.
 * @return A pointer to the message structure.
 */
struct msg *str_to_msg(const char *str) __hidden;

#endif
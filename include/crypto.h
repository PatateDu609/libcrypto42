/**
 * @file crypto.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief All the functions exposed to the user
 * @date 2022-08-08
 *
 * @warning All the functions in this file return malloc-ed strings that must be freed by the user.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdlib.h>


/* ************************* SHA2 related functions ************************* */

enum SHA2_ALG {
	SHA2_ALG_224,
	SHA2_ALG_256,
	SHA2_ALG_384,
	SHA2_ALG_512,
	SHA2_ALG_512_224,
	SHA2_ALG_512_256
};

/**
 * @brief Computes the SHA2 digest of the given string.
 *
 * @param alg The algorithm to use.
 * @param str The string to hash.
 * @return The SHA2 digest of the given string.
 */
char *sha2(enum SHA2_ALG alg, const char *input);

/**
 * @brief Computes the SHA2 digest of the given string and stores the result in the given buffer.
 *
 * @param alg The algorithm to use.
 * @param input The string to hash.
 * @param buf The buffer to store the result in.
 *
 * @return The given buffer.
 * @warning The given buffer must be at least `alg.digest_size` bytes long.
 */
uint8_t *sha2_raw(enum SHA2_ALG alg, const char *input, uint8_t *buf);

/**
 * @brief Computes the SHA2 digest of the given file.
 *
 * @param alg The algorithm to use.
 * @param path The path to the file to hash.
 * @return The SHA2 digest of the given file.
 */
char *sha2_bytes(enum SHA2_ALG alg, const uint8_t *input, size_t input_size);

/**
 * @brief Computes the SHA2 digest of the given array and stores the result in the given buffer.
 *
 * @param alg The algorithm to use.
 * @param input The array to hash.
 * @param input_size The size of the array.
 * @param buf The buffer to store the result in.
 *
 * @return The given buffer.
 * @see sha2_raw
 */
uint8_t *sha2_bytes_raw(enum SHA2_ALG alg, const uint8_t *input, size_t input_size, uint8_t *buf);

/**
 * @brief Computes the SHA2 digest of the given file.
 *
 * @param alg The algorithm to use.
 * @param path The path to the file to hash.
 * @return The SHA2 digest of the given file.
 */
char *sha2_file(enum SHA2_ALG alg, const char *filepath);

/**
 * @brief Computes the SHA2 digest of the given file and stores the result in the given buffer.
 *
 * @param alg The algorithm to use.
 * @param filepath The path to the file to hash.
 * @param buf The buffer to store the result in.
 *
 * @return The given buffer.
 * @see sha2_raw
 */
uint8_t *sha2_file_raw(enum SHA2_ALG alg, const char *filepath, uint8_t *buf);

/**
 * @brief Computes the SHA2 digest of a file pointed by the given file descriptor.
 *
 * @param alg The algorithm to use.
 * @param fd The file descriptor of the file to hash.
 * @return The SHA2 digest of the given string.
 */
char *sha2_descriptor(enum SHA2_ALG alg, int fd);

/**
 * @brief Computes the SHA2 digest of a file pointed by the given file descriptor
 * and stores the result in the given buffer.
 *
 * @param alg The algorithm to use.
 * @param fd The file descriptor of the file to hash.
 * @param buf The buffer to store the result in.
 *
 * @return The given buffer.
 * @see sha2_raw
 */
uint8_t *sha2_descriptor_raw(enum SHA2_ALG alg, int fd, uint8_t *buf);

/// Helper defines for the SHA2 functions above.
static inline char *sha2_224(const char *input) {
	return sha2(SHA2_ALG_224, input);
}

static inline char *sha2_256(const char *input) {
	return sha2(SHA2_ALG_256, input);
}

static inline char *sha2_384(const char *input) {
	return sha2(SHA2_ALG_384, input);
}

static inline char *sha2_512(const char *input) {
	return sha2(SHA2_ALG_512, input);
}

static inline char *sha2_512_224(const char *input) {
	return sha2(SHA2_ALG_512_224, input);
}

static inline char *sha2_512_256(const char *input) {
	return sha2(SHA2_ALG_512_256, input);
}

static inline uint8_t *sha2_224_raw(const char *input, uint8_t *buf) {
	return sha2_raw(SHA2_ALG_224, input, buf);
}

static inline uint8_t *sha2_256_raw(const char *input, uint8_t *buf) {
	return sha2_raw(SHA2_ALG_256, input, buf);
}

static inline uint8_t *sha2_384_raw(const char *input, uint8_t *buf) {
	return sha2_raw(SHA2_ALG_384, input, buf);
}

static inline uint8_t *sha2_512_raw(const char *input, uint8_t *buf) {
	return sha2_raw(SHA2_ALG_512, input, buf);
}

static inline uint8_t *sha2_512_224_raw(const char *input, uint8_t *buf) {
	return sha2_raw(SHA2_ALG_512_224, input, buf);
}

static inline uint8_t *sha2_512_256_raw(const char *input, uint8_t *buf) {
	return sha2_raw(SHA2_ALG_512_256, input, buf);
}

static inline char *sha2_224_bytes(const uint8_t *input, size_t input_size) {
	return sha2_bytes(SHA2_ALG_224, input, input_size);
}

static inline char *sha2_256_bytes(const uint8_t *input, size_t input_size) {
	return sha2_bytes(SHA2_ALG_256, input, input_size);
}

static inline char *sha2_384_bytes(const uint8_t *input, size_t input_size) {
	return sha2_bytes(SHA2_ALG_384, input, input_size);
}

static inline char *sha2_512_bytes(const uint8_t *input, size_t input_size) {
	return sha2_bytes(SHA2_ALG_512, input, input_size);
}

static inline char *sha2_512_224_bytes(const uint8_t *input, size_t input_size) {
	return sha2_bytes(SHA2_ALG_512_224, input, input_size);
}

static inline char *sha2_512_256_bytes(const uint8_t *input, size_t input_size) {
	return sha2_bytes(SHA2_ALG_512_256, input, input_size);
}

static inline uint8_t *sha2_224_bytes_raw(const uint8_t *input, size_t input_size, uint8_t *buf) {
	return sha2_bytes_raw(SHA2_ALG_224, input, input_size, buf);
}

static inline uint8_t *sha2_256_bytes_raw(const uint8_t *input, size_t input_size, uint8_t *buf) {
	return sha2_bytes_raw(SHA2_ALG_256, input, input_size, buf);
}

static inline uint8_t *sha2_384_bytes_raw(const uint8_t *input, size_t input_size, uint8_t *buf) {
	return sha2_bytes_raw(SHA2_ALG_384, input, input_size, buf);
}

static inline uint8_t *sha2_512_bytes_raw(const uint8_t *input, size_t input_size, uint8_t *buf) {
	return sha2_bytes_raw(SHA2_ALG_512, input, input_size, buf);
}

static inline uint8_t *sha2_512_224_bytes_raw(const uint8_t *input, size_t input_size, uint8_t *buf) {
	return sha2_bytes_raw(SHA2_ALG_512_224, input, input_size, buf);
}

static inline uint8_t *sha2_512_256_bytes_raw(const uint8_t *input, size_t input_size, uint8_t *buf) {
	return sha2_bytes_raw(SHA2_ALG_512_256, input, input_size, buf);
}

static inline char *sha2_224_file(const char *filepath) {
	return sha2_file(SHA2_ALG_224, filepath);
}

static inline char *sha2_256_file(const char *filepath) {
	return sha2_file(SHA2_ALG_256, filepath);
}

static inline char *sha2_384_file(const char *filepath) {
	return sha2_file(SHA2_ALG_384, filepath);
}

static inline char *sha2_512_file(const char *filepath) {
	return sha2_file(SHA2_ALG_512, filepath);
}

static inline char *sha2_512_224_file(const char *filepath) {
	return sha2_file(SHA2_ALG_512_224, filepath);
}

static inline char *sha2_512_256_file(const char *filepath) {
	return sha2_file(SHA2_ALG_512_256, filepath);
}

static inline uint8_t *sha2_224_file_raw(const char *filepath, uint8_t *buf) {
	return sha2_file_raw(SHA2_ALG_224, filepath, buf);
}

static inline uint8_t *sha2_256_file_raw(const char *filepath, uint8_t *buf) {
	return sha2_file_raw(SHA2_ALG_256, filepath, buf);
}

static inline uint8_t *sha2_384_file_raw(const char *filepath, uint8_t *buf) {
	return sha2_file_raw(SHA2_ALG_384, filepath, buf);
}

static inline uint8_t *sha2_512_file_raw(const char *filepath, uint8_t *buf) {
	return sha2_file_raw(SHA2_ALG_512, filepath, buf);
}

static inline uint8_t *sha2_512_224_file_raw(const char *filepath, uint8_t *buf) {
	return sha2_file_raw(SHA2_ALG_512_224, filepath, buf);
}

static inline uint8_t *sha2_512_256_file_raw(const char *filepath, uint8_t *buf) {
	return sha2_file_raw(SHA2_ALG_512_256, filepath, buf);
}

static inline char *sha2_224_descriptor(int fd) {
	return sha2_descriptor(SHA2_ALG_224, fd);
}

static inline char *sha2_256_descriptor(int fd) {
	return sha2_descriptor(SHA2_ALG_256, fd);
}

static inline char *sha2_384_descriptor(int fd) {
	return sha2_descriptor(SHA2_ALG_384, fd);
}

static inline char *sha2_512_descriptor(int fd) {
	return sha2_descriptor(SHA2_ALG_512, fd);
}

static inline char *sha2_512_224_descriptor(int fd) {
	return sha2_descriptor(SHA2_ALG_512_224, fd);
}

static inline char *sha2_512_256_descriptor(int fd) {
	return sha2_descriptor(SHA2_ALG_512_256, fd);
}

static inline uint8_t *sha2_224_descriptor_raw(int fd, uint8_t *buf) {
	return sha2_descriptor_raw(SHA2_ALG_224, fd, buf);
}

static inline uint8_t *sha2_256_descriptor_raw(int fd, uint8_t *buf) {
	return sha2_descriptor_raw(SHA2_ALG_256, fd, buf);
}

static inline uint8_t *sha2_384_descriptor_raw(int fd, uint8_t *buf) {
	return sha2_descriptor_raw(SHA2_ALG_384, fd, buf);
}

static inline uint8_t *sha2_512_descriptor_raw(int fd, uint8_t *buf) {
	return sha2_descriptor_raw(SHA2_ALG_512, fd, buf);
}

static inline uint8_t *sha2_512_224_descriptor_raw(int fd, uint8_t *buf) {
	return sha2_descriptor_raw(SHA2_ALG_512_224, fd, buf);
}

static inline uint8_t *sha2_512_256_descriptor_raw(int fd, uint8_t *buf) {
	return sha2_descriptor_raw(SHA2_ALG_512_256, fd, buf);
}

/* ************************** MD5 related functions ************************* */

/**
 * @brief Compute the md5 of a string given as parameter.
 *
 * @param str The string to compute the md5 of.
 * @return The md5 of the string.
 */
char *md5(const char *str);

/**
 * @brief Compute the md5 of a string given as parameter, but put the raw bytes in a given buffer.
 *
 * @param str The string to compute the md5 of.
 * @param output The buffer to put the raw bytes of the md5 in.
 *
 * @return A copy of the given buffer.
 *
 * @note The returned buffer is in raw bytes, and should be treated as a string.
 * @note The returned buffer must be at least of size MD5_DIGEST_LENGTH, or it may
 * end up by a SEGFAULT.
 */
uint8_t *md5_raw(const char *str, uint8_t *output);

/**
 * @brief Compute the md5 of a fixed length array of bytes given as parameter.
 *
 * @param bytes The array of bytes to compute the md5 of.
 * @param len The length of the array.
 * @return The md5 of the array.
 */
char *md5_bytes(const uint8_t *bytes, size_t len);

/**
 * @brief Compute the md5 of a fixed length array of bytes given as parameter,
 * but put the raw bytes in a given buffer.
 *
 * @param bytes The array of bytes to compute the md5 of.
 * @param len The length of the array.
 * @param output The buffer to put the raw bytes of the md5 in.
 *
 * @return A copy of the raw bytes of the md5 in the given buffer.
 *
 * @see md5_raw
 */
uint8_t *md5_bytes_raw(const uint8_t *bytes, size_t len, uint8_t *output);

/**
 * @brief Compute the md5 of a file given as parameter.
 *
 * @param filename The file to compute the md5 of.
 * @return The md5 of the file.
 */
char *md5_file(const char *filename);

/**
 * @brief Compute the md5 of a file given as parameter, but put the raw bytes in a given buffer.
 *
 * @param filename The file to compute the md5 of.
 * @param output The buffer to put the raw bytes of the md5 in.
 *
 * @return A copy of the output buffer.
 *
 * @see md5_raw
 */
uint8_t *md5_file_raw(const char *filename, uint8_t *output);

/**
 * @brief Compute the md5 of a file pointed by the file descriptor given as parameter.
 *
 * @param fd The file descriptor of the file to compute the md5 of.
 * @return The md5 of the pointed file.
 */
char *md5_descriptor(int fd);

/**
 * @brief Compute the md5 of a file pointed by the file descriptor given as parameter
 * but put the raw bytes in a given buffer.
 *
 * @param fd The file descriptor of the file to compute the md5 of.
 * @param output The buffer to put the raw bytes of the md5 in.
 *
 * @return A copy of the output buffer.
 *
 * @see md5_raw
 */
uint8_t *md5_descriptor_raw(int fd, uint8_t *output);

#endif /* CRYPTO_H */

/**
 * @file hmac.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief HMAC implementation
 * @date 2022-08-12
 *
 * @details This implementation is based on the pseudocode found in wikipedia.
 * But one could also use the code from the RFC.
 *
 * @see https://en.wikipedia.org/wiki/HMAC
 * @see https://tools.ietf.org/html/rfc2104
 */

#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Represents a hash function
 *
 * @param data The data to hash
 * @param len The length of the data to hash
 * @param key The key to use to hash the data
 *
 * @return The hash of the data
 *
 * @note The compatible functions can be found by looking every function that is suffixed with _bytes_raw.
 * @see crypto.h
 */
typedef uint8_t *(hash_function)(uint8_t *data, size_t size, uint8_t *buf);

/**
 * @brief Represents every hash algorithm that can be used for HMAC.
 */
enum hmac_algorithm
{
	HMAC_SHA2_224,
	HMAC_SHA2_256,
	HMAC_SHA2_384,
	HMAC_SHA2_512,
	HMAC_SHA2_512_224,
	HMAC_SHA2_512_256,
	HMAC_MD5
};

/**
 * @brief Represents a HMAC hash context.
 */
struct hmac_func
{
	hash_function *H;
	size_t b;
	size_t L;
};

/**
 * @brief Setup a hash function context.
 *
 * @param alg The hash function to use.
 */
struct hmac_func hmac_setup(enum hmac_algorithm alg);


struct hmac_req {
	struct hmac_func ctx;	///< The context used by HMAC.

	uint8_t *key;		///< The key to use for the HMAC algorithm
	size_t key_len;		///< The length of the key

	uint8_t *message;	///< The message to use for the HMAC algorithm
	size_t message_len;	///< The length of the message

	uint8_t *res_hmac;	///< The resulting HMAC stored in a buffer (defined by the user)
};

/**
 * @brief HMAC algorithm implementation
 *
 * @param req The HMAC request
 *
 * @return A pointer to the buffer storing the HMAC
 * @warning The hmac must be of sufficient size to store the result.
 */
uint8_t *hmac(struct hmac_req req);


#endif

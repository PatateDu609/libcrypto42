/**
 * @file pbkdf.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief PBKDF2 implementation based on the RFC 2898.
 * @date 2022-08-13
 */

#ifndef PBKDF_H
#define PBKDF_H

#include <stdint.h>
#include <stddef.h>

#include "hmac.h"

/**
 * @brief Represents a PBKDF2 instance.
 */
struct pbkdf2_hmac_req
{
	enum hmac_algorithm algo;	///< HMAC algorithm to use.

	uint8_t *password;			///< Password to use.
	size_t password_len;		///< Password length.

	uint8_t *salt;				///< Salt to use.
	size_t salt_len;			///< Salt length.

	uint32_t iterations;		///< Number of iterations.

	/**
	 * Length of the derived key in bytes, at most (2^32 - 1) * hLen,
	 * where hLen is the length in bytes of the hash function output.
	*/
	uint64_t dklen;
};

/**
 * @brief PBKDF2 implementation based on the RFC 2898, it uses HMAC.
 *
 * @param req PBKDF2 request.
 * @return The derived key.
 */
uint8_t *pbkdf2(struct pbkdf2_hmac_req req);

#endif

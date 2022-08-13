/**
 * @file hmac.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief HMAC implementation
 * @date 2022-08-12
 */

#include "crypto.h"
#include "hmac.h"
#include "libft.h"

/**
 * @brief Computes a block sized key ready to be used for the HMAC algorithm.
 *
 * @param block_key The block sized key to compute.
 * @param req The requested HMAC configuration.
 */
static void compute_key(uint8_t *block_key, struct hmac_req req)
{
	size_t start;

	if (req.key_len > req.ctx.b)
	{
		start = req.ctx.L;
		req.ctx.H(req.key, req.key_len, block_key);
	}
	else
	{
		start = req.key_len;
		ft_memcpy(block_key, req.key, req.key_len);
	}

	for (size_t i = start; i < req.ctx.b; i++)
		block_key[i] = 0;
}

struct hmac_func hmac_setup(enum hmac_algorithm alg)
{
	switch (alg)
	{
	case HMAC_SHA2_224:
		return (struct hmac_func){.H = (hash_function *)&sha2_224_bytes_raw, .b = 64, .L = 28};
	case HMAC_SHA2_256:
		return (struct hmac_func){.H = (hash_function *)&sha2_256_bytes_raw, .b = 64, .L = 32};
	case HMAC_SHA2_384:
		return (struct hmac_func){.H = (hash_function *)&sha2_384_bytes_raw, .b = 128, .L = 48};
	case HMAC_SHA2_512:
		return (struct hmac_func){.H = (hash_function *)&sha2_512_bytes_raw, .b = 128, .L = 64};
	case HMAC_SHA2_512_224:
		return (struct hmac_func){.H = (hash_function *)&sha2_512_224_bytes_raw, .b = 64, .L = 28};
	case HMAC_SHA2_512_256:
		return (struct hmac_func){.H = (hash_function *)&sha2_512_256_bytes_raw, .b = 64, .L = 32};
	case HMAC_MD5:
		return (struct hmac_func){.H = (hash_function *)&md5_bytes_raw, .b = 64, .L = 16};
	default:
		break;
	}
	return (struct hmac_func){.H = NULL, .b = 0, .L = 0};
}

/**
 * @brief Get constants for the hash function.
 *
 * @param H The hash function we want the constants for.
 * @param b The variable to store the block size in.
 * @param L The variable to store the output size in.
 */

uint8_t *hmac(struct hmac_req req)
{
	if (req.ctx.H == NULL || req.ctx.b == 0 || req.ctx.L == 0) // Invalid HMAC algorithm
		return NULL;

	uint8_t ipad[req.ctx.b];
	uint8_t opad[req.ctx.b];
	uint8_t key[req.ctx.b]; // Block sized key

	compute_key(key, req);

	for (size_t i = 0; i < req.ctx.b; i++)
	{
		// Arbitrary values chosen by the author to split the key in two halves.
		ipad[i] = key[i] ^ 0x36;
		opad[i] = key[i] ^ 0x5c;
	}

	{ // Compute the inner hash
		uint8_t tmp[sizeof ipad + req.message_len];
		ft_memcpy(tmp, ipad, sizeof ipad);
		ft_memcpy(tmp + sizeof ipad, req.message, req.message_len);
		req.ctx.H(tmp, sizeof ipad + req.message_len, req.res_hmac);
	}
	{ // Compute the outer hash
		uint8_t tmp[sizeof opad + req.ctx.L];
		ft_memcpy(tmp, opad, sizeof opad);
		ft_memcpy(tmp + sizeof opad, req.res_hmac, req.ctx.L);
		req.ctx.H(tmp, sizeof opad + req.ctx.L, req.res_hmac);
	}
	return req.res_hmac;
}

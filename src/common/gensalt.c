/**
 * @file gensalt.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief A simple implementation of a function to generate a salt.
 * @date 2022-08-18
 *
 */

#include "common.h"

uint8_t *gensalt(size_t len) {
	if (len == 0)
		return (NULL);

	uint8_t *salt = malloc(len);
	if (salt == NULL)
		return (NULL);
	for (size_t i = 0; i < len; i++) salt[i] = get_random_range(0, 255);
	return (salt);
}

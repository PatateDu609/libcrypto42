/**
 * @file rand.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief A cryptographycally safe random number generator.
 * @date 2022-08-14
 *
 * @note This implementation uses the /dev/urandom device
 */

#include "common.h"
#include <unistd.h>
#include <fcntl.h>

uint64_t get_random_range(uint64_t min, uint64_t max)
{
	uint64_t range = max - min;
	uint64_t random = get_random();

	return min + (random % range);
}


uint64_t get_random(void)
{
	uint64_t random = 0;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		return 0;

	read(fd, &random, sizeof random);
	close(fd);
	return random;
}

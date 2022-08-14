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

uint8_t *get_random_bytes_at(uint8_t *ptr, uint64_t length)
{
	for (uint64_t i = 0; i < length; i++)
		ptr[i] = get_random() & 0xFF;
	return ptr;
}

uint8_t *get_random_bytes(size_t len)
{
	uint8_t *bytes = malloc(len);
	if (!bytes)
		return NULL;
	return get_random_bytes_into(bytes, len);
}

char *get_random_string_at(char *ptr, uint64_t length)
{
	for (uint64_t i = 0; i < length; i++)
	{
		bool upper = get_random() & 1;
		ptr[i] = upper ? get_random_range('A', 'Z') : get_random_range('a', 'z');
	}
	ptr[length] = '\0';
	return ptr;
}

char *get_random_string(size_t len)
{
	char *str = malloc(len + 1);
	if (!str)
		return NULL;
	return get_random_string_at(str, len);
}

char *get_random_string_from(const char *charset, size_t len)
{
	char *str = malloc(len + 1);
	if (!str)
		return NULL;
	for (size_t i = 0; i < len; i++)
		str[i] = charset[get_random_range(0, strlen(charset))];
	str[len] = '\0';
	return str;
}

/**
 * @file crypto.h
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief All the functions exposed to the user
 * @date 2022-08-08
 *
 * @warning All the functions in this file return malloc-ed strings that must be freed by the user.
 */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stdlib.h>

/* ************************** MD5 related functions ************************* */

/**
 * @brief Compute the md5 of a string given as parameter.
 *
 * @param str The string to compute the md5 of.
 * @return The md5 of the string.
 */
char *md5(char *str);

/**
 * @brief Compute the md5 of a fixed length array of bytes given as parameter.
 *
 * @param bytes The array of bytes to compute the md5 of.
 * @param len The length of the array.
 * @return The md5 of the array.
 */
char *md5_bytes(uint8_t *bytes, size_t len);

/**
 * @brief Compute the md5 of a file given as parameter.
 *
 * @param filename The file to compute the md5 of.
 * @return The md5 of the file.
 */
char *md5_file(char *filename);

/**
 * @brief Compute the md5 of a file pointed by the file descriptor given as parameter.
 *
 * @param fd The file descriptor of the file to compute the md5 of.
 * @return The md5 of the pointed file.
 */
char *md5_descriptor(int fd);

#endif

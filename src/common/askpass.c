/**
 * @file askpass.c
 * @author Ghali Boucetta (gboucett@student.42.fr)
 * @brief Ask for a password without printing it to the terminal.
 * @date 2022-08-12
 */

#define _GNU_SOURC
#include "common.h"
#include "libft.h"
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <string.h>

#define BUFFER_SIZE 4096

/**
 * @brief Toggles the echoing to the terminal.
 *
 * @param echo True to enable echoing, false to disable.
 */
static void toggle_echo(bool echo)
{
	struct termios t;

	tcgetattr(STDIN_FILENO, &t);
	if (echo)
		t.c_lflag |= ECHO;
	else
		t.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

char *askpass(const char *prompt)
{
	printf("%s", prompt);
	fflush(stdout);

	toggle_echo(false);
	char buffer[BUFFER_SIZE + 1];
	char *pass = NULL;

	ssize_t ret;
	bool first = true;
	bool last = false;

	while (!last && (ret = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0)
	{
		buffer[ret] = '\0';

		char *r = strchr(buffer, '\n');
		if (r)
		{
			*r = '\0';
			last = true;
		}

		size_t new_size = (pass ? strlen(pass) : 0) + ret + 1;
		pass = realloc(pass, new_size);
		if (first)
		{
			pass[0] = 0;
			first = false;
		}
		if (!pass)
		{
			fprintf(stderr, "Error: Failed to allocate memory.\n");
			break;
		}
		strncat(pass, buffer, new_size);
	}

	toggle_echo(true);
	printf("\n");
	return pass;
}

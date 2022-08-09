#include "crypto.h"

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	char *str = argc > 1 ? argv[1] : "Hello World!";

	char *str_md5 = md5(str);
	printf("%s\n", str_md5);
	free(str_md5);
	return 0;
}
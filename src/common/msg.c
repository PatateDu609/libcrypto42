/**
 * @file msg.c
 * @author your name (you@domain.com)
 * @brief Set up the message structure.
 * @date 2022-08-09
 */

#include "common.h"
#include "libft.h"

struct msg *str_to_msg(const char *str)
{
	struct msg *msg = malloc(sizeof *msg);
	if (msg == NULL)
		return NULL;

	msg->len = ft_strlen(str);
	msg->data = malloc(msg->len * sizeof *msg->data);
	if (msg->data == NULL)
	{
		free(msg);
		return NULL;
	}
	ft_memcpy(msg->data, str, msg->len);

	return msg;
}
# Critical include to remove predefined Makefile variables.
include mkvars/conf.mk

TYPE							=	static
NAME							=	crypto42
LANGUAGE						=	C
COLORS							:=	256
DEBUG							:=	1
RELEASE							:=	0
OPT_CFLAGS						:=	-I./src

PATH_INC						=	include libft/include

include mkvars/init.mk
include mkvars/colors.mk
include mkvars/SRC.mk
include mkvars/tests.mk
include mkvars/rules.mk

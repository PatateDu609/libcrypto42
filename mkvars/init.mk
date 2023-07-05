ifndef NAME
$(error "NAME is not defined")
endif

ifndef TYPE
$(error "TYPE is not defined")
endif

ifndef LANGUAGE
$(error "LANGUAGE is not defined")
endif

VERBOSE				?=	0

DEBUG				?=	0
RELEASE				?=	1

LANGEXTENSION		=

ifeq ($(TYPE),static)
	LIBEXTENTION	=	.a
else ifeq ($(TYPE),shared)
	LIBEXTENTION	=	.so
endif

ifeq ($(LANGUAGE),C)
	LANGEXTENSION	=	.c
else ifeq ($(LANGUAGE),C++)
	LANGEXTENSION	=	.cpp
endif

ifneq ($TYPE,exec)
	NAME			:=	lib$(NAME)$(LIBEXTENTION)
endif

# These variables are editable by the user in the Makefile.
PATH_SRC			?=	src
PATH_OBJ			?=	obj
PATH_LIB			?=	lib
PATH_INC			?=	include

CC					?=	cc
AS					?=	nasm
AR					?=	ar
MAKE				?=	make -s
ECHO				?=	/bin/echo
RM					?=	rm -f
MKDIR				?=	mkdir -p
STRIP				?=	strip

NCC					:= $(CC)
NAS					:= $(AS)
NAR					:= $(AR)
NRM					:= $(RM)
NMKDIR				:= $(MKDIR)

STD					?=	-std=c11
OPT_CFLAGS			?=
CFLAGS				?=	-Wall -Wextra -Werror $(addprefix -I,$(PATH_INC)) $(STD) $(OPT_CFLAGS)
ARFLAGS				?=	rcs
ASFLAGS				?=

ifeq ($(shell $(NCC) --version | grep -oahr -m 1 'clang' | head -1 | tr -d '\n'),clang)
	CFLAGS			+=	-DHAVE_CLANG_COMPILER
else ifeq ($(shell $(NCC) --version | grep -oahr -m 1 'gcc' | head -1),gcc)
	CFLAGS			+=	-DHAVE_GCC_COMPILER
else ifeq ($(shell readlink -f $(NCC) | grep -o gcc),gcc)
	CFLAGS			+=	-DHAVE_GCC_COMPILER
else
	TARGET			!= $(error "unknown compiler, only clang and gcc are managed")
endif

ifeq ($(shell uname),Darwin)
	CFLAGS			+=	-I/opt/homebrew/include
	ECHO			:=	echo
else
	ECHO			:=	/bin/echo -e
endif

NECHO				:= $(ECHO)

ifeq ($(VERBOSE),0)
	CC				:=	@$(CC)
	AS				:=	@$(AS)
	AR				:=	@$(AR)
	ECHO			:=	@$(ECHO)
	RM				:=	@$(RM)
	MKDIR			:=	@$(MKDIR)
	MAKE			:=	@$(MAKE)
endif

ifeq ($(DEBUG),1)
	CFLAGS			+=	-g3 -O0 -DDEBUG -ggdb -fno-omit-frame-pointer -fdiagnostics-color=always
	ASFLAGS			+=	-g
endif

ifeq ($(RELEASE),1)
	CFLAGS			+=	-O2 -DRELEASE
endif

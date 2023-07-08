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
PRINTF				?=	printf
RM					?=	rm -f
MKDIR				?=	mkdir -p
STRIP				?=	strip

NCC					:= $(CC)
NAS					:= $(AS)
NPRINTF				:= $(PRINTF)
NAR					:= $(AR)
NRM					:= $(RM)
NMKDIR				:= $(MKDIR)

STD					?=	-std=c11
OPT_CFLAGS			?=
CFLAGS				?=	-Wall -Wextra -Werror $(addprefix -I,$(PATH_INC)) $(STD) $(OPT_CFLAGS)
ARFLAGS				?=	rcs
ASFLAGS				?=

COMPILER			:=	unknown
ifeq ($(shell $(NCC) --version | grep -o 'clang' | head -1 | tr -d '\n'),clang)
	CFLAGS			+=	-DHAVE_CLANG_COMPILER
	COMPILER		=	clang
else ifeq ($(shell $(NCC) --version | grep -oahr -m 1 'gcc' | head -1),gcc)
	CFLAGS			+=	-DHAVE_GCC_COMPILER
	COMPILER		=	gcc
else ifeq ($(shell readlink -f $(NCC) | grep -o gcc),gcc)
	CFLAGS			+=	-DHAVE_GCC_COMPILER
	COMPILER		=	gcc
else
	TARGET			!= $(error "unknown compiler, only clang and gcc are managed")
endif

ifeq ($(shell uname),Darwin)
	CFLAGS			+=	-I/opt/homebrew/include
endif

ifeq ($(VERBOSE),0)
	CC				:=	@$(CC)
	AS				:=	@$(AS)
	AR				:=	@$(AR)
	PRINTF			:=	@$(PRINTF)
	RM				:=	@$(RM)
	MKDIR			:=	@$(MKDIR)
	MAKE			:=	@$(MAKE)
endif

ifeq ($(DEBUG),1)
	CFLAGS			+=	-O0 -DDEBUG
	ifeq ($(COMPILER),gcc)
		CFLAGS			+=	-g3 -ggdb -fno-omit-frame-pointer -fdiagnostics-color=always
	else ifeq ($(COMPILER),clang)
		CFLAGS			+=	-g -glldb -fdebug-macro -fno-eliminate-unused-debug-types -fstandalone-debug
	endif
	ASFLAGS			+=	-g
endif

ifeq ($(RELEASE),1)
	CFLAGS			+=	-O2 -DRELEASE
endif

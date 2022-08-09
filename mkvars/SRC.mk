LANGEXTENSION			?=	.c

MD5_SRC_BASENAME		=	md5/md5							\
							md5/init						\
							md5/update						\
							md5/final						\

COMMON_SRC_BASENAME		=	common/blocks					\

BASENAME				:=	$(MD5_SRC_BASENAME)				\
							$(COMMON_SRC_BASENAME)

SRC						:=	$(addprefix $(PATH_SRC)/,\
								$(addsuffix $(LANGEXTENSION), $(BASENAME)))


OBJS					:=	$(addprefix $(PATH_OBJ)/, $(addsuffix .o, $(BASENAME)))
DEPS					:=	$(addprefix $(PATH_OBJ)/, $(addsuffix .d, $(BASENAME)))

undefine BASENAME
undefine MD5_SRC_BASENAME

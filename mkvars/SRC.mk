LANGEXTENSION			?=	.c

MD5_SRC_BASENAME			=	md5/md5							\
								md5/init						\
								md5/update						\
								md5/final						\

SHA2_SRC_BASENAME			=	sha2/sha2						\
								sha2/init						\
								sha2/update						\
								sha2/final						\

DES_SRC_BASENAME			=	DES/DES							\
								DES/key							\
								DES/permutation					\
								DES/round						\

COMMON_SRC_BASENAME			=	common/blocks					\
								common/askpass					\

CIPHER_MODE_SRC_BASENAME	=	block_cipher_modes/common					\
								block_cipher_modes/cbc						\
								block_cipher_modes/ecb						\
								# block_cipher_modes/cfb					\
								block_cipher_modes/ctr						\
								block_cipher_modes/ecb						\
								block_cipher_modes/ofb						\

BASENAME					:=	$(MD5_SRC_BASENAME)				\
								$(SHA2_SRC_BASENAME)			\
								$(COMMON_SRC_BASENAME)			\
								$(DES_SRC_BASENAME)				\
								$(CIPHER_MODE_SRC_BASENAME)		\
								hmac							\
								pbkdf							\
								base64							\

SRC							:=	$(addprefix $(PATH_SRC)/,\
									$(addsuffix $(LANGEXTENSION), $(BASENAME)))


OBJS						:=	$(addprefix $(PATH_OBJ)/, $(addsuffix .o, $(BASENAME)))
DEPS						:=	$(addprefix $(PATH_OBJ)/, $(addsuffix .d, $(BASENAME)))

undefine BASENAME
undefine MD5_SRC_BASENAME

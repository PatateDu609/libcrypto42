ifndef PATH_OBJ
$(error "PATH_OBJ is not defined")
endif

TEST_PATH		=	tests
TEST_NAME		=	test_crypto42
TEST_LANGUAGE	=	C
TEST_COLORS		=	256
TEST_DEBUG		=	1

TEST_SRC		=	tests/md5.c			\
					tests/registry.c	\

TEST_OBJ		=	$(addprefix $(PATH_OBJ)/, $(TEST_SRC:.c=.o))

TEST_CFLAGS		=	-Iinclude -Ilibft/include -Wall -Werror -Wextra
TEST_LDFLAGS	=	-L. -Llibft -lcrypto -lssl -lcrypto42 -lft -lcunit

$(PATH_OBJ)/%.o:	%.c
	$(MKDIR) $(dir $@)
	$(ECHO) -e " $(BOLD)$(MAGENTA)$(GREATER)$(NORMAL)   Compiling $(ITALIC)$(subst $(PATH_SRC)/,,$<)$(TRESET)"
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(TEST_NAME):		$(TEST_OBJ)
	$(ECHO) -e " $(BOLD)$(YELLOW)$(BIGGREATER)$(NORMAL)   Linking $(ITALIC)$(subst $(PATH_OBJ)/,,$@)$(TRESET)"
	$(CC) $(TEST_OBJ) -o $(TEST_NAME) $(TEST_LDFLAGS)

check:			$(TEST_NAME)
	@./$(TEST_NAME)
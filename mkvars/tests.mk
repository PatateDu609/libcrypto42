ifndef PATH_OBJ
$(error "PATH_OBJ is not defined")
endif

TEST_PATH			=	tests
TEST_NAME			=	test_crypto42
TEST_LANGUAGE		=	C
TEST_COLORS			=	256
TEST_DEBUG			=	1

TEST_SRC			=	$(shell find src -type f -name "*.test.c") $(shell find src/tests -type f -name "*.c")

TEST_OBJ			=	$(addprefix $(PATH_OBJ)/, $(subst $(PATH_SRC)/,,$(TEST_SRC:.c=.o)))

TEST_LDFLAGS		:=	-L. -Llibft -lcrypto -lssl -lcrypto42 -lft -lcriterion -lm

ifeq ($(shell uname),Darwin)
	TEST_LDFLAGS	+=	-L/opt/homebrew/lib
endif

$(TEST_NAME):		 CFLAGS	+= -Isrc/tests
$(TEST_NAME):		 CFLAGS	:= $(filter-out -Werror,$(CFLAGS))
$(TEST_NAME):		$(NAME) $(TEST_OBJ)
	$(MAKE) -C libft/
	$(PRINTF) " $(BOLD)$(YELLOW)$(BIGGREATER)$(NORMAL)   Linking $(ITALIC)$(subst $(PATH_OBJ)/,,$@)$(TRESET)\n"
	$(CC) $(TEST_OBJ) -o $(TEST_NAME) $(TEST_LDFLAGS)

check:				$(TEST_NAME)
	@./$(TEST_NAME) --full-stats --verbose

check_gdb:			$(TEST_NAME)
	@./$(TEST_NAME) --full-stats --verbose --debug=gdb

check_lldb:			$(TEST_NAME)
	@./$(TEST_NAME)	--full-stats --verbose --debug=lldb
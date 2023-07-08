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
ifeq ($(FILTER),)
	@./$(TEST_NAME) --full-stats --verbose
else
	@./$(TEST_NAME) --full-stats --verbose --filter=$(FILTER)
endif

check_gdb: DEBUGGER		:=	gdb
check_gdb: check_debug

check_lldb: DEBUGGER	:=	lldb
check_lldb: check_debug

check_debug_auto: $(TEST_NAME)
ifeq ($(FILTER),)
	@./$(TEST_NAME) --full-stats --verbose --debug
else
	@./$(TEST_NAME) --full-stats --verbose --filter=$(FILTER) --debug
endif

check_debug:			$(TEST_NAME)
	@if [ "$(DEBUGGER)" = "" ]; then \
		echo "DEBUGGER is unset for debugging rule"; \
  		exit 1; \
  	fi
ifeq ($(FILTER),)
	@./$(TEST_NAME) --full-stats --verbose --debug=$(DEBUGGER)
else
	@./$(TEST_NAME) --full-stats --verbose --filter=$(FILTER) --debug=$(DEBUGGER)
endif
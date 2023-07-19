ifndef PATH_OBJ
$(error "PATH_OBJ is not defined")
endif

TEST_PATH					=	tests
TEST_NAME					=	test_crypto42
TEST_COLORS					=	256
TEST_DEBUG					=	1

TEST_SRC					:=	$(shell find src -type f -name "*.test.cc") $(shell find src/tests -type f -name "*.cc")

TEST_OBJ					:=	$(addprefix $(PATH_OBJ)/, $(subst $(PATH_SRC)/,,$(TEST_SRC:.cc=.o)))

GTEST_FOLDER				:=	gtest
GTEST_BUILD_FOLDER			:=	$(GTEST_FOLDER)/build
GTEST_OUT_FOLDER			:=	$(GTEST_BUILD_FOLDER)/out
GTEST_LIB_FOLDER			:=	$(GTEST_OUT_FOLDER)/lib
GTEST_LIB					:=	$(GTEST_OUT_FOLDER)/lib/libgtest.a

TEST_LDFLAGS				:=	-L. -Llibft -lcrypto -lssl -lcrypto42 -lft -lm -L$(GTEST_LIB_FOLDER) -lgtest -lpthread

ifeq ($(shell uname),Darwin)
	TEST_LDFLAGS			+=	-L/opt/homebrew/lib
endif

$(GTEST_FOLDER):
	$(PRINTF) " $(MAGENTA_129)≫ Getting $(UNDERLINE)Google Test$(TRESET)\n"
	@git submodule update --remote
	$(MKDIR) -p $(GTEST_OUT_FOLDER)

$(GTEST_LIB):				$(GTEST_FOLDER)
	cd $(GTEST_BUILD_FOLDER) ; \
	pwd ; \
	$(NPRINTF) " $(GREEN_79)$(DOUBLEGREATER) Generating $(UNDERLINE)Google Test$(TRESET)\n" ; \
	cmake .. -DBUILD_GMOCK=OFF -DCMAKE_INSTALL_PREFIX=$(notdir $(GTEST_OUT_FOLDER)) ; \
	$(NPRINTF) " $(ORANGE)$(DOUBLEGREATER) Building $(UNDERLINE)Google Test$(TRESET)\n" ; \
	$(NMAKE) ; \
	$(NPRINTF) " $(GREEN_42)$(DOUBLEGREATER) Installing $(UNDERLINE)Google Test$(TRESET)\n" ; \
	$(NMAKE) install

$(TEST_NAME):		 CFLAGS	+= -Isrc/tests -I$(GTEST_OUT_FOLDER)/include
$(TEST_NAME):		 CFLAGS	:= $(filter-out -Werror,$(CFLAGS))
$(TEST_NAME):		$(GTEST_LIB) $(NAME) $(TEST_OBJ)
	$(MAKE) -C libft/
	$(PRINTF) " $(BOLD)$(YELLOW)$(BIGGREATER)$(NORMAL)   Linking $(ITALIC)$(subst $(PATH_OBJ)/,,$@)$(TRESET)\n"
	$(CXX) $(TEST_OBJ) -o $(TEST_NAME) $(TEST_LDFLAGS)

check:				$(TEST_NAME)
ifeq ($(FILTER),)
	@./$(TEST_NAME) --full-stats --verbose
else
	@./$(TEST_NAME) --full-stats --verbose --filter=$(FILTER)
endif

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
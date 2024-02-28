ifndef PATH_OBJ
$(error "PATH_OBJ is not defined")
endif

TEST_PATH					=	tests
TEST_NAME					=	test_crypto42
TEST_COLORS					=	256
TEST_DEBUG					=	1

TEST_SRC					:=	$(shell find src -type f -name "*.test.cc") $(shell find src/tests -type f -name "*.cc")

TEST_OBJ					:=	$(addprefix $(PATH_OBJ)/, $(subst $(PATH_SRC)/,,$(TEST_SRC:.cc=.o)))
DEPS						+=	$(addprefix $(PATH_OBJ)/, $(subst $(PATH_SRC)/,,$(TEST_SRC:.cc=.d)))

GTEST_FOLDER				:=	gtest
GTEST_BUILD_FOLDER			:=	$(GTEST_FOLDER)/build
GTEST_OUT_FOLDER			:=	$(GTEST_BUILD_FOLDER)/out
GTEST_LIB_FOLDER			:=	$(GTEST_OUT_FOLDER)/lib
GTEST_LIB					:=	$(GTEST_OUT_FOLDER)/lib/libgtest.a

TEST_LDFLAGS				:=	-L. -Llibft -lcrypto -lssl -lcrypto42 -lft -lm -L$(GTEST_LIB_FOLDER) -L$(GTEST_LIB_FOLDER)64 -lgtest -lpthread

ifeq ($(shell uname),Darwin)
	TEST_LDFLAGS			+=	-L/opt/homebrew/lib
endif

$(TEST_NAME):		 CFLAGS	+= -Isrc/tests -I$(GTEST_OUT_FOLDER)/include
$(TEST_NAME):		 CFLAGS	:= $(filter-out -Werror,$(CFLAGS))
$(TEST_NAME):		$(GTEST_LIB) $(NAME) $(TEST_OBJ)
	$(MAKE) -C libft/
	$(PRINTF) " $(BOLD)$(YELLOW)$(BIGGREATER)$(NORMAL)   Linking $(ITALIC)$(subst $(PATH_OBJ)/,,$@)$(TRESET)\n"
	$(CXX) $(TEST_OBJ) -o $(TEST_NAME) $(TEST_LDFLAGS)

check:				$(TEST_NAME)
	@./$(TEST_NAME) --full-stats --verbose

$(GTEST_FOLDER):
	$(PRINTF) " $(MAGENTA_129)≫ Getting $(UNDERLINE)Google Test$(TRESET)\n"
	@git submodule update --remote
	$(MKDIR) -p $(GTEST_OUT_FOLDER)

$(GTEST_LIB):				$(GTEST_FOLDER)
	$(MKDIR) -p $(GTEST_BUILD_FOLDER)
	@cd $(GTEST_BUILD_FOLDER) ; \
	pwd ; \
	$(NPRINTF) " $(GREEN_79)$(DOUBLEGREATER) Generating $(UNDERLINE)Google Test$(TRESET)\n" ; \
	cmake .. -DBUILD_GMOCK=OFF -DCMAKE_INSTALL_PREFIX=$(notdir $(GTEST_OUT_FOLDER)) ; \
	$(NPRINTF) " $(ORANGE)$(DOUBLEGREATER) Building $(UNDERLINE)Google Test$(TRESET)\n" ; \
	$(NMAKE) ; \
	$(NPRINTF) " $(GREEN_42)$(DOUBLEGREATER) Installing $(UNDERLINE)Google Test$(TRESET)\n" ; \
	$(NMAKE) install

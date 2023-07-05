ifndef SRC
$(error "SRC is not defined")
endif

ifndef OBJS
$(error "OBJS is not defined")
endif

ifndef DEPS
$(error "DEPS is not defined")
endif

all:							$(NAME) $(TEST_NAME)

$(PATH_OBJ)/%.o:			$(PATH_SRC)/%$(LANGEXTENSION)
	$(MKDIR) $(dir $@)

	$(ECHO) " $(BOLD)$(if $(filter $(shell echo $< | grep 'tests/' ; echo $$?),1),$(if $(filter $(shell echo $< | grep -E '\.test\.c' ; echo $$?),0),$(MAGENTA),$(BLUE)),$(CYAN))"
	$(ECHO) "$(GREATER)$(NORMAL)   Compiling $(ITALIC)$(subst $(PATH_SRC)/,,$<)$(TRESET)"

	$(CC) $(CFLAGS) -c -MMD $< -o $@


-include $(DEPS)

$(NAME):						$(OBJS)
ifeq ($(TYPE),exec)

	$(ECHO) " $(BOLD)$(GREEN)$(BIGGREATER)$(NORMAL)   Linking $(ITALIC)$(subst $(PATH_OBJ)/,,$@)$(TRESET)"
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

else ifeq ($(TYPE),static)

	$(ECHO) " $(BOLD)$(GREEN)$(BIGGREATER)$(NORMAL)   Creating $(ITALIC)$(subst $(PATH_LIB)/,,$@)$(TRESET)"
	$(AR) $(ARFLAGS) $@ $(OBJS)

else ifeq ($(TYPE),shared)

	$(ECHO) " $(BOLD)$(GREEN)$(BIGGREATER)$(NORMAL)   Creating $(ITALIC)$(subst $(PATH_LIB)/,,$@)$(TRESET)"
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS)

endif

re:								fclean all

fclean:							clean
	$(RM) $(NAME)
	$(RM) -r $(PATH_OBJ)

clean:
	$(RM) $(OBJS)
	$(RM) $(DEPS)

info:							test_colors info_vars

test_colors:
	$(ECHO) "Testing colors..."
	$(ECHO) "$(RED)RED$(TRESET)"
	$(ECHO) "$(GREEN)GREEN$(TRESET)"
	$(ECHO) "$(YELLOW)YELLOW$(TRESET)"
	$(ECHO) "$(BLUE)BLUE$(TRESET)"
	$(ECHO) "$(MAGENTA)MAGENTA$(TRESET)"
	$(ECHO) "$(CYAN)CYAN$(TRESET)"

	$(ECHO) "$(UNDERLINE)UNDERLINE$(TRESET)"
	$(ECHO) "$(BOLD)BOLD$(TRESET)\n"


info_vars:
	$(ECHO) "Displaying variables..."
	@($(NECHO) "CC:$(CC)";																\
	$(NECHO) "AS:$(AS)";																\
	$(NECHO) "AR:$(AR)";																\
	$(NECHO) "RM:$(RM)";																\
	$(NECHO) "MKDIR:$(MKDIR)";															\
	$(NECHO) "ECHO:$(ECHO)";															\
	$(NECHO);																			\
	\
	$(NECHO) "NCC:$(NCC)";																\
	$(NECHO) "NAS:$(NAS)";																\
	$(NECHO) "NAR:$(NAR)";																\
	$(NECHO) "NRM:$(NRM)";																\
	$(NECHO) "NMKDIR:$(NMKDIR)";														\
	$(NECHO) "NECHO:$(NECHO)";															\
	$(NECHO);																			\
	\
	$(NECHO) "PATH_SRC:$(PATH_SRC)";													\
	$(NECHO) "PATH_OBJ:$(PATH_OBJ)";													\
	$(NECHO) "PATH_LIB:$(PATH_LIB)";													\
	$(NECHO) "PATH_INC:$(PATH_INC)";													\
	$(NECHO);																			\
	\
	$(NECHO) "CFLAGS:$(CFLAGS)";														\
	$(NECHO) "ARFLAGS:$(ARFLAGS)";														\
	$(NECHO) "ASFLAGS:$(ASFLAGS)";														\
	$(NECHO);																			\
	\
	$(NECHO) "NAME:$(NAME)";															\
	$(NECHO) "TYPE:$(TYPE)";															\
	$(NECHO) "LANGUAGE:$(LANGUAGE)";													\
	$(NECHO) "COLORS:$(COLORS)";														\
	$(NECHO);																			\
	\
	$(NECHO) "VERBOSE:$(VERBOSE)";														\
	$(NECHO) "DEBUG:$(DEBUG)";															\
	$(NECHO) "RELEASE:$(RELEASE)";														\
	$(NECHO);																			\
	\
	$(NECHO) "SRC:$(SRC)";																\
	$(NECHO) "OBJS:$(OBJS)";															\
	$(NECHO) "DEPS:$(DEPS)"																\
	) | awk '																			\
		{																				\
			input = $$0;																\
			split(input, x, ":");														\
			printf "$(BOLD)$(RED)""%-15s""$(CRESET)""%s""$(CRESET)\n", x[1], x[2]		\
		}'

.PHONY: all info info_vars test_colors clean fclean re
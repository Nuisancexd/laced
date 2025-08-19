ifeq ($(OS),Windows_NT)
    include Makefile.win
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        include Makefile.linux
    endif
endif

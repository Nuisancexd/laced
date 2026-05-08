ifeq ($(OS),Windows_NT)
    include Makefile.win
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        UNAME_M := $(shell uname -m)
        ifeq ($(UNAME_M),armv7l)
            include Makefile_arm.linux # ARM make
        else
            include Makefile.linux
        endif
    endif
endif

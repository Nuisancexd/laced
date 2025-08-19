CC = g++
CFLAGS = -m32 -O3 -std=c++20 -DNDEBUG -fsanitize=address -pthread
LDFLAGS = -lssl -lcrypto 
SRC = main.cpp threadpool.cpp api.cpp logs.cpp memory.cpp global_parameters.cpp CommandParser.cpp pathsystem.cpp locker.cpp filesystem.cpp chacha20/laced.cpp sha/sha256.cpp aes/aes256.cpp base64/base64.cpp rsa/rsa.cpp
OBJ = $(SRC:.cpp=.o)
EXEC = laced

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXEC) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)

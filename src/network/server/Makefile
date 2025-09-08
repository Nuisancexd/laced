CC = g++
CFLAGS = -I ../asio/asio/include -m32 -O3 -std=c++20 -DNDEBUG -fsanitize=address
LDFLAGS = -lssl -lcrypto 
SRC = server.cpp ../../logs.cpp ../../threadpool.cpp ../../CommandParser.cpp ../../memory.cpp ../../global_parameters.cpp ../../api.cpp ../../locker.cpp ../../filesystem.cpp ../../chacha20/laced.cpp ../../sha/sha256.cpp ../../aes/aes256.cpp ../../base64/base64.cpp ../../rsa/rsa.cpp ../port_scanner.cpp
#SRC = server.cpp
OBJ = $(SRC:.cpp=.o)
EXEC = laced_server

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXEC) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)

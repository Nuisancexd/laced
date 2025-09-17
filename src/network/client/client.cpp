
#include <iostream>
#define ASIO_STANDALONE
#include <asio.hpp>

#include "client.h"
#include "../protocol.h"


using asio::ip::tcp;

#include "../../logs.h"
#include "../../memory.h"
#include "../../rsa/rsa.h"
#include "../../filesystem.h"
#include "../../sha/sha256.h"

class client : public Protocol
{
    asio::io_context io_ctx;
    tcp::resolver resolver;
    tcp::socket socket;
    std::vector<char> vec;
    size_t len_read = 0;
public:

    client(const char* ip, const char* port) :
            resolver(io_ctx),
            socket(io_ctx)
    {
        if(std::atoi(port) < 1)
            throw std::invalid_argument("PORT FAILED");

        asio::connect(socket, resolver.resolve(ip, port));
        LOG_SUCCESS("CONNECTED");

        if(!setup_connect_client(socket))
            throw std::runtime_error("[setup_connect_client] failed");

        while(true)
        {
            std::string s;
            std::getline(std::cin, s);
            if(s == "exit")
                break;
            sign_and_send(socket, (char*)s.c_str(), s.size());
        }
    }
    ~client()
    {
        rsa::del_session_key(session);
    }

private:
};

void init_client()
{
    try
    {
        client client("127.0.0.1", "12345");
    }
    catch(std::exception& ex)
    {
        LOG_ERROR("%s", ex.what());
    }
}


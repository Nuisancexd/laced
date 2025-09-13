
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

#define VERSIO_PROTOCOL 1.0


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
        printf("\033[0;29m");

        if(!read(socket, vec, len_read))
            printf("FAIlED");
        
        memcpy(nonce.get(), (BYTE*)vec.data(), 32);
        LOG_INFO("GENERATE SESSION KEY");
        generate_session_key();
        LOG_INFO("HASH NONCE");
        hash_nonce_();
        LOG_INFO("SIGNATURE NONCE");
        auto pair = signature_nonce();
        LOG_INFO("SEND PUB KEY");
        send(socket, (char*)session->pub_key, session->pub_len);
        LOG_INFO("SEND SIGNATURE OF NONCE");
        send(socket, (char*)pair.first, pair.second);

        while(true);
    
    }
    ~client()
    {
        if(session)
        {
            memory::memzero_explicit(session->prv_key, session->prv_len);
            memory::memzero_explicit(session->pub_key, session->pub_len);
            memory::m_free(session->prv_key);
            memory::m_free(session->pub_key);
        }
    }
};

void init_client()
{
    try
    {
        client client("127.0.0.1", "12345");
    }
    catch(std::exception& ex)
    {
        printf("%s\n", ex.what());
    }
}


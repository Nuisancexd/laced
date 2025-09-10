
#include <iostream>
#define ASIO_STANDALONE
#include <asio.hpp>

#include "client.h"

using asio::ip::tcp;

#include "../../logs.h"
#include "../../memory.h"
#include "../../rsa/rsa.h"
#include "../../filesystem.h"
#include "../../sha/sha256.h"


#define VERSIO_PROTOCOL 1.0

class GenerateProtocol
{
    PSESSION_KEY session = NULL;
public:
    BYTE* nonce = NULL;
    BYTE* sig_nonce = NULL;
    GenerateProtocol()
    {
        nonce = (BYTE*)memory::m_malloc(32);
    }
    ~GenerateProtocol()
    {
        if(session)
            rsa::del_session_key(session);
        if(nonce)
            memory::m_free(nonce);
    }

    void generate_session_key()
    {
        session = rsa::gen_session_key(false, 2048);
        for(int i = 0; i < 10; ++i)
            printf("%02X", session->pub_key[i]);
    }

    bool signature_nonce()
    {
        if(!session)
        {
            LOG_ERROR("[CLIENT] [sig_nonce] missing session keys");
            return false;
        }
        BYTE* hash_out = (BYTE*)memory::m_malloc(32);
        sha256(nonce, 32, hash_out);
        sig_nonce = rsa::signature(hash_out, session->prv_key, session->prv_len);
        return sig_nonce ? true : false; 
    }
};

class client : public GenerateProtocol
{
    asio::io_context io_ctx;
    tcp::resolver resolver;
    tcp::socket socket;
    std::array<BYTE, 1024> data;
public:

    client(const char* ip, const char* port) :
            resolver(io_ctx),
            socket(io_ctx)
    {
        if(std::atoi(port) < 1)
            throw std::invalid_argument("PORT FAILED");

        asio::connect(socket, resolver.resolve(ip, port));
        LOG_SUCCESS("CONNECTED");
        reader();
        signature_nonce();
        printf("NONCE\n");
        for(int i = 0; i < 32; ++i)
            printf("%02X", data[i]);

        //generate_session_key();
        while(true)
        {
            if(!send(NULL))
                break;
        }
    }
    ~client()
    {

    }

    bool reader()
    {
        memory::memzero_explicit(data.data(), 1024);
        asio::error_code error;
        size_t length = socket.read_some(asio::buffer(data), error);
        if (error == asio::error::eof) 
        {
            LOG_INFO("[CLIENT]");
            return false;
        }
        else if(error)
        {
            LOG_ERROR("[CLIENT]");
            return false;
        }
        LOG_SUCCESS("[CLIENT] getting: %s", data.data());
        return true;
    }

    bool send(char* strsend)
    {
        if(strsend)
        {
            asio::write(socket, asio::buffer(std::string(strsend)));
            return true;
        }
        std::string str;
        std::getline(std::cin, str);
        if(str == std::string("exit"))
            return false;
        asio::write(socket, asio::buffer(str));
        return true;
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
#include <iostream>
#include <optional>
#include <vector>
#include <csignal>
#include <thread>

#include "server.h"

#define ASIO_STANDALONE
#include <asio.hpp>
using asio::ip::tcp;

#include "../../logs.h"
#include "../../memory.h"
#include "../../rsa/rsa.h"

class GenerateProtocol
{
    PSESSION_KEY session = NULL;
public:
    BYTE* nonce = NULL;
    GenerateProtocol()
    {
        
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

    bool generate_nonce()
    {
        nonce = (BYTE*)memory::m_malloc(33);
        if(!RAND_bytes(nonce, 32))
        {
            LOG_ERROR("[rand_bytes] failed");
            return false;
        }
        return true;
    }
};

class server : public GenerateProtocol
{
    int port = -1;
    int cc = 0;
    std::array<char, 1024> data{};
    std::atomic<bool> doneman = true;

    asio::io_context io_ctx;
    tcp::acceptor accept;
    tcp::socket sock;
    asio::signal_set signals;

    tcp::socket connect()
    {
        while(doneman)
        {
            try
            {
                LOG_INFO("WAIT CONNECT");
                if(!doneman)
                    break;
                tcp::socket socket(io_ctx);
                accept.accept(socket);

                LOG_SUCCESS("CONNECTED; %s : %u", socket.remote_endpoint().address().to_string().c_str(), socket.remote_endpoint().port());
                return socket;
            }
            catch(std::exception& ex)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if(!doneman)
                    break;
                LOG_ERROR("[SERVER] Connection failed: %s", ex.what());
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        return tcp::socket(io_ctx);
    }

    void setup_signal_handling() 
    {
        signals.async_wait([this](const asio::error_code& error, int signal_number) 
        {
            if (!error) 
            {
                LOG_SUCCESS("[SERVER] EXIT_SUCCESS");
                doneman = false;
                asio::error_code ec;
                sock.close(ec);
                accept.close(ec);
            }
        });
    }

    void run_io()
    {
        try
        {
            io_ctx.run();
        }
        catch (const std::exception& ex) 
        {
            LOG_ERROR("io_context exception: %s", ex.what());
        }
    }

public:
    server(int port_) : 
            accept(io_ctx, tcp::endpoint(tcp::v4(), port_)), 
            sock(io_ctx), 
            signals(io_ctx, SIGINT, SIGTERM)
    {
        if(port_ < 1)
            throw std::invalid_argument("PORT FAILED");

        std::jthread io_thread(&server::run_io, this);
        port = port_;
        setup_signal_handling();
        //generate_session_key();
        sock = connect();
        if(generate_nonce())
            send((char*)nonce);
        else
            LOG_ERROR("[SERVER] failed send nonce");
        run();
    }

    ~server()
    {
        asio::error_code ec;
        sock.close(ec);
        accept.close(ec);
    }

    void run()
    {
        while(doneman)
        {
            if(!doneman)
                break;
            if(!reader())
                sock = connect();
        }
    }

    bool reader()
    {
        memory::memzero_explicit(data.data(), 1024);
        asio::error_code error;
        size_t length = sock.read_some(asio::buffer(data), error);
        if (error == asio::error::eof) 
        {
            LOG_INFO("[SERVER] Client Exit");
            return false;
        }
        else if(error)
        {
            LOG_ERROR("[SERVER] read error");
            return false;
        }
        LOG_SUCCESS("[SERVER] getting: %s", data.data());
        return true;
    }

    bool send(char* msg)
    {
        LOG_INFO("mst to send %s", nonce);
        sock.write_some(asio::buffer(std::string(msg)));
        return true;
    }
};

void init_server()
{
    try
    {
        server server(12345);        
    } 
    catch(std::exception& e)
    {
        LOG_ERROR(e.what());
    }
}
#include <iostream>
#include <optional>
#include <vector>
#include <csignal>
#include <thread>

#include "server.h"
#include "../protocol.h"

#define ASIO_STANDALONE
#include <asio.hpp>
using asio::ip::tcp;

#include "../../logs.h"
#include "../../memory.h"
#include "../../rsa/rsa.h"
#include "../../sha/sha256.h"

class server : public Protocol
{
    int port = -1;
    int cc = 0;
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
        sock = connect();

        if(generate_nonce())
        {
            send(sock, (char*)nonce.get(), 32);
            LOG_SUCCESS("send nonce");
            printf("\033[0;29m");
        }
        else
            LOG_ERROR("[SERVER] failed send nonce");

        read(sock, data, size_pkc);
        pub_key_client = init_uniq(reinterpret_cast<BYTE*>(data.data()), size_pkc);
        read(sock, data, size_sign);
        signature = init_uniq(reinterpret_cast<BYTE*>(data.data()), size_sign);

        if(!verify_sign(signature.get(), size_sign, 
                pub_key_client.get(), size_pkc))
        {
            LOG_ERROR("FAILED VERIFYED SIGNATURE");
        }
        else
        {
            generate_session_key();
            send(sock, reinterpret_cast<char*>(session->pub_key), session->pub_len);
        }


    }

    ~server()
    {
        if(session)
        {
            memory::memzero_explicit(session->prv_key, session->prv_len);
            memory::memzero_explicit(session->pub_key, session->pub_len);
            memory::m_free(session->prv_key);
            memory::m_free(session->pub_key);
            delete session;
        }
        asio::error_code ec;
        sock.close(ec);
        accept.close(ec);
    }

private:
    std::vector<char> data;
    size_t size_data = 0;
    std::unique_ptr<BYTE[]> pub_key_client;
    size_t size_pkc;
    // void run()
    // {
    //     while(doneman)
    //     {
    //         std::vector<char> vec;
    //         size_t len = 0;
    //         if(!reader(sock, vec, len))
    //             sock = connect();

    //         //procc_data
    //     }
    // }
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
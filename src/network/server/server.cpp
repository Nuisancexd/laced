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

    void run()
    {
        while(doneman)
        {
            sock = connect();
            if(!doneman)
                break;
            if(!setup_connect_server(sock))
                continue;

            while(receive_and_verify(sock, data, size_data, pub_key_client.get(), size_pkc));
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
        run();
    }

    ~server()
    {
        rsa::del_session_key(session);
        asio::error_code ec;
        sock.close(ec);
        accept.close(ec);
    }

private:
    std::vector<char> data;
    size_t size_data = 0;
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
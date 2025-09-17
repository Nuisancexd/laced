#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#define ASIO_STANDALONE
#include <asio.hpp>

#include "../logs.h"
#include "../memory.h"
#include "../rsa/rsa.h"
#include "../sha/sha256.h"

using asio::ip::tcp;


class Sample
{
public:
    template<typename T>
    std::unique_ptr<T[]> init_uniq(T* copy, size_t size)
    {
        if(size == 0) return nullptr;
        if(copy == nullptr) throw std::invalid_argument("init_uniq failed, pointer null");
        auto array = std::make_unique<T[]>(size);
        memory::memzero_explicit(array.get(), size * sizeof(T));
        memcpy(array.get(), copy, size * sizeof(T));
        return array;
    }
};  

class NetworkBase
{
private:
    bool read_ex(tcp::socket& socket, void* data, size_t length);
public:
    virtual ~NetworkBase() = default;
    NetworkBase(){}
    bool send(tcp::socket& socket, char* strsend, size_t size_send);
    bool read(tcp::socket& socket, std::vector<char>& vec, size_t& length);
};

class Protocol : public Sample, public NetworkBase
{
public:
    
    bool generate_nonce();
    void generate_session_key();
    bool verify_sign(BYTE* signature, size_t sign_len, BYTE* pub_key, size_t key_len);
    std::pair<std::unique_ptr<BYTE[]>, unsigned> signature_nonce();
    void set_hash_nonce();
    bool sign_and_send(tcp::socket& socket, char* send, size_t send_size);
    bool receive_and_verify(tcp::socket& socket, std::vector<char>& data, size_t size_data, BYTE* public_key, size_t pubkey_sz);
    bool setup_connect_client(tcp::socket& socket);
    bool setup_connect_server(tcp::socket& socket);

    Protocol()
    {
        nonce = std::make_unique<BYTE[]>(size_nonce);
        hash_nonce = std::make_unique<BYTE[]>(size_nonce);
    }
    ~Protocol()
    {

    }
    PSESSION_KEY session = NULL;
    std::unique_ptr<BYTE[]> nonce;
    std::unique_ptr<BYTE[]> hash_nonce;
    std::unique_ptr<BYTE[]> signature;
    std::unique_ptr<BYTE[]> sig_nonce;
    std::unique_ptr<BYTE[]> pub_key_server;
    std::unique_ptr<BYTE[]> pub_key_client;
    size_t size_pkc;
    size_t size_pks;
    size_t size_sign;
    static constexpr size_t size_nonce = 32;
};


#endif
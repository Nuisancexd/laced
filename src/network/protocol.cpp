#include "protocol.h"

#include <iostream>

/* NETWPRK_BASE */

bool NetworkBase::read_ex(tcp::socket& socket, void* data, size_t length)
{
    size_t total_read = 0;
    asio::error_code error;
    while (total_read < length)
    {
        size_t bytes = socket.read_some(
            asio::buffer(static_cast<char*>(data) + total_read, length - total_read), 
            error);
        
        if (error || bytes == 0)
        {
            LOG_ERROR("[read_error] %s", error.message().c_str());
            return false;
        } 
            
        total_read += bytes;
    }
    return total_read == length;
}

bool NetworkBase::read(tcp::socket& socket, std::vector<char>& vec, size_t& length)
{
    if(!read_ex(socket, &length, sizeof(length)))
        return false;
    vec.resize(length);
    if(!read_ex(socket, vec.data(), length))
        return false;
    return true;
}


bool NetworkBase::send(tcp::socket& socket, char* strsend, size_t size_send)
{
    try
    {
        if (size_send > std::numeric_limits<uint32_t>::max()) 
        {
           LOG_ERROR("Message too large");
            return false;
        }

        LOG_INFO("LEN TO SEND: %u", size_send);
        asio::write(socket, asio::buffer(&size_send, sizeof(size_t)));
        
        if(size_send > 0 && strsend)
            asio::write(socket, asio::buffer(strsend, size_send));

        return true;
    }
    catch (const std::system_error& e) 
    {
        LOG_ERROR("Network error: %s", e.what());
        return false;
    } catch (const std::exception& e) 
    {
        LOG_ERROR("Send error: %s", e.what());
        return false;
    }
}



/* PROTOCOL */

void Protocol::set_hash_nonce()
{
    sha256(nonce.get(), 32, hash_nonce.get());
}

bool Protocol::generate_nonce()
{
    if(!RAND_bytes(nonce.get(), size_nonce))
    {
        LOG_ERROR("[generate_nonce] [rand_bytes] failed");
        return false;
    }
    sha256(nonce.get(), size_nonce, hash_nonce.get());
    return true;
}

void Protocol::generate_session_key()
{
    session = rsa::gen_session_key(false, 2048);
}

bool Protocol::verify_sign(BYTE* signature, size_t sign_len, BYTE* pub_key, size_t key_len)
{
    if(!signature)
    {
        LOG_ERROR("[verify_sign] missing signature");
        return false;
    }
    else if(!pub_key)
    {
        LOG_ERROR("[verify_sign] missing pub key");
        return false;
    }
    return rsa::verify(hash_nonce.get(), signature, sign_len, pub_key, key_len);
}


std::pair<std::unique_ptr<BYTE[]>, unsigned> Protocol::signature_nonce()
{
    if(!session->prv_key)
    {
        LOG_ERROR("[CLIENT] [sig_nonce] missing session keys");
        return {nullptr, 0};
    }
    else if(!hash_nonce)
    {
        LOG_ERROR("[CLIENT] [sig_nonce] missing hash nonce");
        return {nullptr, 0};
    }
    
    return rsa::signature(hash_nonce.get(), session->prv_key, session->prv_len);
}


bool Protocol::sign_and_send(tcp::socket& socket, char* send_msg, size_t send_size)
{
    if(!session)
        return false;
    BYTE msg_hash[32];
    sha256(reinterpret_cast<BYTE*>(send_msg), send_size, msg_hash);
    auto pair = rsa::signature(msg_hash, session->prv_key, session->prv_len);
    if(!pair.first)
        return false;

    if(!send(socket, reinterpret_cast<char*>(pair.first.get()), pair.second)
        || !send(socket, send_msg, send_size))
        return false;

    return true;
}

bool Protocol::receive_and_verify
(
    tcp::socket& socket,
    std::vector<char>& data,
    size_t size_data,
    BYTE* public_key,
    size_t pubkey_sz
)
{
    if(!session)
        return false;
    
    BYTE hash[32];
    std::vector<char> vec_sign;
    size_t sign_sz;
    if(!read(socket, vec_sign, sign_sz)
        || !read(socket, data, size_data))
        return false;

    sha256(reinterpret_cast<BYTE*>(data.data()), size_data, hash);
    if(!rsa::verify(hash, reinterpret_cast<BYTE*>(vec_sign.data()), sign_sz, public_key, pubkey_sz))
        return false;
    data.push_back('\0');
    LOG_INFO("[SERVER] %s", data.data());
    return true;
}


bool Protocol::setup_connect_client(tcp::socket& socket)
{
    std::vector<char> vec;
    size_t size_read;
    if(!read(socket, vec, size_read))
        return false;
    memcpy(nonce.get(), reinterpret_cast<BYTE*>(vec.data()), size_read);
    generate_session_key();
    if(!session)
        return false;
    set_hash_nonce();
    auto pair = signature_nonce();
    if(!pair.first)
        return false;
    if(!send(socket, reinterpret_cast<char*>(session->pub_key), session->pub_len)
        || !send(socket, reinterpret_cast<char*>(pair.first.get()), pair.second))
        return false;
    if(!read(socket, vec, size_pks))
        return false;
    pub_key_server = init_uniq(reinterpret_cast<BYTE*>(vec.data()), size_pks);
    if(!read(socket, vec, size_sign))
        return false;
    signature = init_uniq(reinterpret_cast<BYTE*>(vec.data()), size_sign);

    if(!verify_sign(signature.get(), size_sign, pub_key_server.get(), size_pks))
        return false;

    return true;
}

bool Protocol::setup_connect_server(tcp::socket& socket)
{
    std::vector<char> vec;
    if(!generate_nonce() 
        || !send(socket, reinterpret_cast<char*>(nonce.get()), size_nonce))
        return false;

    if(!read(socket, vec, size_pkc))
        return false;
    pub_key_client = init_uniq(reinterpret_cast<BYTE*>(vec.data()), size_pkc);

    if(!read(socket, vec, size_sign))
        return false;
    signature = init_uniq(reinterpret_cast<BYTE*>(vec.data()), size_sign);

    if(!verify_sign(signature.get(), size_sign, pub_key_client.get(), size_pkc))
        return false;
        
    generate_session_key();
    if(!session)
        return false;
    if(!send(socket, reinterpret_cast<char*>(session->pub_key), session->pub_len))
        return false;
    
    auto pair = signature_nonce();
    if(!pair.first)
        return false;
    if(!send(socket, reinterpret_cast<char*>(pair.first.get()), pair.second))
        return false;

    return true;
}
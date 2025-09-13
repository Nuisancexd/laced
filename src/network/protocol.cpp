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
            LOG_ERROR("read error %s", error.message().c_str());
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


bool NetworkBase::send(tcp::socket& socket, char* strsend, unsigned size_send)
{
    try
    {
        if (size_send > std::numeric_limits<uint32_t>::max()) 
        {
           LOG_ERROR("Message too large");
            return false;
        }

        LOG_INFO("LEN TO SEND: %u", size_send);
        asio::write(socket, asio::buffer(&size_send, sizeof(unsigned)));
        
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

bool Protocol::hash_nonce_()
{
    sha256(nonce.get(), 32, hash_nonce.get());
    return true;
}

bool Protocol::generate_nonce()
{
    if(!RAND_bytes(nonce.get(), size_nonce))
    {
        LOG_ERROR("[rand_bytes] failed");
        return false;
    }
    sha256(nonce.get(), 32, hash_nonce.get());
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


std::pair<BYTE*, unsigned> Protocol::signature_nonce()
{
    if(!session->prv_key)
    {
        LOG_ERROR("[CLIENT] [sig_nonce] missing session keys");
        return {NULL, 0};
    }
    else if(!hash_nonce)
    {
        LOG_ERROR("[CLIENT] [sig_nonce] missing hash nonce");
        return {NULL, 0};
    }
    return rsa::signature(hash_nonce.get(), session->prv_key, session->prv_len);
    //auto sig_nonce = rsa::signature(hash_nonce, session->prv_key, session->prv_len);
    //return sig_nonce ? true : false;
}


bool Protocol::sign_and_send()
{
    return false; /*TODO*/
}

bool Protocol::receive_and_verify()
{
    return false; /*TODO*/
}

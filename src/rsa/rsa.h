#ifndef _RSA_H_
#define _RSA_H_

#include "../filesystem.h"


#ifdef _WIN32

bool HandlerGenKeyPairRSA();
bool HandleError(NTSTATUS status);
#endif

#ifdef __linux
#include <openssl/pem.h>
#include <openssl/bio.h>


typedef struct alignas(32) session_key
{
	BYTE* pub_key;
	BYTE* prv_key;
    unsigned prv_len;
    unsigned pub_len;
	bool base;
}SESSION_KEY, *PSESSION_KEY;


/*RSA API*/

bool HandlerGenKeyPairRSA();
void err();

namespace rsa
{
    bool EncryptRSA(BIO* bio, EVP_PKEY* pkey, EVP_PKEY_CTX* ctx, BYTE* buffer_encrypt, size_t* bencrypt_size, BYTE** buffer);
    bool DecryptRSA(BIO* bio, EVP_PKEY* pkey, EVP_PKEY_CTX* ctx, BYTE* buffer_decrypt, size_t* bdecrypt_size, BYTE** buffer);
    PSESSION_KEY gen_session_key(bool base, unsigned bit);
    void del_session_key(PSESSION_KEY session);
    BYTE* signature(BYTE* hash, BYTE* private_key_data, unsigned key_len);
    bool verify(BYTE* hash);
}

#endif

#endif
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



/*RSA API*/

bool HandlerGenKeyPairRSA();
void err();

namespace rsa
{
    bool EncryptRSA(BIO* bio, EVP_PKEY* pkey, EVP_PKEY_CTX* ctx, BYTE* buffer_encrypt, size_t* bencrypt_size, BYTE** buffer);
    bool DecryptRSA(BIO* bio, EVP_PKEY* pkey, EVP_PKEY_CTX* ctx, BYTE* buffer_decrypt, size_t* bdecrypt_size, BYTE** buffer);
}

#endif

#endif
#ifndef LACED_HPP
#define LACED_HPP

#ifdef __cplusplus

extern "C"

{
#endif

    //#include "ecrypt-portable.h"
#include <stdint.h>
#define CHACHA_BLOCKLENGTH 64

    typedef struct
    {
        //u32 input[16];
        uint32_t input[16];
    } laced_ctx;

    void ECRYPT_init(void);
    void ECRYPT_encrypt_bytes(laced_ctx* x, const uint8_t* m, uint8_t* c, uint32_t bytes);
    void ECRYPT_keysetup(laced_ctx* x, const uint8_t* k, uint32_t kbits);
    void ECRYPT_ivsetup(laced_ctx* x, const uint8_t* iv);

#ifdef __cplusplus 

}

#endif

#endif

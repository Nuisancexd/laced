#include <stdio.h>
#include <stddef.h>


#include "macro.h"

namespace crypto
{
    void generate_master_key(BYTE** master_key);
    void output_master_key();
    BYTE* get_master_key_hex(const char* master_key, size_t size);
    BYTE* get_master_key_base(const char* master_key, size_t size);
    void load_public_root_key(BYTE** g_PublicKeyRoot, size_t* size);
    void load_private_root_key(BYTE** g_PrivateKeyRoot, size_t* size);
    void load_root_symmetric_key(BYTE** g_RootKey);
}
#ifndef _AES_256_H_
#define _AES_256_H_

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <stdio.h>

#include "../macro.h"

#undef INLINE
#define INLINE inline

typedef uint32_t u32;
typedef uint8_t u8;

constexpr u32 AES_MAX_KEYLENGTH_U32 = 60;
constexpr u32 AES_KEYSIZE_256 = 32;
constexpr u32 ROUNDS_256 = 14;
constexpr u32 KEY_WORDS = 8;
constexpr u32 AES_BLOCK_SIZE = 16;

enum MODE_AES
{
	AES_CRYPT = 8,
	AES_DECRYPT = 9,
	AES_CRYPT_NO_PADDING = 10,
	AES_DECRYPT_NO_PADDING = 11
};



struct crypto_aes_ctx
{
	u32 key_enc[AES_MAX_KEYLENGTH_U32];
	u32 key_dec[AES_MAX_KEYLENGTH_U32];
	u32 padding;
};



VOID aes_expandkey(crypto_aes_ctx* ctx, CONST u8* in_key);
VOID aes_encrypt(crypto_aes_ctx* ctx, u8* out, CONST u8* in);
VOID aes_decrypt(crypto_aes_ctx* ctx, u8* out, CONST u8* in);
BOOL aes256(u8* out, CONST u8* in, u8* key, u32 mode);
u32 aes256_padding(u32 bytes);
VOID aes_encrypt_blocks(crypto_aes_ctx* ctx, CONST u8* in, u8* out, u32 bytes, u32* size_padding, u32 mode);
VOID aes_init();


#endif

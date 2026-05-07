#ifndef ECRYPT_SYNC
#define ECRYPT_SYNC

#ifdef __cplusplus
extern "C" {
#endif


#include "ecrypt-portable.h"


#define ECRYPT_NAME "laced"
#define ECRYPT_PROFILE "_____"


#define ECRYPT_MAXKEYSIZE 256                 
#define ECRYPT_KEYSIZE(i) (128 + (i)*128)     

#define ECRYPT_MAXIVSIZE 64                   
#define ECRYPT_IVSIZE(i) (64 + (i)*64)        

      /* ------------------------------------------------------------------------- */

      /* Data structures */

      /*
       * ECRYPT_ctx is the structure containing the representation of the
       * internal state of your cipher.
       */
    typedef struct
    {
        u32 input[16];
        
    } laced_ctx;


    void ECRYPT_init();

    /*
     * Key setup. It is the user's responsibility to select the values of
     * keysize and ivsize from the set of supported values specified
     * above.
     */
    void ECRYPT_keysetup(
        laced_ctx* ctx,
        const u8* key,
        u32 keysize,                /* Key size in bits. */
        u32 ivsize);                /* IV size in bits. */

    /*
     * IV setup. After having called ECRYPT_keysetup(), the user is
     * allowed to call ECRYPT_ivsetup() different times in order to
     * encrypt/decrypt different messages with the same key but different
     * IV's.
     */
    void ECRYPT_ivsetup(
        laced_ctx* ctx,
        const u8* iv);

   
    void ECRYPT_encrypt_bytes(
        laced_ctx* ctx,
        const u8* plaintext,
        u8* ciphertext,
        u32 msglen);                /* Message length in bytes. */

    void ECRYPT_decrypt_bytes(
        laced_ctx* ctx,
        const u8* ciphertext,
        u8* plaintext,
        u32 msglen);                /* Message length in bytes. */

   

#define ECRYPT_GENERATES_KEYSTREAM
#ifdef ECRYPT_GENERATES_KEYSTREAM

    void ECRYPT_keystream_bytes(
        laced_ctx* ctx,
        u8* keystream,
        u32 length);                /* Length of keystream in bytes. */

#endif

    /* ------------------------------------------------------------------------- */

    /* Optional optimizations */

    /*
     * By default, the functions in this section are implemented using
     * calls to functions declared above. However, you might want to
     * implement them differently for performance reasons.
     */

     /*
      * All-in-one encryption/decryption of (short) packets.
      *
      * The default definitions of these functions can be found in
      * "ecrypt-sync.c". If you want to implement them differently, please
      * undef the ECRYPT_USES_DEFAULT_ALL_IN_ONE flag.
      */
#define ECRYPT_USES_DEFAULT_ALL_IN_ONE        /* [edit] */

    void ECRYPT_encrypt_packet(
        laced_ctx* ctx,
        const u8* iv,
        const u8* plaintext,
        u8* ciphertext,
        u32 msglen);

    void ECRYPT_decrypt_packet(
        laced_ctx* ctx,
        const u8* iv,
        const u8* ciphertext,
        u8* plaintext,
        u32 msglen);

    /*
     * Encryption/decryption of blocks.
     *
     * By default, these functions are defined as macros. If you want to
     * provide a different implementation, please undef the
     * ECRYPT_USES_DEFAULT_BLOCK_MACROS flag and implement the functions
     * declared below.
     */

#define ECRYPT_BLOCKLENGTH 64                 

#define ECRYPT_USES_DEFAULT_BLOCK_MACROS      
#ifdef ECRYPT_USES_DEFAULT_BLOCK_MACROS

#define ECRYPT_encrypt_blocks(ctx, plaintext, ciphertext, blocks)  \
  ECRYPT_encrypt_bytes(ctx, plaintext, ciphertext,                 \
    (blocks) * ECRYPT_BLOCKLENGTH)

#define ECRYPT_decrypt_blocks(ctx, ciphertext, plaintext, blocks)  \
  ECRYPT_decrypt_bytes(ctx, ciphertext, plaintext,                 \
    (blocks) * ECRYPT_BLOCKLENGTH)

#ifdef ECRYPT_GENERATES_KEYSTREAM

#define ECRYPT_keystream_blocks(ctx, keystream, blocks)            \
  ECRYPT_keystream_bytes(ctx, keystream,                        \
    (blocks) * ECRYPT_BLOCKLENGTH)

#endif

#else

    void ECRYPT_encrypt_blocks(
        ECRYPT_ctx* ctx,
        const u8* plaintext,
        u8* ciphertext,
        u32 blocks);                /* Message length in blocks. */

    void ECRYPT_decrypt_blocks(
        ECRYPT_ctx* ctx,
        const u8* ciphertext,
        u8* plaintext,
        u32 blocks);                /* Message length in blocks. */

#ifdef ECRYPT_GENERATES_KEYSTREAM

    void ECRYPT_keystream_blocks(
        ECRYPT_ctx* ctx,
        const u8* keystream,
        u32 blocks);                /* Keystream length in blocks. */

#endif

#endif

    /*
     * If your cipher can be implemented in different ways, you can use
     * the ECRYPT_VARIANT parameter to allow the user to choose between
     * them at compile time (e.g., gcc 
     
     ECRYPT_VARIANT=3 ...). Please
     * only use this possibility if you really think it could make a
     * significant difference and keep the number of variants
     * (ECRYPT_MAXVARIANT) as small as possible (definitely not more than
     * 10). Note also that all variants should have exactly the same
     * external interface (i.e., the same ECRYPT_BLOCKLENGTH, etc.).
     */
#define ECRYPT_MAXVARIANT 1                   /* [edit] */

#ifndef ECRYPT_VARIANT
#define ECRYPT_VARIANT 1
#endif

#if (ECRYPT_VARIANT > ECRYPT_MAXVARIANT)
#error this variant does not exist
#endif


#ifdef __cplusplus
}
#endif
/* ------------------------------------------------------------------------- */

#endif

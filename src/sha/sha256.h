#ifndef _SHA_256_H_
#define _SHA_256_H_


#undef STATIC
#undef VOID
#undef CONST
#undef INLINE

#define STATIC static
#define VOID void
#define CONST const
#define INLINE inline

typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;

constexpr u32 SHA256_BLOCK_SIZE = 64;
constexpr u32 SHA256_DIGEST_SIZE = 32;


struct sha256_state
{
	u32 state[SHA256_DIGEST_SIZE / 4];
	u64 count;
	u8 buf[SHA256_BLOCK_SIZE];
};

STATIC INLINE VOID sha256_init(sha256_state* sctx)
{
	sctx->state[0] = 0x6a09e667UL;
	sctx->state[1] = 0xbb67ae85UL;
	sctx->state[2] = 0x3c6ef372UL;
	sctx->state[3] = 0xa54ff53aUL;
	sctx->state[4] = 0x510e527fUL;
	sctx->state[5] = 0x9b05688cUL;
	sctx->state[6] = 0x1f83d9abUL;
	sctx->state[7] = 0x5be0cd19UL;
	sctx->count = 0;
}

VOID sha256(CONST u8* data, u32 len, u8* out);

VOID sha256_init_context(sha256_state* ctx);
VOID sha256_update_context(sha256_state* ctx, CONST u8* data, u32 len);
VOID sha256_final_context(sha256_state* ctx, u8* out);

#endif
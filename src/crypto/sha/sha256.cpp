#include "sha256.h"

#include <cstdlib>
#include <cstring>

STATIC CONST u32 SHA256_K[] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

STATIC INLINE u32 Ch(u32 x, u32 y, u32 z)
{
	return z ^ (x & (y ^ z));
}

STATIC INLINE u32 Maj(u32 x, u32 y, u32 z)
{
	return (x & y) | (z & (x | y));
}

STATIC INLINE unsigned rol32(unsigned x, unsigned y)
{
	return x << y | x >> (32 - y);
}

STATIC INLINE unsigned ror32(unsigned x, unsigned y)
{
	return rol32(x, 32 - y);
}

STATIC INLINE unsigned e0(unsigned x)
{
	return ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22);
}

STATIC INLINE unsigned e1(unsigned x)
{
	return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25);
}

STATIC INLINE unsigned s0(unsigned x)
{
	return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3);
}

STATIC INLINE unsigned s1(unsigned x)
{
	return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10);
}


STATIC INLINE VOID LOAD_OP(int I, u32* W, CONST u8* input)
{
	u32 value = static_cast<u32>(input[4 * I + 0]) << 24 |
		static_cast<u32>(input[4 * I + 1]) << 16 |
		static_cast<u32>(input[4 * I + 2]) << 8 |
		static_cast<u32>(input[4 * I + 3]);
	W[I] = value;
}

STATIC INLINE VOID BLEND_OP(int I, u32* W)
{
	W[I] = s1(W[I - 2]) + W[I - 7] + s0(W[I - 15]) + W[I - 16];
}


INLINE VOID SHA256_ROUND(u32 i, u32& a, u32& b, u32& c, u32& d, u32& e, u32& f, u32& g, u32& h, u32* W)
{
	u32 t1{}, t2{};
	t1 = h + e1(e) + Ch(e, f, g) + SHA256_K[i] + W[i];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
}


STATIC VOID sha256_transform(u32* state, CONST u8* input, u32* W)
{
	u32 a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i += 8)
	{
		LOAD_OP(i + 0, W, input);
		LOAD_OP(i + 1, W, input);
		LOAD_OP(i + 2, W, input);
		LOAD_OP(i + 3, W, input);
		LOAD_OP(i + 4, W, input);
		LOAD_OP(i + 5, W, input);
		LOAD_OP(i + 6, W, input);
		LOAD_OP(i + 7, W, input);
	}

	for (i = 16; i < 64; i += 8)
	{
		BLEND_OP(i + 0, W);
		BLEND_OP(i + 1, W);
		BLEND_OP(i + 2, W);
		BLEND_OP(i + 3, W);
		BLEND_OP(i + 4, W);
		BLEND_OP(i + 5, W);
		BLEND_OP(i + 6, W);
		BLEND_OP(i + 7, W);
	}

	a = state[0];  b = state[1];  c = state[2];  d = state[3];
	e = state[4];  f = state[5];  g = state[6];  h = state[7];

	for (i = 0; i < 64; i += 8)
	{
		SHA256_ROUND(i + 0, a, b, c, d, e, f, g, h, W);
		SHA256_ROUND(i + 1, h, a, b, c, d, e, f, g, W);
		SHA256_ROUND(i + 2, g, h, a, b, c, d, e, f, W);
		SHA256_ROUND(i + 3, f, g, h, a, b, c, d, e, W);
		SHA256_ROUND(i + 4, e, f, g, h, a, b, c, d, W);
		SHA256_ROUND(i + 5, d, e, f, g, h, a, b, c, W);
		SHA256_ROUND(i + 6, c, d, e, f, g, h, a, b, W);
		SHA256_ROUND(i + 7, b, c, d, e, f, g, h, a, W);
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}


INLINE VOID secure_memset(u32* W, size_t len)
{
	volatile u32* ptr = W;
	while (len--) *ptr++ = 0;
}

STATIC VOID sha256_transform_blocks(struct sha256_state* sctx, CONST u8* input, int blocks)
{
	u32 W[64];

	do {
		sha256_transform(sctx->state, input, W);
		input += SHA256_BLOCK_SIZE;
	} while (--blocks);

	secure_memset(W, 64);
}

STATIC VOID sha256_update(sha256_state* ctx, CONST u8* data, u32 len)
{
	u32 part = ctx->count % SHA256_BLOCK_SIZE;
	ctx->count += len;

	if (part + len >= SHA256_BLOCK_SIZE)
	{
		int blocks;
		if (part)
		{
			int p = SHA256_BLOCK_SIZE - part;
			memcpy(ctx->buf + part, data, p);
			data += p;
			len -= p;

			sha256_transform_blocks(ctx, ctx->buf, 1);
		}

		blocks = len / SHA256_BLOCK_SIZE;
		len %= SHA256_BLOCK_SIZE;

		if (blocks)
		{
			sha256_transform_blocks(ctx, data, blocks);
			data += blocks * SHA256_BLOCK_SIZE;
		}

		part = 0;
	}

	if (len)
		memcpy(ctx->buf + part, data, len);
}

INLINE VOID memzero_explicit(sha256_state* ctx)
{
	volatile char* ptr = (volatile char*)ctx;
	for (size_t i = 0; i < sizeof(ctx); ++i)
		ptr[i] = 0;
}

STATIC VOID sha256_final(sha256_state* ctx, u8* out, u32 digest_size)
{
	CONST int bit_offset = SHA256_BLOCK_SIZE - sizeof(u64);
	u64* bits = (u64*)(ctx->buf + bit_offset);
	u32 part = ctx->count % SHA256_BLOCK_SIZE;
	ctx->buf[part++] = 0x80;

	if (part > bit_offset)
	{
		memset(ctx->buf + part, 0x0, SHA256_BLOCK_SIZE - part);
		part = 0;

		sha256_transform_blocks(ctx, ctx->buf, 1);
	}

	memset(ctx->buf + part, 0x0, bit_offset - part);
	u64 bitlen = ctx->count << 3;
	*bits = ctx->count << 3;
	ctx->buf[63] = bitlen & 0xff;
	ctx->buf[62] = (bitlen >> 8) & 0xff;
	ctx->buf[61] = (bitlen >> 16) & 0xff;
	ctx->buf[60] = (bitlen >> 24) & 0xff;
	ctx->buf[59] = (bitlen >> 32) & 0xff;
	ctx->buf[58] = (bitlen >> 40) & 0xff;
	ctx->buf[57] = (bitlen >> 48) & 0xff;
	ctx->buf[56] = (bitlen >> 56) & 0xff;

	sha256_transform_blocks(ctx, ctx->buf, 1);

	for (size_t i = 0; i < 4; ++i)
	{
		out[i] = (ctx->state[0] >> (24 - i * 8)) & 0xff;
		out[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
		out[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
		out[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
		out[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
		out[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
		out[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
		out[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
	}
	memzero_explicit(ctx);
}

VOID sha256(CONST u8* data, u32 len, u8* out)
{
	sha256_state ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, out, 32);
}

VOID sha256_init_context(sha256_state* ctx)
{
	sha256_init(ctx);
}

VOID sha256_update_context(sha256_state* ctx, CONST u8* data, u32 len)
{
	sha256_update(ctx, data, len);
}

VOID sha256_final_context(sha256_state* ctx, u8* out)
{
	sha256_final(ctx, out, 32);
}
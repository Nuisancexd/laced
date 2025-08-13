#include "base64.h"

#include <cstddef>
#include <cstring>
#include <cstdio>

typedef int (*FindIndexFunc)(unsigned char smb); 


static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char dec_table[256] = {0};

static int index_ch(unsigned char src)
{
	for(int i = 0; i < 64; ++i)
	{
		if(src == base64_table[i])
			return i;
	}
	return -1;
}

static int index_ch_table(unsigned char src)
{
	return dec_table[src];
}

FindIndexFunc FuncIF = (FindIndexFunc)index_ch;
void base64::init_table_base64_decode()
{
	for(int i = 0; i < 256; ++i) 
		dec_table[i] = -1;
	for(int i = 0; i < 64; ++i)
		dec_table[(unsigned char)base64_table[i]] = i;

	FuncIF = (FindIndexFunc)index_ch_table;
}

int base64::base64_encode(const unsigned char* src, unsigned len, char* dst)
{
    unsigned in_bytes = 0;
	int bits = 0;
	char* p = dst;

	for (int i = 0; i < len; ++i) 
    {
		in_bytes = (in_bytes << 8) | src[i]; 
		bits += 8;
		do 
        {
			bits -= 6;
			*dst++ = base64_table[(in_bytes >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits)
    {
		*dst++ = base64_table[(in_bytes << (6 - bits)) & 0x3f];
		bits -= 6;
	}
	while (bits < 0)
    {
		*dst++ = '=';
		bits += 2;
	}

	return dst - p;
}


int base64::base64_decode(const unsigned char* src, size_t len, char* dst)
{
    unsigned in_bytes = 0;
	int bits = 0;
	int i;
	char *pd = dst;

	for (i = 0; i < len; ++i) 
	{
		int indx = FuncIF(src[i]);

		if (src[i] == '=') 
		{
			for (++i; i < len; ++i)
        		if (src[i] != '=')
            		return -1;
    		break;
		}
		if (indx == -1) return -1;

		in_bytes = (in_bytes << 6) | indx;
		bits += 6;
		if (bits >= 8) 
		{
			bits -= 8;
			*pd++ = (unsigned char)(in_bytes >> bits);
		}
	}
	if (in_bytes & ((1 << bits) - 1))
		return -1;
	return pd - dst;
}


bool base64::base64(BASE_E e, const unsigned char* src, unsigned len, char* dst, int* bsize)
{
	if(e == BASE_E::ENCODE)
		*bsize = base64_encode(src, len, dst);
	else if(e == BASE_E::DECODE)
		*bsize = base64_decode(src, len, dst);
	else
		return false;

	return *bsize != -1 ? true : false;
}
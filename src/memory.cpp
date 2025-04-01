#include "memory.h"
#include <cstring>


VOID memory::Copy(PVOID pDst, CONST PVOID pSrc, size_t size)
{
	void* tmp = pDst;
	size_t wordsize = sizeof(size_t);
	unsigned char* _src = (unsigned char*)pSrc;
	unsigned char* _dst = (unsigned char*)pDst;
	size_t len;
	for (len = size / wordsize; len--; _src += wordsize, _dst += wordsize)
		*(size_t*)_dst = *(size_t*)_src;

	len = size % wordsize;
	while (len--)
		*_dst++ = *_src++;
}

#define HASHING_SEED 24759
#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
#define LowerChar(C) if (C >= 'A' && C <= 'Z') {C = C + ('a'-'A');}

unsigned int memory::MurmurHash2A(const void* key, int len)
{
	char temp[64];
	memset(temp, 0, 64);	
	memory::Copy(temp, (PVOID)key, len);

	for (int i = 0; i < len; i++) {
		LowerChar(temp[i]);
	}

	const unsigned int m = 0x5bd1e995;
	const int r = 24;
	unsigned int l = len;

	const unsigned char* data = (const unsigned char*)temp;

	unsigned int h = HASHING_SEED;
	unsigned int k;

	while (len >= 4)
	{
		k = *(unsigned int*)data;

		mmix(h, k);

		data += 4;
		len -= 4;
	}

	unsigned int t = 0;

	switch (len)
	{
	case 3: t ^= data[2] << 16;
	case 2: t ^= data[1] << 8;
	case 1: t ^= data[0];
	};

	mmix(h, t);
	mmix(h, l);

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}


int memory::my_stoi(const char* str)
{
	unsigned int strLen = memory::StrLen(str);
	int num = 0;
	int ten;
	for (int i = 0; i < strLen; ++i)
	{
		ten = 1;
		for (unsigned int j = 0; j < strLen - 1 - i; ++j)
		{
			ten *= 10;
		}

		num += ten * (str[i] - '0');
	}

	return num;
}

int memory::my_stoi2(char* str) {
	unsigned int strLen = 0;
	unsigned int i = 0;
	while (str[i] != '\0') {
		strLen += 1;
		i++;
	}

	int num = 0;
	int ten;
	BOOL signFlag = TRUE; //true: +, false: -
	for (i = 0; i < strLen; i++) {
		if (str[i] < '0' || str[i] > '9') {
			if (i == 0 && str[i] == '-') {
				signFlag = FALSE;
				continue;
			}
			if (i == 0 && str[i] == '+') {
				signFlag = TRUE;
				continue;
			}

			return 0;
		}

		ten = 1;
		for (unsigned int j = 0; j < strLen - 1 - i; j++) {
			ten *= 10;
		}

		num += ten * (str[i] - '0');
	}

	if (signFlag) {
		return num;
	}
	else {
		return -num;
	}
}


PVOID memory::m_malloc(size_t size)
{
	PVOID buf = malloc(size);
	if (buf)
	{
		memset(buf, 0, size);
	}
	return buf;
}

VOID memory::m_free(PVOID memory)
{
	if (memory)
		free(memory);
}


size_t memory::StrLen(const char* Str)
{
	size_t Length = 0;
	while (*Str)
	{
		Length++;
		Str++;
	}

	return Length;
}


size_t memory::StrLen(const wchar_t* Str)
{
	size_t Length = 0;
	while (*Str)
	{
		Length++;
		Str++;
	}

	return Length;
}

const char* memory::FindChar(const char* Str, char Ch)
{
	while (*Str)
	{
		if (*Str == Ch)
		{
			return Str;
		}
		Str++;
	}

	return NULL;
}
size_t memory::FindCharWI(const wchar_t* Str, wchar_t Ch)
{
	size_t Length = 0;
	while (*Str)
	{
		++Length;
		if (*Str == Ch)
		{
			return Length;
		}
		++Str;
	}
	return 0;
}

const wchar_t* memory::FindCharW(const wchar_t* Str, wchar_t Ch)
{
	while (*Str)
	{
		if (*Str == Ch)
		{
			return Str;
		}
		Str++;
	}
	return NULL;
}


BOOL memory::StrStrC(const char* Str, const char* StrEq)
{
	if (StrLen(Str) != StrLen(StrEq))
	{
		return FALSE;
	}
	while (*Str)
	{
		if (*Str != *StrEq)
		{
			return FALSE;
		}
		++Str;
		++StrEq;
	}

	return TRUE;
}

BOOL memory::StrStrCW(const wchar_t* wstr, const wchar_t* wstreq)
{
	if (StrLen(wstr) != StrLen(wstreq))
	{
		return FALSE;
	}

	while (*wstr)
	{
		if (*wstr != *wstreq)
		{
			return FALSE;
		}
		++wstr;
		++wstreq;
	}
	return TRUE;
}

size_t memory::FindCharI(const char* Str, char ch)
{
	size_t i = 0;
	while (*Str)
	{
		++i;
		if (*Str == ch)
		{
			return i;
		}
		++Str;
	}
	return 0;
}


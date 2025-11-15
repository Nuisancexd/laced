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

#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
#define LowerChar(C) if (C >= 'A' && C <= 'Z') {C = C + ('a'-'A');}

unsigned int memory::MurmurHash2A(const void* key, int len, int seed)
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
	
	unsigned int h = seed;
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

char* memory::FindChar(char* Str, char Ch)
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

std::pair<bool, char*> memory::FindCharUntil(char* Str, char ch, char fch)
{
	while(*Str)
	{
		if(*Str == ch)
			return {true, Str};
		else if(*Str == fch)
			return {false, Str};
		Str++;
	}

	return {0, NULL};
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

BOOL memory::StrStr(const TCHAR* Str, const TCHAR* StrEq)
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


unsigned char* memory::BinaryToHex(unsigned char* src, size_t size)
{
	unsigned char* hashHEX = (unsigned char*)m_malloc(65);
	CONST char* literals = "0123456789abcdef";

	int i = 0;
	int j = 0;
	for (; i < size; ++i)
	{
		hashHEX[j++] = literals[src[i] >> 4];
		hashHEX[j++] = literals[src[i] & 0x0F];
	}

	return hashHEX;
}


unsigned char* memory::HexToBinary(const char* hexStr, size_t hexSize)
{
	unsigned char* outBuf = (unsigned char*)m_malloc(hexSize / 2);

	auto hexCharToVal = [](char c) -> int 
	{
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		return -1;
	};

	for (size_t i = 0; i < hexSize; i += 2)
	{
		int high = hexCharToVal(hexStr[i]);
		int low  = hexCharToVal(hexStr[i + 1]);
		if (high < 0 || low < 0)
			return NULL;

		outBuf[i / 2] = (unsigned char)((high << 4) | low);
	}

	return outBuf;
}

VOID memory::memzero_explicit(volatile VOID* ptr, size_t size_of_ptr)
{
	if (!ptr || size_of_ptr == 0) return;
	volatile char* p = (volatile char*)ptr;

#if defined(__GNUC__)
	asm volatile ("" : : "r"(p) : "memory");
#endif
	while (size_of_ptr--) *p++ = 0;

#ifdef _MSC_VER
	_ReadWriteBarrier();
#endif
}
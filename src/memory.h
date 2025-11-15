#pragma once
#include "macro.h"

#define PVOID void*
#define HASHING_SEED 24759

#include <cstddef>
#include <memory>

namespace memory
{
	unsigned int MurmurHash2A(const void* key, int len, int seed);
	VOID* CopyMem(PVOID dst, PVOID src, size_t size);
	int my_stoi(const char* str);
	int my_stoi2(char* str);
	VOID* CopyMemW(PVOID dst, PVOID src, size_t size);
	VOID Copy(PVOID pDst, CONST PVOID pSrc, size_t size);
	PVOID m_malloc(size_t size);
	VOID m_free(PVOID memory);
	size_t StrLen(const char* Str);
	size_t StrLen(const wchar_t* Str);
	char* FindChar(char* Str, char Ch);
	std::pair<bool, char*> FindCharUntil(char* Str, char ch, char fch);
	const wchar_t* FindCharW(const wchar_t* Str, wchar_t Ch);
	size_t FindCharWI(const wchar_t* Str, wchar_t Ch);
	BOOL StrStr(const TCHAR* Str, const TCHAR* StrEq);
	BOOL StrStrC(const char* Str, const char* StrEq);
	BOOL StrStrCW(const wchar_t* wstr, const wchar_t* wstreq);
	size_t FindCharI(const char* Str, char ch);
	unsigned char* BinaryToHex(unsigned char* src, size_t size);
	unsigned char* HexToBinary(const char* hexStr, size_t hexSize);
	VOID memzero_explicit(volatile VOID* ptr, size_t size_of_ptr);
}

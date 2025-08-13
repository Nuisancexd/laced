#ifndef _MACRO_H_
#define _MACRO_H_

#define BOOL int
#define CONST const
#define TRUE 1
#define FALSE 0
#define VOID void
#define PVOID void*
#define STATIC static

typedef wchar_t WCHAR;
typedef char CHAR;
typedef unsigned char BYTE;

#ifdef _WIN32
#define TCHAR WCHAR
#define DESC HANDLE
#define Tsize sizeof(WCHAR)
#define memc(dst, src, size) wmemcpy(dst, src, size)
#define T(str) L##str
#define log_str "%ls"
#define slash L"\\"
#endif
#ifdef __linux__
#define INVALID_HANDLE_VALUE -1
#define DWORD unsigned int
#define TCHAR CHAR
#define DESC int
#define Tsize sizeof(CHAR)
#define memc(dst, src, size) memcpy(dst, src, size)
#define T(str) str
#define log_str "%s"
#define slash "/"
#define LPVOID void*
typedef long long LONGLONG;
#endif

#endif

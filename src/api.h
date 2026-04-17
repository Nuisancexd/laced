#ifndef _API_H_
#define _API_H_

#if defined(_WIN32)
#include <Windows.h>
#endif

#ifdef __linux__
#define FILE_BEGIN SEEK_SET
#define FILE_END   SEEK_END
#endif

#include "macro.h"
#include <cstddef>
#include <cstdio>
#include <cstring>

namespace api
{
#if defined(_WIN32)

    HANDLE OpenFile(CONST WCHAR* wstr);
    HANDLE OpenFile(CONST CHAR* str);
    BOOL WriteFile(HANDLE desc_file, CONST VOID* buff, DWORD BytesToWrite, DWORD* BytesWritten);
    VOID CloseDesc(HANDLE desc_file);
    BOOL ReadFile(HANDLE desc_file, VOID* buf, size_t size, size_t* BytesRead);
    BOOL GetCurrentDir(WCHAR* dir_buf, size_t size);
    BOOL GetCurrentDir(CHAR* dir_buf, size_t size);
    BOOL GetExecPath(char* dir_buf, size_t size);
    BOOL SetPoint(HANDLE desc, int seek);
    BOOL SetPointOff(HANDLE desc, int offset, int seek);
    wchar_t* utf8_to_char(char* str, size_t len);
    char* wchar_to_utf8(WCHAR* wstr, size_t len);    
#else
    int OpenFile(const char* pathaname);
    int CreateFile(const char* pathaname);
    VOID CloseDesc(int desc_file);
    BOOL ReadFile(int desc_file, VOID* buf, size_t size, size_t* BytesRead);
    BOOL WriteFile(int desc_file, CONST VOID* buf, size_t size, int* written);
    BOOL GetCurrentDir(char* dir_buf, size_t size);
    BOOL GetExecPath(CHAR* dir_buf, size_t size);
    BOOL SetPoint(int desc, int seek);
    BOOL SetPointOff(int desc, int offset, int seek);
#endif

    bool get_parse_file(char* FilePath, DESC* desc_file, size_t* filesize);
    bool create_file_open(DESC* desc_file, char* filename);
}


#endif
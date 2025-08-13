#include "api.h"


#if defined(_WIN32)

HANDLE api::OpenFile(CONST WCHAR* wstr)
{
    return CreateFileW(wstr, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

HANDLE api::OpenFile(CONST CHAR* str)
{
    return CreateFileA(str, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

BOOL api::ReadFile(HANDLE desc_file, VOID* buf, size_t size, size_t* BytesRead)
{
    DWORD bytesRead = 0;
    if (!::ReadFile(desc_file, buf, (DWORD)size, &bytesRead, NULL))
        return FALSE;

    if (BytesRead)
        *BytesRead = bytesRead;

    return TRUE;
}

BOOL api::WriteFile(HANDLE desc_file, VOID* buff, DWORD BytesToWrite, DWORD* BytesWritten)
{
    return ::WriteFile(desc_file, buff, BytesToWrite, BytesWritten, NULL);
}

BOOL api::GetCurrentDir(WCHAR* dir_buf, size_t size)
{
    INT getsize = GetCurrentDirectoryW(size, dir_buf);
    if (getsize == 0)
    {
        printf("[GetCurrentDir] Failed\n");
        return FALSE;
    }
    return getsize;
}

BOOL api::GetCurrentDir(CHAR* dir_buf, size_t size)
{
    INT getsize = GetCurrentDirectoryA(size, dir_buf);
    if (getsize == 0)
    {
        printf("[GetCurrentDir] Failed\n");
        return FALSE;
    }
    return TRUE;
}

BOOL api::SetPoint(HANDLE desc, int seek)
{
    if (SetFilePointer(desc, 0, NULL, seek) == INVALID_SET_FILE_POINTER)
        return FALSE;
    return TRUE;
}


VOID api::CloseDesc(HANDLE desc_file)
{
    if (desc_file != INVALID_HANDLE_VALUE) CloseHandle(desc_file);
}


#endif
#if defined(__linux__)

#include <fcntl.h>
#include <unistd.h> 


int api::OpenFile(CONST CHAR* pathaname)
{
    int desc_file = open(pathaname, O_RDWR, S_IRWXU);
    if (desc_file == -1)
        return -1;
    return desc_file;
}

int api::CreateFile(CONST CHAR* pathaname)
{
    int desc_file = open(pathaname, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
    if (desc_file == -1)
    {
        printf("ERROR");
        return -1;
    }
    return desc_file;
}

VOID api::CloseDesc(int desc_file)
{
    if (desc_file != -1) close(desc_file);
}

BOOL api::ReadFile(int desc_file, VOID* buf, size_t size, size_t* BytesRead)
{
    if ((*BytesRead = read(desc_file, buf, size)) == -1)
        return FALSE;
    return TRUE;
}

BOOL api::WriteFile(int desc_file, CONST VOID* buf, unsigned size, int* written)
{
    if ((*written = write(desc_file, buf, size)) == -1)
    {
        printf("ERror\n");
        return FALSE;
    }
    return TRUE;
}


BOOL api::GetCurrentDir(CHAR* dir_buf, size_t size)
{
    if (getcwd(dir_buf, size))
        return TRUE;
    return FALSE;
}

BOOL api::SetPoint(int desc, int seek)
{
    if (lseek(desc, 0, seek) == -1)
        return FALSE;
    return TRUE;
}

/*
SEEK_SET
SEEK_CUR
SEEK_END
*/
BOOL api::SetPointOff(int desc, int offset, int seek)
{
    if (lseek(desc, offset, seek) == -1)
        return FALSE;
    return TRUE;
}



#endif
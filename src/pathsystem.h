#ifndef _PATH_SYSTEM_H_
#define _PATH_SYSTEM_H_

#include <queue>
#include "structures.h"
#include "CommandParser.h"
#include <memory>

struct DriveInfo
{
    TCHAR* Filename;
    TCHAR* Exst;
    TCHAR* FullPath;
    TCHAR* Path;
    LIST_ENTRY(DriveInfo);
};

struct DirectoryInfo
{
    TCHAR* Directory;
    LIST_ENTRY(DirectoryInfo);
};

class PathSystem
{
public:
    PathSystem() {}
    PathSystem(TCHAR* StartDirectory) : directory(StartDirectory) 
    { drive_info = new LIST<DriveInfo>;
      directory_info = new LIST<DirectoryInfo>;
    }
    PathSystem(std::queue<std::pair<size_t, std::unique_ptr<char[]>>>& qpaths) : 
        q_paths(std::move(qpaths)), 
        ec(static_cast<size_t>(GLOBAL_ENUM.g_EncryptCat))
    {   drive_info = new LIST<DriveInfo>;
        directory_info = new LIST<DirectoryInfo>;
    }
    PathSystem(std::queue<std::pair<size_t, std::unique_ptr<char[]>>>& qpaths, TCHAR* StartDirectory) : 
        q_paths(), 
        ec(static_cast<size_t>(GLOBAL_ENUM.g_EncryptCat))
    {
        drive_info = new LIST<DriveInfo>;
        directory_info = new LIST<DirectoryInfo>;
        
        if(CommandParser::PPATH)
        {
            q_paths = std::move(qpaths);
            qm = &PathSystem::qpath;
        }
        else if(StartDirectory != NULL)
            directory = StartDirectory;
        else LOG_ERROR("failed init pathsystem");
    }
    ~PathSystem();
    size_t start_local_search();
    void free_drive_info();
    void free_directory_info();
private:
    typedef void (PathSystem::*qpaths_method)();
    bool check_filename(TCHAR* cFilename);
    TCHAR* make_exst(TCHAR* Filename);
    TCHAR* MakePath(TCHAR* Filename, TCHAR* Directory);
#ifdef _WIN32
    WCHAR* MakeSearchMask(WCHAR* Directory, size_t DirLen)
#endif

    void search_files(LIST<DirectoryInfo>* DirectoryInfo, int* cf);
    void qpath();
    void nop();
public:
    LIST<DriveInfo>* drive_info = NULL;
    LIST<DirectoryInfo>* directory_info = NULL;
    TCHAR* directory = NULL;
    DriveInfo* data = NULL;
    int f_count = 0;
    std::queue<std::pair<size_t, std::unique_ptr<char[]>>> q_paths;
    size_t ec;
    qpaths_method qm = &PathSystem::nop;
};

typedef DriveInfo DRIVE_INFO;
typedef DriveInfo* PDRIVE_INFO;
typedef DirectoryInfo DIRECTORY_INFO;
typedef DirectoryInfo* PDIRECTORY_INFO;


#endif

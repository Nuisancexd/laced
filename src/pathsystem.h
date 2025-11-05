#ifndef _PATH_SYSTEM_H_
#define _PATH_SYSTEM_H_


#include "structures.h"


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
    PathSystem(){}
    PathSystem(TCHAR* StartDirectory) : directory(StartDirectory) 
    {
        drive_info = new LIST<DriveInfo>;
    }
    ~PathSystem();
    size_t start_local_search();
    void free_drive_info();
    void free_directory_info();
private:
    bool check_filename(TCHAR* cFilename);
    TCHAR* make_exst(TCHAR* Filename);
    TCHAR* MakePath(TCHAR* Filename, TCHAR* Directory);
#ifdef _WIN32
    WCHAR* MakeSearchMask(WCHAR* Directory, size_t DirLen)
#endif

    void search_files(LIST<DirectoryInfo>* DirectoryInfo, int* cf);

public:
    LIST<DriveInfo>* drive_info = NULL;
    LIST<DirectoryInfo>* directory_info = NULL;
    DriveInfo* data = NULL;
    TCHAR* directory = NULL;
    int f_count = 0;
};

typedef DriveInfo DRIVE_INFO;
typedef DriveInfo* PDRIVE_INFO;
typedef DirectoryInfo DIRECTORY_INFO;
typedef DirectoryInfo* PDIRECTORY_INFO;


#endif

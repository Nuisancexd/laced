#ifndef _PATH_SYSTEM_H_
#define _PATH_SYSTEM_H_


#include "structures.h"

namespace pathsystem
{
    typedef struct drive_info
    {
        WCHAR* Filename;
        WCHAR* Exst;
        WCHAR* FullPath;
        WCHAR* Path;
        LIST_ENTRY(drive_info);
    }DRIVE_INFO, * PDRIVE_INFO;

    struct INFO
    {
        int fle = 0;
        int dir = 0;
    };
    STATIC pathsystem::INFO f;
    
    
    size_t StartLocalSearch(LIST<DRIVE_INFO>* DriveInfo, WCHAR* dir);
    VOID FreeList(LIST<DRIVE_INFO>* DriveInfo);
}

typedef pathsystem::DRIVE_INFO  DRIVE_INFO;
typedef pathsystem::PDRIVE_INFO PDRIVE_INFO;


#endif

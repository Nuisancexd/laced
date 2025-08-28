#ifndef _PATH_SYSTEM_H_
#define _PATH_SYSTEM_H_


#include "structures.h"

namespace pathsystem
{
    typedef struct drive_info
    {
        TCHAR* Filename;
        TCHAR* Exst;
        TCHAR* FullPath;
        TCHAR* Path;
        LIST_ENTRY(drive_info);
    }DRIVE_INFO, * PDRIVE_INFO;
    
    size_t StartLocalSearch(LIST<DRIVE_INFO>* DriveInfo, TCHAR* dir);
    VOID FreeList(LIST<DRIVE_INFO>* DriveInfo);
}

typedef pathsystem::DRIVE_INFO  DRIVE_INFO;
typedef pathsystem::PDRIVE_INFO PDRIVE_INFO;


#endif

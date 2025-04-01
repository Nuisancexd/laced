#ifndef _GLOBAL_PARAMETERS_H_
#define _GLOBAL_PARAMETERS_H_

#include "macro.h"

enum EncryptModes
{

	FULL_ENCRYPT = 10,
	PARTLY_ENCRYPT = 11,
	HEADER_ENCRYPT = 12,
	BLOCK_ENCRYPT = 13,
	AUTO_ENCRYPT = 14
};

enum EncryptCatalog
{
	FILE_CAT = 13,
	DIR_CAT = 14,
	INDIR_CAT = 15,
	AUTO_CAT = 16
};

enum
{
	ASYMMETRIC = 5,
	SYMMETRIC = 6,
	RSA_ONLY = 7,

	CRYPT = 8,
	DECRYPT = 9
};


namespace global
{
	int GetEncrypt();
	VOID SetEncrypt(int Encrypt);
	int GetDeCrypt();
	VOID SetDeCrypt(int DeCrypt);
	WCHAR* GetPath();
	VOID SetPath(WCHAR* set_path);
	WCHAR* GetPathRSAKey();
	VOID SetPathRSAKey(WCHAR* set_path);
	int GetEncMode();
	VOID SetEncMode(int g_EncryptCat_);
	VOID SetStatus(BOOL g_Status_);
	int GetnEncCat();
	VOID SetEncCat(int EncCat);
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
	VOID SetCryptName(BOOL stat);
	BOOL GetCryptName();
	VOID SetFlagDelete(BOOL flag);
	BOOL GetFlagDelete();
	VOID free_global();
}



#endif





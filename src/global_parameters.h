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
	AUTO_ENCRYPT = 14,
	PIPELINE_ENCRYPT = 15
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

enum class NAME
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
	struct GlobalPath
	{
		TCHAR* g_Path = NULL;
		TCHAR* g_PathRSAKey = NULL;
		TCHAR* g_PathSignRSAKey = NULL;
		TCHAR* g_Path_out = NULL;
	};

	struct GlobalEnum
	{
		EncryptCipher g_Encrypt = EncryptCipher::NONE;
		EncryptCipher g_DeCrypt = EncryptCipher::NONE;
		EncryptModes g_EncryptMode = EncryptModes::FULL_ENCRYPT;
		EncryptCatalog g_EncryptCat = EncryptCatalog::DIR_CAT;
		NAME g_CryptName = NAME::NONE;
		CryptoPolicy g_EncryptMethod = CryptoPolicy::CHACHA;
	};

	struct alignas(8) GlobalState
	{
		bool g_Status = false;
		bool g_print_hash = false;
		bool g_DropMode = false;
		bool g_print_hex = false;
		bool g_FlagDelete = false;
		bool g_RsaBase64 = false;
	};

	struct alignas(4) GlobalOverWrite
	{
		bool g_OverWrite = false;
		int g_OverWriteMode = ZEROS;
		int g_OverWriteCount = 1;
	};

	struct GlobalKeys
	{
		BYTE* g_Key = NULL;
		BYTE* g_IV = NULL;
		unsigned g_BitKey = 4096;
	};

	struct GlobalScanPort
	{
		char* g_scan_ip = NULL;
		int sport = 0;
		int eport = 0;
	};

	BOOL print_command_g();
	VOID free_global();
}

extern global::GlobalPath GLOBAL_PATH;
extern global::GlobalEnum GLOBAL_ENUM;
extern global::GlobalState GLOBAL_STATE;
extern global::GlobalKeys GLOBAL_KEYS;
extern global::GlobalOverWrite GLOBAL_OVERWRITE;
extern global::GlobalScanPort GLOBAL_SCAN_PORT;

#endif





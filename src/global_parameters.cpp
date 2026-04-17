#include <iostream>
#include <cstring>
#include <string>

#include "logs.h"
#include "global_parameters.h"
#include "CommandParser.h"
#include "memory.h"


global::GlobalPath GLOBAL_PATH;
global::GlobalEnum GLOBAL_ENUM;
global::GlobalState GLOBAL_STATE;
global::GlobalKeys GLOBAL_KEYS;
global::GlobalOverWrite GLOBAL_OVERWRITE;
global::GlobalScanPort GLOBAL_SCAN_PORT;

#define str_ std::string
#define str(s) std::string(s)

BOOL global::print_command_g()
{
	LOG_NONE("[LACED PARAMETERS]");
	auto print_kv = [](const std::string& key, const str_& value)
	{
	    constexpr int width = 15;
	    int pad = std::max(1, width - (int)key.size());
	    LOG_NONE("%s%*s%s", key.c_str(), pad, "", value.c_str());
	};

	std::string algo;
	std::string method;
	std::string mode;
	std::string cat;
	std::string dcrypt;
	std::string thrt;

	if (CommandParser::O_REWRITE)
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
	else if(CommandParser::HASH_FILE)
	{
		if (GLOBAL_PATH.g_Path)
			LOG_NONE("-path " log_str, GLOBAL_PATH.g_Path);
		LOG_NONE("HASH_FILE");
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
		print_kv("name:","BASE64_NAME");
		break;
	case NAME::HASH_NAME:
		print_kv("name:", "HASH_NAME");
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

	switch (GLOBAL_ENUM.g_throttle_time) 
	{
		case throttle_time::base:
		break;
		case throttle_time::fast:
		thrt = "fast";
		break;
		case throttle_time::minimal:
		thrt = "minimal";
		break;
		case throttle_time::optimal:
		thrt = "optimal";
		break;
		case throttle_time::background:
		thrt = "background";
		break;

	}

	print_kv("Category:", cat);
	print_kv("EncrMode:", mode);
	print_kv("Method:", method);
	print_kv("Algorithm:", algo);
	if(!thrt.empty())
	print_kv("Throttle", thrt);


	if (GLOBAL_PATH.g_Path)
		print_kv("Path:", str(GLOBAL_PATH.g_Path));
	if(GLOBAL_PATH.g_Path_out)
		print_kv("Path out:", str(GLOBAL_PATH.g_Path_out));
	if (GLOBAL_PATH.g_PathRSAKey)
		print_kv("RSA:", str(GLOBAL_PATH.g_PathRSAKey));
	if (GLOBAL_PATH.g_PathSignRSAKey)
		print_kv("sign RSA:", str(GLOBAL_PATH.g_PathSignRSAKey));
	if (GLOBAL_ENUM.g_DeCrypt != EncryptCipher::NONE)
		print_kv("DeCrypt:", dcrypt);

	if(CommandParser::NO_LOG)
		print_kv("","NOLOG");
	if(GLOBAL_STATE.g_write_in)
		print_kv("","WRITEIN");
	if (GLOBAL_STATE.g_FlagDelete)
		print_kv("","FDELETE");
	if (GLOBAL_OVERWRITE.g_OverWrite)
		print_kv("","OVERWRITE");
	if (CommandParser::THREAD_ENABLE)
		print_kv("","THREAD");
	if (CommandParser::PIPELINE)
		print_kv("", "PIPELINE");

end:
	std::string str;
	LOG_DISABLE("PROCEED [Y-enter/n]");
	std::getline(std::cin, str);

	if (str == "n") return FALSE;
	else if (str.empty() || str == "y" || str == "Y" || str == "yes" || str == "YES")
		return TRUE;
	else { LOG_DISABLE("Type y/Y/yes/YES or press enter"); return FALSE; }
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
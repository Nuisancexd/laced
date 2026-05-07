#include "filesystem.h"
#include "../sha/sha256.h"

#define ECRYPT_WNAME_P T(".laced")
#define ECRYPT_NAME_P ".laced"
#define ECRYPT_NAME_LEN 6


char* filesystem::OptionNameStandart(PFILE_INFO fileinfo, char* Filename, char* exst, char* FPath)
{
	size_t len_filename = memory::StrLen(Filename);
	char* name = (char*)memory::m_malloc(MAX_PATH + 1);

	if (memory::StrStrC(exst, ECRYPT_NAME_P))
		memcpy(name, Filename, len_filename - ECRYPT_NAME_LEN);
	else
	{
		memcpy(name, Filename, len_filename);
		memcpy(&name[len_filename], ECRYPT_NAME_P, ECRYPT_NAME_LEN);
	}

	return name;
}

char* filesystem::OptionNameHash(PFILE_INFO fileinfo, char* Filename, char* exst, char* FPath)
{
	size_t len_filename = memory::StrLen(Filename);
	char* name = (char*)memory::m_malloc(MAX_PATH + 1);

	if (memory::StrStrC(exst, ECRYPT_NAME_P))
		memcpy(name, Filename, len_filename - ECRYPT_NAME_LEN);
	else
	{
		unsigned char out[32] = { 0 };
		sha256((BYTE*)Filename, len_filename, out);
		unsigned char* name_h = memory::BinaryToHex(out, 32);
		memcpy(name, name_h, 64);
		memcpy(&name[64], ECRYPT_NAME_P, ECRYPT_NAME_LEN);
		memory::m_free(name_h);
	}

	return name;
}

char* filesystem::OptionNameBase(PFILE_INFO fileinfo, char* Filename, char* exst, char* FPath)
{
	size_t len_filename = memory::StrLen(Filename);
	char* name = (char*)memory::m_malloc(MAX_PATH + 1);

	if (memory::StrStrC(exst, ECRYPT_NAME_P))
	{
		char decoded[MAX_PATH + MAX_PATH];
		int bsize = 0;
		if (!base64::base64(BASE_E::DECODE,
			(const BYTE*)Filename,
			(int)len_filename - ECRYPT_NAME_LEN,
			decoded, &bsize))
		{
			LOG_ERROR("[OptionNameBase] Failed; %s", Filename);
			memory::m_free(name);
			return OptionNameStandart(fileinfo, Filename, exst, FPath);
		}
		memcpy(name, decoded, bsize);
		if(GLOBAL_ENUM.g_CryptName == NAME::BASE64_NAME_CRYPT)
			ECRYPT_encrypt_bytes((laced_ctx*)fileinfo->hblock->ctx, (BYTE*)name, (BYTE*)name, bsize);
	}
	else
	{
		const char* ptr = Filename;
		if(GLOBAL_ENUM.g_CryptName == NAME::BASE64_NAME_CRYPT)
		{
			ECRYPT_encrypt_bytes((laced_ctx*)fileinfo->hblock->ctx, (BYTE*)Filename, (BYTE*)name, len_filename);
			ptr = name;
		}
		char encoded[MAX_PATH + MAX_PATH];
		int bsize = 0;
		if (!base64::base64(BASE_E::ENCODE,
			(const BYTE*)ptr,
			(int)len_filename,
			encoded, &bsize))
		{
			LOG_ERROR("[OptionNameBase] Failed; %s; trying name_standart", Filename);
			return OptionNameStandart(fileinfo, Filename, exst, FPath);
		}

		if (bsize > MAX_PATH)
		{
			LOG_ERROR("[OptionNameBase] Failed; ENAME TOO LONG; %s; trying name_standart", Filename);
			return OptionNameStandart(fileinfo, Filename, exst, FPath);
		}
		memory::memzero_explicit(name, MAX_PATH + 1);
		memcpy(name, encoded, bsize);
		memcpy(&name[bsize], ECRYPT_NAME_P, ECRYPT_NAME_LEN);
	}
	if(!name)
		LOG_ERROR("filename is null! %s", Filename);
	return name;
}


char* filesystem::NameMethodState(PFILE_INFO fileinfo, PDRIVE_INFO data)
{
	size_t len_path = memory::StrLen(data->Path);
	size_t len_FPath = memory::StrLen(data->FullPath);
	if (len_FPath >= 3840)
	{
		LOG_ERROR("[OptionName] Failed; FULL PATH TOO LONG; " log_str, data->FullPath);
		return NULL;
	}
	
	if(false)
	{
		size_t lenf = memory::StrLen(data->Filename);
		char* swp_name = (char*)memory::m_malloc(MAX_PATH + len_path);
		size_t offset = 0;
		// memcpy_offset(swp_name, data->Path, len_path, &offset);
		// memcpy_offset(swp_name, slash, 1, &offset);
		// memcpy_offset(swp_name, data->Filename, lenf, &offset);
		// memcpy_offset(swp_name, ".swp", 4, &offset);
		return swp_name;
	}
	
	char* name = fileinfo->crypt_info->name_method(fileinfo, data->Filename, data->Exst, data->FullPath);
	if(name == NULL || memory::StrLen(name) > MAX_PATH)
	{
		LOG_ERROR("[NameMethodState] Failed; filename too long; " log_str, data->Filename);
		return NULL;
	}

	char* fullpath = (char*)memory::m_malloc(MAX_PATH + len_path);
	GLOBAL_PATH.g_Path_out != NULL ? 
		memcpy(fullpath, GLOBAL_PATH.g_Path_out, memory::StrLen(GLOBAL_PATH.g_Path_out)) 
		:
		memcpy(fullpath, data->Path, len_path);

	memcpy(&fullpath[memory::StrLen(fullpath)], slash, 1);
	memcpy(&fullpath[memory::StrLen(fullpath)], name, memory::StrLen(name));
	memory::m_free(name);
	return fullpath;
}


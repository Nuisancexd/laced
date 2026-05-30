#include "filesystem.h"


static bool Write(DESC desc_file, unsigned filesize, BYTE* buff)
{
	size_t size_mb = 1048576;
	api::SetPoint(desc_file, 0);
	auto fsize = filesize;
	size_t toWrite;
	size_t written = 0;
	size_t offset = 0;
	while (fsize > 0)
	{
		toWrite = (size_t)fsize >= size_mb ? size_mb : fsize;
		if(!api::WriteFile(desc_file, (BYTE*)buff, toWrite, &written) || !written)
		{
			LOG_ERROR("Failed WriteFullData in OverWriteFile");
			return FALSE;
		}
		offset += written;
		fsize -= written;
	}

	return true;
}


bool filesystem::nopOverWriteFile(PCRYPT_INFO CryptInfo, DESC desc_file, unsigned filesize)
{
	return true;
}

bool filesystem::ZerosOverWriteFile(PCRYPT_INFO CryptInfo, DESC desc_file, unsigned filesize)
{
	for (int i = 0; i < GLOBAL_OVERWRITE.g_OverWriteCount; ++i)
	{
		if (!Write(desc_file, filesize, CryptInfo->zeros))
			return false;
	}
	return true;
}

bool filesystem::RandomOverWriteFile(PCRYPT_INFO CryptInfo, DESC desc_file, unsigned filesize)
{
	for (int i = 0; i < GLOBAL_OVERWRITE.g_OverWriteCount; ++i)
	{
		if (!Write(desc_file, filesize, CryptInfo->random))
			return false;
	}
	return true;
}

bool filesystem::DODOverWriteFile(PCRYPT_INFO CryptInfo, DESC desc_file, unsigned filesize)
{
	for (int i = 0; i < GLOBAL_OVERWRITE.g_OverWriteCount; ++i)
	{
		if (!Write(desc_file, filesize, CryptInfo->zeros))
			return false;
		if (!Write(desc_file, filesize, CryptInfo->random))
			return false;
	}
	return true;
}

bool filesystem::RewriteSDelete(CRYPT_INFO* CryptInfo, char* FullPath)
{
	bool success = false;
	DESC desc = INVALID_HANDLE_VALUE;
	size_t filesize = 0;
	if (!api::get_parse_file(FullPath, &desc, &filesize))
	{
		LOG_ERROR("[getParseFile] [RewriteSDelete] Failed; " log_str, FullPath);
		return false;
	}

	if (!CryptInfo->overwrite_method(CryptInfo, desc, filesize))
	{
		LOG_ERROR("[OverWriteFile] Failed; " log_str, FullPath);
		goto end;
	}


	api::SetPoint(desc, FILE_BEGIN);

#ifdef _WIN32
	if (!SetEndOfFile(desc))
	{
		LOG_ERROR("[RewriteSDelete] Failed; " log_str, FullPath);
		goto end;
	}
#else
	if (ftruncate(desc, 0) == -1)
	{
		LOG_ERROR("[RewriteSDelete] [ftruncate] Failed; %s", FullPath);
		goto end;
	}
#endif

	success = true;
#ifdef __linux
	fsync(desc);
#endif
end:
	if (desc != INVALID_HANDLE_VALUE)
		api::CloseDesc(desc);

	if (success &&
#ifdef _WIN32
		!DeleteFileA(FullPath))
#elif __linux__
		unlink(FullPath) != 0)
#endif		 
	{
		LOG_ERROR("Failed to unlink file after secure delete: %ls", FullPath);
		success = false;
	}
	return success;
}
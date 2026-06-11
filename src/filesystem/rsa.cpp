#include "api.h"
#include "CommandParser.h"
#include "filesystem.h"
#include "crypto/rsa/rsa.h"
#include "crypto/sha/sha256.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <fileapi.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#define PSIZE_BLOCK 256
#define IV_SIZE 8

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
			LOG_INFO("[ReadRSAFile] if key in format Base64 - check flag -b64");
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
	BYTE* FileBuffer = (BYTE*)memory::m_malloc(FileInfo->crypt_info->desc.size);
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
	FileInfo->filesize = dwDataLen;
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
	FileInfo->filesize = size;
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

	FileInfo->crypt_info->methods.gen_key_method(FileInfo->ctx, CryptKey, CryptIV);

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

	if (!FileInfo->crypt_info->methods.mode_method(FileInfo))
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
	int off_meta = CommandParser::NOMETA ? IV_SIZE : PSIZE_BLOCK;

#ifdef _WIN32
	LARGE_INTEGER Offset;
	Offset.QuadPart = -(4 + off_meta);

	if (!SetFilePointerEx(handle, Offset, NULL, FILE_END)
		|| !ReadFile(handle, ReadInfo, 4, NULL, NULL))
	{
		LOG_ERROR("[ReadEncryptInfo] Failed to read file info. GetLastError = %lu", GetLastError());
		return NULL;
	}
#else
	unsigned read;
	if (!api::SetPointOff(handle, -(4 + off_meta), SEEK_END)
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
	Offset.QuadPart = -(size_bit + 4 + off_meta);
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
	if (!api::SetPointOff(handle, -(size_bit + 4 + off_meta), SEEK_END)
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

	FileInfo->crypt_info->methods.gen_key_method(FileInfo->ctx, CryptKey, CryptIV);

	success = FileInfo->crypt_info->methods.mode_method(FileInfo);

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

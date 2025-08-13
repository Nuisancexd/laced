#include "rsa.h"
#include "../logs.h"
#include "../memory.h"
#include "../base64/base64.h"
#include "../global_parameters.h"

#ifdef _WIN32

static void PrintHex(const BYTE* data, size_t size)
{
	for (size_t i = 0; i < size; ++i)
		printf("\\x%02X", data[i]);
	printf("\n");
}



bool HandleError(NTSTATUS status)
{
	if (!BCRYPT_SUCCESS(status))
	{
		LOG_ERROR("BCrypt API failed. NTSTATUS = 0x%02X", status);
		return FALSE;
	}

	return TRUE;
}




bool HandlerGenKeyPairRSA()
{
	BCRYPT_ALG_HANDLE hProvider = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status = 0;
	DWORD dwPublicKeySize = 0;
	DWORD dwPrivateKeySize = 0;
	BYTE* PublicKey = NULL;
	BYTE* PrivateKey = NULL;

	std::wstring s_prv = global::GetPath();
	s_prv += L"/RSA_private_key_laced.txt";
	std::wstring s_pub = global::GetPath();
	s_pub += L"/RSA_public_key_laced.txt";
	HANDLE desc_prv = CreateFileW(s_prv.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	HANDLE desc_pub = CreateFileW(s_pub.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if (desc_prv == INVALID_HANDLE_VALUE || desc_pub == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("Failed Create File");
		goto end;
	}

	if (!HandleError
	(BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RSA_ALGORITHM, NULL, 0)))
	{
		LOG_ERROR("[BCryptOpenAlgorithmProvider] Failed");
		goto end;
	}

	if (!HandleError
	(BCryptGenerateKeyPair(hProvider, &hKey, global::GetBitKey(), 0)))
	{
		LOG_ERROR("[BCryptGenerateKeyPair] Failed");
		goto end;
	}

	if (!HandleError
	(BCryptFinalizeKeyPair(hKey, 0)))
	{
		LOG_ERROR("[BCryptFinalizeKeyPair] Failed");
		goto end;
	}

	if (!HandleError
	(BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &dwPublicKeySize, 0)))
	{
		LOG_ERROR("[BCryptExportKeySize] Failed");
		goto end;
	}

	PublicKey = (BYTE*)memory::m_malloc(dwPublicKeySize);
	if (!HandleError
	(BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, PublicKey, dwPublicKeySize, &dwPublicKeySize, 0)))
	{
		LOG_ERROR("[BCryptExportKey] Failed");
		goto end;
	}

	if (!HandleError
	(BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &dwPrivateKeySize, 0)))
	{
		LOG_ERROR("[BCryptExportKeySize] Failed");
		goto end;
	}

	PrivateKey = (BYTE*)memory::m_malloc(dwPrivateKeySize);
	if (!HandleError
	(BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, PrivateKey, dwPrivateKeySize, &dwPrivateKeySize, 0)))
	{
		LOG_ERROR("[BCryptExportKey] Failed");
		goto end;
	}

	if (global::GetRsaBase64())
	{
		char bb_prv[4096];
		char bb_pub[4096];
		int bsize_prv;
		int bsize_pub;
		base64::base64(BASE_E::ENCODE, PrivateKey, dwPrivateKeySize, bb_prv, &bsize_prv);
		base64::base64(BASE_E::ENCODE, PublicKey, dwPublicKeySize, bb_pub, &bsize_pub);

		if (!filesystem::WriteFullData(desc_prv, bb_prv, bsize_prv)
			|| !filesystem::WriteFullData(desc_pub, bb_pub, bsize_pub))
		{
			LOG_ERROR("[WriteFullData] Failed;");
			goto end;
		}
		memory::memzero_explicit(bb_prv, 4096);
		memory::memzero_explicit(bb_pub, 4096);
	}
	else
	{
		if (!filesystem::WriteFullData(desc_pub, PublicKey, dwPublicKeySize)
			|| !filesystem::WriteFullData(desc_prv, PrivateKey, dwPrivateKeySize))
		{
			LOG_ERROR("[WriteFullData] Failed;");
			goto end;
		}
	}


	LOG_SUCCESS("Public Key (%lu bytes) generated and saved in: %ls", dwPublicKeySize, global::GetPath());
	LOG_SUCCESS("Private Key (%lu bytes) generated and saved in: %ls", dwPrivateKeySize, global::GetPath());

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


#endif


#ifdef __linux__
#include <openssl/err.h>
#include <openssl/rsa.h>


typedef unsigned char byte;
static unsigned bits = global::GetBitKey();
//static BIGNUM exp = 65537;

static void PrintHex(const byte* data, size_t size)
{
	for (size_t i = 0; i < size; ++i)
		printf("\\x%02X", data[i]);
	printf("\n");
}


void err()
{
	char buf[256];
	ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
	LOG_ERROR("OpenSSL error: %s", buf);
}



static bool check_lbits()
{
	switch (bits)
	{
	case 2048:break;
	case 3072:break;
	case 4096:break;
	default:
		LOG_ERROR("bits Failed;");
		return false;
	}
	return true;
}

//https://docs.openssl.org/1.0.2/man3/EVP_PKEY_keygen/#examples
bool HandlerGenKeyPairRSA()
{
	if (!check_lbits())
		return false;

	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;
	bool success = false;

	byte* buf_prv = NULL;
	byte* buf_pub = NULL;
	int len_prv;
	int len_pub;

	std::string s_prv = global::GetPath();
	s_prv += "/RSA_private_key_laced.txt";
	std::string s_pub = global::GetPath();
	s_pub += "/RSA_public_key_laced.txt";
	int desc_prv = -1;
	int desc_pub = -1;

	if (!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)))
	{
		LOG_ERROR("[HandlerGenKeyPairRSA] Failed; 1");
		err();
		goto end;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0)
	{
		LOG_ERROR("[HandlerGenKeyPairRSA] Failed; 2");
		err();
		goto end;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
	{
		LOG_ERROR("[HandlerGenKeyPairRSA] Failed; 3");
		err();
		goto end;
	}

	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		LOG_ERROR("[HandlerGenKeyPairRSA] Failed; 4");
		err();
		goto end;
	}

	len_prv = i2d_PrivateKey(pkey, &buf_prv);
	len_pub = i2d_PUBKEY(pkey, &buf_pub);
	if (len_prv <= 0 || len_pub <= 0)
	{
		LOG_ERROR("Failed to encode private key to DER");
		err();
		goto end;
	}

	desc_prv = api::CreateFile(s_prv.c_str());
	desc_pub = api::CreateFile(s_pub.c_str());
	if (desc_prv == -1 || desc_pub == -1)
	{
		LOG_ERROR("[HandlerGenKeyPairRSA] Failed Create Files keys; %s\t%s", s_prv.c_str(), s_pub.c_str());
		err();
		goto end;
	}

	if (global::GetRsaBase64())
	{
		char bb_prv[4096];
		char bb_pub[4096];
		int bsize_prv;
		int bsize_pub;
		base64::base64(BASE_E::ENCODE, buf_prv, len_prv, bb_prv, &bsize_prv);
		base64::base64(BASE_E::ENCODE, buf_pub, len_pub, bb_pub, &bsize_pub);

		if (!filesystem::WriteFullData(desc_prv, bb_prv, bsize_prv)
			|| !filesystem::WriteFullData(desc_pub, bb_pub, bsize_pub))
		{
			LOG_ERROR("[WriteFullData] Failed;");
			err();
			goto end;
		}
		memory::memzero_explicit(bb_prv, 4096);
		memory::memzero_explicit(bb_pub, 4096);
	}
	else
	{
		if (!filesystem::WriteFullData(desc_prv, buf_prv, len_prv)
			|| !filesystem::WriteFullData(desc_pub, buf_pub, len_pub))
		{
			LOG_ERROR("[WriteFullData] Failed;");
			err();
			goto end;
		}
	}

	LOG_SUCCESS("Public Key  (%d\tbytes) generated and saved in:\t%s", len_pub, s_pub.c_str());
	LOG_SUCCESS("Private Key (%d\tbytes) generated and saved in:\t%s", len_prv, s_prv.c_str());
	success = true;

end:
	if (buf_prv)
	{
		memory::memzero_explicit(buf_prv, len_prv);
		free(buf_prv);
	}
	if (buf_pub)
	{
		memory::memzero_explicit(buf_pub, len_pub);
		free(buf_pub);
	}
	if (desc_prv != -1)
		api::CloseDesc(desc_prv);
	if (desc_pub != -1)
		api::CloseDesc(desc_pub);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return success;
}


bool rsa::EncryptRSA(BIO* bio, EVP_PKEY* pkey, EVP_PKEY_CTX* ctx, BYTE* buffer_encrypt, size_t* bencrypt_size, BYTE** buffer)
{
	bool success = false;
	if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
	{
		LOG_ERROR("[EncryptRSA] [KEY_CTX] Failed.");
		err();
		return false;
	}

	if (EVP_PKEY_encrypt_init(ctx) <= 0)
	{
		LOG_ERROR("[EncryptRSA] Failed enrypt init");
		err();
		goto end;
	}

	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	size_t key_size;
	if (EVP_PKEY_encrypt(ctx, NULL, &key_size, buffer_encrypt, *bencrypt_size) <= 0)
	{
		LOG_ERROR("EVP_PKEY_encrypt size failed");
		err();
		goto end;
	}
	*buffer = (BYTE*)memory::m_malloc(key_size);
	if (EVP_PKEY_encrypt(ctx, *buffer, &key_size, buffer_encrypt, *bencrypt_size) <= 0)
	{
		LOG_ERROR("EVP_PKEY_encrypt failed");
		err();
		goto end;
	}
	*bencrypt_size = key_size;
	success = true;
end:
	EVP_PKEY_CTX_free(ctx);
	return success;
}

bool rsa::DecryptRSA(BIO* bio, EVP_PKEY* pkey, EVP_PKEY_CTX* ctx, BYTE* buffer_decrypt, size_t* bdecrypt_size, BYTE** buffer)
{
	bool success = false;
	if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
	{
		LOG_ERROR("[EncryptRSA] [KEY_CTX] Failed.");
		err();
		return false;
	}

	if (EVP_PKEY_decrypt_init(ctx) <= 0)
	{
		LOG_ERROR("[EncryptRSA] Failed decrypt init");
		err();
		goto end;
	}

	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
	size_t key_size;
	if (EVP_PKEY_decrypt(ctx, NULL, &key_size, buffer_decrypt, *bdecrypt_size) <= 0)
	{
		LOG_ERROR("EVP_PKEY_decrypt size failed");
		err();
		goto end;
	}
	*buffer = (BYTE*)memory::m_malloc(key_size);
	if (EVP_PKEY_decrypt(ctx, *buffer, &key_size, buffer_decrypt, *bdecrypt_size) <= 0)
	{
		LOG_ERROR("EVP_PKEY_decrypt failed");
		err();
		goto end;
	}

	*bdecrypt_size = key_size;
	success = true;
end:
	EVP_PKEY_CTX_free(ctx);
	return success;
}

#endif
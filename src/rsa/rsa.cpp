#include "rsa.h"
#include "../logs.h"
#include "../memory.h"
#include "../base64/base64.h"
#include "../global_parameters.h"

#include <stdalign.h>

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

	std::wstring s_prv = GLOBAL_PATH.g_Path;
	s_prv += L"/RSA_private_key_laced.txt";
	std::wstring s_pub = GLOBAL_PATH.g_Path;
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
	(BCryptGenerateKeyPair(hProvider, &hKey, GLOBAL_KEYS.g_BitKey, 0)))
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

	if (GLOBAL_STATE.g_RsaBase64)
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


	LOG_SUCCESS("Public Key (%lu bytes) generated and saved in: %ls", dwPublicKeySize, GLOBAL_PATH.g_Path);
	LOG_SUCCESS("Private Key (%lu bytes) generated and saved in: %ls", dwPrivateKeySize, GLOBAL_PATH.g_Path);

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
static unsigned bits = GLOBAL_KEYS.g_BitKey;
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

	std::string s_prv = GLOBAL_PATH.g_Path;
	s_prv += "/RSA_private_key_laced.txt";
	std::string s_pub = GLOBAL_PATH.g_Path;
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

	if (GLOBAL_STATE.g_RsaBase64)
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


void rsa::del_session_key(PSESSION_KEY session)
{
	if(session->prv_key)
	{
		memory::memzero_explicit(session->prv_key, session->prv_len);
		if(session->base)
			delete[] session->prv_key;
		else free(session->prv_key);
	}
	if(session->pub_key)
	{
		memory::memzero_explicit(session->pub_key, session->pub_len);
		if(session->base)
			delete[] session->pub_key;
		else free(session->pub_key);
	}

	delete session;
}

PSESSION_KEY rsa::gen_session_key(bool base, unsigned bit)
{
	bool success = false;
	PSESSION_KEY session = new SESSION_KEY;
	session->base = base;
	session->prv_key = NULL;
	session->pub_key = NULL;

	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;

	if (!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))
		|| EVP_PKEY_keygen_init(ctx) <= 0
		|| EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bit) <= 0
		|| EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		LOG_ERROR("[HandlerGenKeyPairRSA] Failed;");
		err();
		goto end;
	}

	if ((session->prv_len = i2d_PrivateKey(pkey, &session->prv_key)) <= 0 
		|| (session->pub_len = i2d_PUBKEY(pkey, &session->pub_key)) <= 0)
	{
		LOG_ERROR("Failed to encode private key to DER");
		err();
		goto end;
	}

	if (base)
	{
		char bb_prv[4096];
		char bb_pub[4096];
		int bsize_prv;
		int bsize_pub;
		if(!base64::base64(BASE_E::ENCODE, session->prv_key, session->prv_len, bb_prv, &bsize_prv)
			|| !base64::base64(BASE_E::ENCODE, session->pub_key, session->pub_len, bb_pub, &bsize_pub))
		{
			LOG_ERROR("[GENERATE RSA] [BASE64] Failed;");
			session->base = false;
		}
		else
		{			
			memory::memzero_explicit(session->prv_key, session->prv_len);
			memory::memzero_explicit(session->pub_key, session->pub_len);
			free(session->prv_key);
			free(session->pub_key);
			session->prv_key = new byte[bsize_prv];
			session->pub_key = new byte[bsize_pub];
			memcpy(session->prv_key, bb_prv, bsize_prv);
			memcpy(session->pub_key, bb_pub, bsize_pub);
			session->prv_len = bsize_prv;
			session->pub_len = bsize_pub;
		}
	}
	
	success = true;
end:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return success ? session : NULL;
}

BYTE* rsa::signature(BYTE* hash, BYTE* private_key_data, unsigned size_key)
{
	bool success = false;
	BYTE* SignatureBuffer = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* PKEY = NULL;
	BIO* bio = NULL;

	unsigned sig_len;
	if (!(bio = BIO_new_mem_buf(private_key_data, size_key))
		|| !(PKEY = d2i_PrivateKey_bio(bio, NULL))
		|| !(ctx = EVP_PKEY_CTX_new(PKEY, NULL))
		|| (EVP_PKEY_sign_init(ctx) <= 0)
		|| (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
		|| (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
		|| (EVP_PKEY_sign(ctx, NULL, &sig_len, hash, SHA256_DIGEST_LENGTH) <= 0))
	{
		LOG_ERROR("[SignatureRSA] Failed");
		err();
		goto end;
	}
	SignatureBuffer = (BYTE*)memory::m_malloc(sig_len);
	if (EVP_PKEY_sign(ctx, SignatureBuffer, &sig_len, hash, SHA256_DIGEST_LENGTH) <= 0)
	{
		LOG_ERROR("[SignatureRSA] [key_sign] Failed");
		err();
		goto end;
	}

	success = true;
end:
	if (bio)
		BIO_free(bio);
	if (PKEY)
		EVP_PKEY_free(PKEY);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	return success ? SignatureBuffer : NULL;
}

bool rsa::verify(BYTE* hash)
{
	return false; /*todo*/
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
	*bdecrypt_size = key_size;
	if (EVP_PKEY_decrypt(ctx, *buffer, &key_size, buffer_decrypt, *bdecrypt_size) <= 0)
	{
		LOG_ERROR("EVP_PKEY_decrypt failed");
		err();
		goto end;
	}

	success = true;
end:
	EVP_PKEY_CTX_free(ctx);
	return success;
}

#endif
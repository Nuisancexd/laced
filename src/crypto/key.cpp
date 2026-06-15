#include "logs.h"
#include "crypto.h"
#include "base64/base64.h"
#include "memory.h"

#define KEY_SIZE 32

void crypto::generate_master_key(BYTE** master_key)
{
    *master_key = (BYTE*)memory::m_malloc(KEY_SIZE);
#ifdef _WIN32
	BCryptGenRandom(0, *master_key, KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
	RAND_bytes(*master_key KEY_SIZE);
#endif
}

void crypto::output_master_key()
{
	BYTE* master_key = NULL;
	generate_master_key(&master_key);
	if(!master_key)
	{ LOG_ERROR("failed generate key"); return;}
	LOG_STDOUT("%s\n", master_key);
	
	BYTE* hex_mkey = memory::BinaryToHex(master_key, KEY_SIZE);
	
	LOG_DISABLE("HEX %s", hex_mkey);
	int bsize;
	char key_base[KEY_SIZE + KEY_SIZE] = { 0 };
	base64::base64(BASE_E::ENCODE,
			master_key, KEY_SIZE,
			key_base, &bsize);
	LOG_DISABLE("BASE %s", key_base);

	memory::m_free(hex_mkey);
	memory::m_free(master_key);
}

BYTE* crypto::get_master_key_hex(const char* master_key, size_t size)
{
	return (BYTE*)memory::HexToBinary(master_key, size);
}

BYTE* crypto::get_master_key_base(const char* master_key, size_t size)
{
	BYTE* key_base = (BYTE*)memory::m_malloc(32);
	int bsize;
	if(!base64::base64(BASE_E::DECODE,
			(const BYTE*)master_key, (int)size,
			(char*)key_base, &bsize) || bsize !=32)
	{LOG_ERROR("[get_master_key_base] failed"); return NULL;}
	
	size = bsize;
	return key_base;
}

void crypto::load_public_root_key(BYTE** g_PublicKeyRoot, size_t* size)
{
	BYTE pub[] = "__public_key__"; // "\x06\x02\x00" Root RSA Public key / Type -print while gen keys
	*size = sizeof(pub);
	*g_PublicKeyRoot = (BYTE*)memory::m_malloc(4096);
	if (!g_PublicKeyRoot) return;
	memcpy(*g_PublicKeyRoot, pub, *size);
	memory::memzero_explicit((VOID*)pub, *size);
}

void crypto::load_private_root_key(BYTE** g_PrivateKeyRoot, size_t* size)
{
	BYTE prv[] = "__private_key__"; // "\x07\x02\x00" Root RSA Private key / Type -print while gen keys
	*size = sizeof(prv);
	*g_PrivateKeyRoot = (BYTE*)memory::m_malloc(4096);
	if (!g_PrivateKeyRoot) return;
	memcpy(*g_PrivateKeyRoot, prv, *size);
	memory::memzero_explicit((VOID*)prv, *size);
}

void crypto::load_root_symmetric_key(BYTE** g_RootKey)
{
	BYTE root_key[] = "____________ROOT_KEY____________";
	*g_RootKey = (BYTE*)memory::m_malloc(32);
	if (!*g_RootKey)
		return;
	memcpy(*g_RootKey, root_key, 32);
	memory::memzero_explicit((VOID*)root_key, sizeof(root_key));
}
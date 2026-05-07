#include "filesystem.h"
#include "../rsa/rsa.h"
#include "../sha/sha256.h"
#include <map>

#include <thread>
std::mutex g_MutexBcrypt;

#define MB 1048576

STATIC VOID dump_hash(CONST BYTE* hash, size_t len)
{
	std::lock_guard<std::mutex> lock(g_MutexBcrypt);
	for (size_t i = 0; i < len; ++i) printf("%02X", hash[i]);
	printf("\n");
}

void filesystem::sort_hash_list(SLIST<HASH_LIST>* list)
{
	SLIST<locker::HLIST>* list_sorted = new SLIST<locker::HLIST>;
	std::multimap<u32, BYTE*> map;
	locker::PHLIST DataHash = NULL;
	SLIST_FOREACH(DataHash, list)
		map.insert({ memory::MurmurHash2A(DataHash->hash, 32, 0), DataHash->hash });

	for (auto& e : map)
	{
		locker::PHLIST hash_sorted = new locker::HLIST;
		hash_sorted->hash = e.second;
		hash_sorted->hash_size = 32;
		list_sorted->SLIST_INSERT_HEAD(hash_sorted);
	}

	*list = *list_sorted;
	delete list_sorted;
}


bool filesystem::nopHashSumFile(CRYPT_INFO* CryptInfo, DESC desc_file, char* Filename)
{
	return true;
}


bool filesystem::HashSumFile(PCRYPT_INFO CryptInfo, DESC desc_file, char* Filename)
{
	BYTE* buff_hash = (BYTE*)memory::m_malloc(MB);
	size_t BytesRead;
	BYTE* out = (BYTE*)memory::m_malloc(33);
	api::SetPoint(desc_file, SEEK_SET);
	sha256_state ctx;
	sha256_init_context(&ctx);
	while (api::ReadFile(desc_file, buff_hash, 1048576, &BytesRead) && BytesRead != 0)
		sha256_update_context(&ctx, buff_hash, BytesRead);
	sha256_final_context(&ctx, out);

	PHASH_LIST hash = new HASH_LIST;
	hash->Filename = Filename;
	LOG_SUCCESS("%s", hash->Filename);
	hash->hash = out;
	hash->hash_size = 32;
	CryptInfo->hash_data.HashList->SLIST_INSERT_HEAD_SAFE(hash);
	if (GLOBAL_STATE.g_print_hash)
	{
		unsigned char* hex = memory::BinaryToHex(out, 32);
		LOG_INFO("hash sum in hex  %s\tfilename " log_str, hex, Filename);
		memory::m_free(hex);
	}	
	LOG_STDOUT("%s", out);
	memory::m_free(buff_hash);
	return true;
}

bool filesystem::hash_file(PCRYPT_INFO CryptInfo, DESC desc, char* fullpath, char* filename)
{
	DESC desc_hf;
	unsigned fs;
	if (!api::get_parse_file(fullpath, &desc_hf, &fs) || desc_hf == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[SetOptionFileInfo] [ParseFile] Failed; %s", fullpath);
		return false;
	}

	HashSumFile(CryptInfo, desc_hf, filename);

	api::CloseDesc(desc_hf);
	return true;
}

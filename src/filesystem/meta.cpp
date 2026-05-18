#include "filesystem.h"
#include "memory.h"
#include "crypto/sha/sha256.h"

#define ECRYPT_VERSION "1.0"
#define ECRYPT_VERSION_LEN 3
#define ECRYPT_NAME_STORAGE "LACEDSTORAGE"
#define ECRYPT_LEN_STORAGE 12
#define ECRYPT_NAMEHEAD "LACEDEND"
#define ECRYPT_NAMEHEAD_LEN 8
#define PSIZE_BLOCK 256
#define HPSIZE_BLOCK PSIZE_BLOCK/2
#define IV_SIZE 8
#define MODE_SIZE 2

static void memcpy_offset(void* pdst, const void* psrc, size_t size, size_t* offset)
{
	if((*offset + size) > PSIZE_BLOCK)
	{
		LOG_ERROR("failed offset metadata");
		return;
	}
	memcpy(pdst, psrc, size);
	*offset += size;
}

static bool read_headname(DESC filehandle)
{
	BYTE buff[ECRYPT_NAMEHEAD_LEN];
	api::SetPointOff(filehandle, -ECRYPT_NAMEHEAD_LEN, FILE_END);
	api::ReadFile(filehandle, buff, ECRYPT_NAMEHEAD_LEN, NULL);
	api::SetPoint(filehandle, FILE_BEGIN);
	return memory::memcmp(buff, ECRYPT_NAMEHEAD, ECRYPT_NAMEHEAD_LEN);
}

void filesystem::write_metadata(PFILE_INFO fileinfo)
{
	api::SetPoint(fileinfo->recent_filehandle, FILE_END);
	
	CommandParser::NOMETA ? 
		api::WriteFile(fileinfo->recent_filehandle, fileinfo->hblock->IV, IV_SIZE, NULL)
		:
	 	api::WriteFile(fileinfo->recent_filehandle, fileinfo->hblock->pblock, PSIZE_BLOCK, NULL);
}

void filesystem::delete_metadata(DESC filehandle, size_t* filesize)
{
#ifdef _WIN32
	api::SetPointOff(filehandle, *filesize, FILE_BEGIN);
	SetEndOfFile(filehandle);
#else
	if(ftruncate(filehandle, *filesize) == -1)
		return;
#endif
}

void filesystem::free_hblock_mdata(PHEAD_BLOCK hblock_t)
{
	memory::memzero_free(hblock_t->pblock, 256);
	memory::memzero_free(hblock_t->ctx, sizeof(laced_ctx));
	memory::memzero_free(hblock_t->IV, IV_SIZE);
	memory::m_free(hblock_t);
}

PHEAD_BLOCK filesystem::init_mdata_hblock(PFILE_INFO fileinfo)
{
	size_t offset = 0;
	PHEAD_BLOCK hblock_t = (PHEAD_BLOCK)memory::m_malloc(sizeof(HEAD_BLOCK));
	*hblock_t = 
	{
		.ctx = (laced_ctx*)memory::m_malloc(sizeof(laced_ctx)),
		.pblock = (BYTE*)memory::m_malloc(PSIZE_BLOCK),
		.IV = (BYTE*)memory::m_malloc(IV_SIZE),
		.status = true,
		.crypt = true
	};

	if(CommandParser::NOMETA)
	{
		if(GLOBAL_ENUM.g_DeCrypt == EncryptCipher::DECRYPT)
		{
			hblock_t->crypt = false;
			fileinfo->filesize -= IV_SIZE;
			api::SetPointOff(fileinfo->filehandle, fileinfo->filesize, FILE_BEGIN);
			api::ReadFile(fileinfo->filehandle, hblock_t->IV, IV_SIZE, NULL);
			api::SetPoint(fileinfo->filehandle, FILE_BEGIN);
		}
		else if(GLOBAL_ENUM.g_DeCrypt == EncryptCipher::CRYPT)
		{
#ifdef _WIN32
			BCryptGenRandom(0, hblock_t->IV, IV_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
			RAND_bytes(hblock_t->IV, IV_SIZE);
#endif
		}
		else hblock_t->status = false;
		
		return hblock_t;
	}

	if(fileinfo->filesize >= PSIZE_BLOCK && read_headname(fileinfo->filehandle))
	{
		hblock_t->crypt = false;
		fileinfo->filesize -= PSIZE_BLOCK;
		api::SetPointOff(fileinfo->filehandle, fileinfo->filesize, FILE_BEGIN);
		api::ReadFile(fileinfo->filehandle, hblock_t->pblock, PSIZE_BLOCK, NULL);
		api::SetPoint(fileinfo->filehandle, FILE_BEGIN);
		offset = HPSIZE_BLOCK;
 		if(GLOBAL_KEYS.g_Key)
		{
			ECRYPT_keysetup((laced_ctx*)hblock_t->ctx, GLOBAL_KEYS.g_Key, 256, 64);
 			ECRYPT_ivsetup((laced_ctx*)hblock_t->ctx, &hblock_t->pblock[offset + 72]);
			ECRYPT_encrypt_bytes((laced_ctx*)hblock_t->ctx, hblock_t->pblock, hblock_t->pblock, HPSIZE_BLOCK);
		}
		BYTE hash[32];
		sha256(hblock_t->pblock, HPSIZE_BLOCK, hash);
		if(!memory::memcmp(&hblock_t->pblock[offset], hash, 32))
		{
			LOG_ERROR("[init_mdata_hblock] hash metadata invalid");
			hblock_t->status = false;
		}
		offset += 32;
		memcpy_offset(hblock_t->IV, &hblock_t->pblock[offset], 8, &offset);
		sha256(hblock_t->IV, 8, hash);
		if(!memory::memcmp(&hblock_t->pblock[offset], hash, 32))
		{
			LOG_ERROR("[init_mdata_hblock] hash metadata IV invalid");
			hblock_t->status = false;
		}
		offset += 32;
		if(!memory::memcmp(&hblock_t->pblock[ECRYPT_LEN_STORAGE], ECRYPT_VERSION, ECRYPT_VERSION_LEN))
		{
			LOG_ERROR("[init_mdata_hblock] ecrypt_version metadata invalid");
			hblock_t->status = false;
		}
		if(!memory::memcmp(&hblock_t->pblock[ECRYPT_LEN_STORAGE + ECRYPT_VERSION_LEN], std::to_string((int)GLOBAL_ENUM.g_EncryptMode).c_str(), MODE_SIZE))
		{
			LOG_ERROR("[init_mdata_hblock] encrypt mode metadata invalid");
			hblock_t->status = false;
		}
		if(!memory::memcmp(&hblock_t->pblock[ECRYPT_LEN_STORAGE + ECRYPT_VERSION_LEN + MODE_SIZE], fileinfo->crypt_info->name, memory::StrLen(fileinfo->crypt_info->name)))
		{
			LOG_ERROR("[init_mdata_hblock] namecrypt metadata invalid");
			hblock_t->status = false;
		}
	}
	else
	{
 		memcpy_offset(&hblock_t->pblock[offset], ECRYPT_NAME_STORAGE, ECRYPT_LEN_STORAGE, &offset);
 		memcpy_offset(&hblock_t->pblock[offset], ECRYPT_VERSION, ECRYPT_VERSION_LEN, &offset);
		memcpy_offset(&hblock_t->pblock[offset], std::to_string((int)GLOBAL_ENUM.g_EncryptMode).c_str(), MODE_SIZE, &offset);
 		memcpy_offset(&hblock_t->pblock[offset], fileinfo->crypt_info->name, memory::StrLen(fileinfo->crypt_info->name), &offset);
#ifdef _WIN32
		BCryptGenRandom(0, &hblock_t->pblock[offset], PSIZE_BLOCK - offset, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
		RAND_bytes(&hblock_t->pblock[offset], PSIZE_BLOCK - offset);
#endif
		memcpy(&hblock_t->pblock[PSIZE_BLOCK - ECRYPT_NAMEHEAD_LEN], ECRYPT_NAMEHEAD, ECRYPT_NAMEHEAD_LEN);
 		offset = HPSIZE_BLOCK;
		sha256(hblock_t->pblock, HPSIZE_BLOCK, &hblock_t->pblock[offset]);
		offset += 32;
		memcpy_offset(hblock_t->IV, &hblock_t->pblock[offset], 8, &offset);
		sha256(hblock_t->IV, 8, &hblock_t->pblock[offset]);
		offset += 32;
		if(GLOBAL_KEYS.g_Key)
		{
			ECRYPT_keysetup((laced_ctx*)hblock_t->ctx, GLOBAL_KEYS.g_Key, 256, 64);
 		 	ECRYPT_ivsetup((laced_ctx*)hblock_t->ctx, &hblock_t->pblock[offset]);
			offset += 8;
			ECRYPT_encrypt_bytes((laced_ctx*)hblock_t->ctx, hblock_t->pblock, hblock_t->pblock, HPSIZE_BLOCK);
		}
		else
			ECRYPT_ivsetup((laced_ctx*)hblock_t->ctx, hblock_t->IV);
	}

	return hblock_t;
}

void filesystem::output_metadata(char* path)
{
	LOG_DISABLE(" ");
	DESC desc = INVALID_HANDLE_VALUE;
	size_t filesize;
	if(!api::get_parse_file(path, &desc, &filesize) || filesize < PSIZE_BLOCK)
	{
		LOG_ERROR("failed parse file %s", path);
		return;
	}
	else if(!read_headname(desc))
	{
		LOG_ERROR("failed tag headname %s", path);
		return;
	}

	BYTE pblock[PSIZE_BLOCK] = {0};
	laced_ctx ctx;

	api::SetPointOff(desc, -PSIZE_BLOCK, FILE_END);
	api::ReadFile(desc, pblock, PSIZE_BLOCK, NULL);
	api::CloseDesc(desc);
	if(GLOBAL_KEYS.g_Key)
	{
		ECRYPT_keysetup(&ctx, GLOBAL_KEYS.g_Key, 256, 64);
 		ECRYPT_ivsetup(&ctx, &pblock[HPSIZE_BLOCK + 72]);
		ECRYPT_encrypt_bytes(&ctx, pblock, pblock, HPSIZE_BLOCK);
	}
	
	if(!memory::memcmp(&pblock, ECRYPT_NAME_STORAGE, ECRYPT_LEN_STORAGE))
			LOG_ERROR("[init_mdata_hblock] headname metadata invalid");
	
	int pad = 15;
	LOG_INFO("path:%*s%.*s", std::max(1, pad - 5), "", memory::StrLen(path), path);
	LOG_INFO("version:%*s%.*s", std::max(1, pad - 8), "", ECRYPT_VERSION_LEN, &pblock[ECRYPT_LEN_STORAGE]);

	BYTE mode[MODE_SIZE + 1] = {0};
	memcpy(mode, &pblock[ECRYPT_LEN_STORAGE + ECRYPT_VERSION_LEN], MODE_SIZE);
	int al = memory::my_stoi((char*)mode);
	switch (al)
	{
	case (int)EncryptModes::FULL_ENCRYPT:
		LOG_INFO("MODE:%*s%s", std::max(1, pad - 5), "", "FULL_ENCRYPT");
		break;
	case (int)EncryptModes::PARTLY_ENCRYPT:
		LOG_INFO("MODE:%*s%s", std::max(1, pad - 5), "", "PARTLY_ENCRYPT");
		break;
	case (int)EncryptModes::HEADER_ENCRYPT:
		LOG_INFO("MODE:%*s%s", std::max(1, pad - 5), "", "HEADER_ENCRYPT");
		break;
	case (int)EncryptModes::BLOCK_ENCRYPT:
		LOG_INFO("MODE:%*s%s", std::max(1, pad - 5), "", "BLOCK_ENCRYPT");
		break;
	default:
		LOG_INFO("MODE:%*s%s", std::max(1, pad - 5), "", "NOT_FOUND");
	}

	BYTE algo[11];
	memcpy(algo, &pblock[ECRYPT_LEN_STORAGE + ECRYPT_VERSION_LEN + MODE_SIZE], 10);
	if(memory::substr(algo, 10, "AES256", 6))
		LOG_INFO("namecrypt:%*s%s", std::max(1, pad - 10), "", "AES256");
	else if (memory::substr(algo, 10, "ChaCha20", 8))
		LOG_INFO("namecrypt:%*s%s", std::max(1, pad - 10), "", "ChaCha20");
	else if (memory::substr(algo, 10, "RSA_AES256", 10))
		LOG_INFO("namecrypt:%*s%s", std::max(1, pad - 10), "", "RSA_AES256");
	else if (memory::substr(algo, 10, "RSA_CHACHA", 10))
		LOG_INFO("namecrypt:%*s%s", std::max(1, pad - 10), "", "RSA_CHACHA");
	else if (memory::substr(algo, 10, "RSA", 3))
		LOG_INFO("namecrypt:%*s%s", std::max(1, pad - 10), "", "RSA");
	else
		LOG_INFO("namecrypt:%*s%s", std::max(1, pad - 10), "", "NOT_FOUND");

	BYTE hash[32];
	sha256(pblock, HPSIZE_BLOCK, hash);
	BYTE* hash_hex_hblock = memory::BinaryToHex(hash, 32);
	sha256(&pblock[HPSIZE_BLOCK + 32], 8, hash);
	BYTE* hash_hex_iv = memory::BinaryToHex(hash, 32);
	sha256(pblock, PSIZE_BLOCK, hash);
	BYTE* hash_hex_block = memory::BinaryToHex(hash, 32);

	LOG_INFO("hash hblock%*s%s", std::max(1, pad - 11), "", hash_hex_hblock);
	LOG_INFO("hash block%*s%s", std::max(1, pad - 10), "", hash_hex_block);
	LOG_INFO("hash IV%*s%s", std::max(1, pad - 7), "", hash_hex_iv);
	memory::m_free(hash_hex_hblock);
	memory::m_free(hash_hex_block);
	memory::m_free(hash_hex_iv);
}
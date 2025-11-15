#include <chrono>
#include "filesystem.h"
#include "CommandParser.h"
#include "global_parameters.h"
#include "threadpool.h"
#include "logs.h"

typedef void (*operation_func)(CRYPT_INFO* CryptInfo, DRIVE_INFO* data);
void execute_operation(LIST<DRIVE_INFO>* DriveInfo, PDRIVE_INFO data, CRYPT_INFO* CryptInfo, int f);
void rewrite_operation(CRYPT_INFO* CryptInfo, DRIVE_INFO* data);
void hash_operation(CRYPT_INFO* CryptInfo, DRIVE_INFO* data);
void crypt_operation(CRYPT_INFO* CryptInfo, DRIVE_INFO* data);
bool path_operation(PathSystem* psys);



int main(int argc, char* argv[])
{
    logs::initLog(TRUE);
    BOOL success = FALSE;
    CommandParser pcl(argc, argv);        
    PathSystem psys(pcl.q_paths, GLOBAL_PATH.g_Path);

    CRYPT_INFO* CryptInfo = new CRYPT_INFO;
    std::chrono::time_point<std::chrono::high_resolution_clock> start_time;


    if (!locker::GeneratePolicy(CryptInfo))
    { LOG_ERROR("Failed to Generate Policy."); goto exit; }
    
    if(!path_operation(&psys)) goto exit;

    if (!global::print_command_g()) goto exit;
    start_time = std::chrono::high_resolution_clock::now();

    execute_operation(psys.drive_info, psys.data, CryptInfo, psys.f_count);

    success = TRUE;
exit:
    locker::FreeCryptInfo(CryptInfo);
    global::free_global();
    if (success)
    {
        auto end_time = std::chrono::high_resolution_clock::now();
        LOG_INFO("[TIME] %s seconds", std::to_string(std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count()).c_str());
        LOG_SUCCESS("EXIT_SUCCESS");
    }
    else LOG_ERROR("EXIT");
    logs::CloseLog();   

    return EXIT_SUCCESS;
}

bool path_operation(PathSystem* psys)
{
    int size = 1;
    if(!psys->q_paths.empty())
        size = psys->q_paths.size();
    for(int i = 0; i < size; ++i)
    {
        psys->start_local_search();
        if (psys->f_count == 0) { LOG_ERROR("No files. null."); return false; }
        LOG_DISABLE("After this operation %d files will be changed", psys->f_count);
        LIST_FOREACH(psys->data, psys->drive_info)
            LOG_INFO("Filename: " log_str, psys->data->Filename);        
    }

    return true;
}

void execute_operation(LIST<DRIVE_INFO>* DriveInfo, PDRIVE_INFO data, CRYPT_INFO* CryptInfo, int f)
{
    operation_func operation = NULL;

    if(CommandParser::O_REWRITE) operation = rewrite_operation;
    else if(CommandParser::HASH_FILE) operation = hash_operation;
    else operation = crypt_operation;

    if(CommandParser::PIPELINE)
    {
        ThreadPipeLine* pipeline = new ThreadPipeLine;
        LIST_FOREACH(data, DriveInfo)
            pipeline->init(CryptInfo, data);

        pipeline->wait();
        delete pipeline;
    }
    else if(f == 1 || !CommandParser::THREAD_ENABLE)
    {
        LIST_FOREACH(data, DriveInfo)
            operation(CryptInfo, data);
    }
    else
    {
        int maxThreads = std::thread::hardware_concurrency() - 1;
        int threads = maxThreads;
        if (f <= maxThreads)
            threads = f - 1;

        ThreadPool pool(threads);
        LIST_FOREACH(data, DriveInfo)
            pool.put_task([=]()
            {
                operation(CryptInfo, data);
            });

        pool.run_main_thread();
    }

    if (CommandParser::signature && !filesystem::VerifySignatureRSA(CryptInfo->hash_data.HashList))
        LOG_ERROR("[VerifySignatureRSA] Failed");
}

void rewrite_operation(CRYPT_INFO* CryptInfo, DRIVE_INFO* data)
{
    if (filesystem::RewriteSDelete(CryptInfo, data->FullPath))
        LOG_SUCCESS("success overwrite file; " log_str, data->Filename);
    else
        LOG_ERROR("failed overwrite file; " log_str, data->Filename);
}

void hash_operation(CRYPT_INFO* CryptInfo, DRIVE_INFO* data)
{
    CryptInfo->hash_sum_method
    (
        CryptInfo, 
        memory::StrLen(data->FullPath) - memory::StrLen(data->Filename), 
        data->FullPath
    );
}

void crypt_operation(CRYPT_INFO* CryptInfo, DRIVE_INFO* data)
{
    locker::HandlerCrypt(CryptInfo, data);
}
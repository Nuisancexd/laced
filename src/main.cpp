#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#define DBG_NEW new( _NORMAL_BLOCK , __FILE__ , __LINE__ )
#define newDBG_NEW



#include <Windows.h>
#include "structures.h"
#include "pathsystem.h"


#include "memory.h"
#include "global_parameters.h"
#include "filesystem.h"
#include "locker.h"
#include "threadpool.h"
#include "logs.h"

#include <string>
#include <vector>

#define min(a,b) (((a) < (b)) ? (a) : (b))

STATIC BOOL Gen = FALSE;
STATIC BOOL THREAD_ENABLE = FALSE;
STATIC BOOL Signature = FALSE;
STATIC BOOL SignatureRoot = FALSE;


CHAR* GetCommandLineArgCh(int argc, CHAR** argv, const CHAR* argv_name)
{
    for (int i = 0; i < argc; ++i)
    {
        if (memory::StrStrC(argv[i], argv_name))
        {
            if ((i + 1) < argc)
            {
                return argv[i + 1];
            }
        }
    }

    return NULL;
}

CHAR* GetCommandLineArgChCurr(int argc, CHAR** argv, const CHAR* argv_name)
{
    for (int i = 0; i < argc; ++i)
    {
        if (memory::StrStrC(argv[i], argv_name))
        {
            return argv[i];
        }
    }

    return NULL;
}



WCHAR* GetCommandLineArg(int argc, WCHAR** argv, const WCHAR* argv_name)
{
    for (int i = 0; i < argc; ++i)
    {
        if (memory::StrStrCW(argv[i], argv_name))
        {
            if ((i + 1) < argc)
            {
                return argv[i + 1];
            }
        }
    }

    return NULL;
}

WCHAR* GetCommandLineArgCurr(int argc, WCHAR** argv, const WCHAR* argv_name)
{
    for (int i = 0; i < argc; ++i)
    {
        if (memory::StrStrCW(argv[i], argv_name))
        {
            return argv[i];
        }
    }

    return NULL;
}


VOID CommandLineHelper();
VOID ParsingCommandLine(int argc_, char** argv, WCHAR** wargv_)
{
    int argc;    
    WCHAR** wargv = NULL;
    LPWSTR cmd = NULL;
    if (wargv_)
    {
        wargv = wargv_;
        argc = argc_;
    }
    else
    {
        cmd = GetCommandLineW();
        wargv = CommandLineToArgvW(cmd, &argc);
    }
    
    
    if (!wargv || argc <= 1) CommandLineHelper();

    WCHAR* helper = GetCommandLineArg(argc, wargv, L"-h");
    if (!helper) helper = GetCommandLineArg(argc, wargv, L"-help");
    if (helper) CommandLineHelper();

    /*      TODO     */  
    WCHAR* RootSignature = GetCommandLineArgCurr(argc, wargv, L"-s_r");
    if (!RootSignature) RootSignature = GetCommandLineArgCurr(argc, wargv, L"-sign_root");
    if (RootSignature)
    {        
        exit(1);
        SignatureRoot = TRUE;
        RootSignature = GetCommandLineArg(argc, wargv, L"-p");
        if(!RootSignature)RootSignature = GetCommandLineArg(argc, wargv, L"-path");
        if (!RootSignature)
        {
            printf("Type full path to rsa public key\n");
            exit(1);
        }
        else
        {
            size_t len = memory::StrLen(RootSignature);
            WCHAR* spath = (WCHAR*)memory::m_malloc((len + 1) * sizeof(WCHAR));
            wmemcpy_s(spath, len, RootSignature, len);
            global::SetPath(spath);
        }

        RootSignature = GetCommandLineArgCurr(argc, wargv, L"-sign");
        if(RootSignature)
            global::SetStatus(TRUE);
        else
        {
            RootSignature = GetCommandLineArgCurr(argc, wargv, L"-verify");
            if (RootSignature)
                global::SetStatus(FALSE);
            else
            {
                printf("Type -sign / -verify\n");
                exit(1);
            }
        }
        
        filesystem::RootKeySignatureTrust();
        global::free_global();
        printf("SUCCESS\n");
        exit(1); /*RETURN SUCCESS*/
    }

    WCHAR* path = GetCommandLineArg(argc, wargv, L"-p");
    if (!path) path = GetCommandLineArg(argc, wargv, L"-path");
    if (!path)
    {
        WCHAR* locale = (WCHAR*)memory::m_malloc(MAX_PATH * sizeof(WCHAR));
        GetCurrentDirectoryW(MAX_PATH, locale);
        global::SetPath(locale);
    }
    else if (path)
    {
        size_t len = memory::StrLen(path);
        WCHAR* spath = (WCHAR*)memory::m_malloc((len + 1) * sizeof(WCHAR));
        wmemcpy_s(spath, len, path, len);
        global::SetPath(spath);
    }
    printf_s("directory:\t%ls\n", global::GetPath());


    WCHAR* CryptFileName = GetCommandLineArgCurr(argc, wargv, L"-n_hash");    
    if (!CryptFileName) CryptFileName = GetCommandLineArgCurr(argc, wargv, L"-name_hash");
    if(CryptFileName) global::SetCryptName(Name::HASH_NAME);
    else
    {
        CryptFileName = GetCommandLineArgCurr(argc, wargv, L"-n_base");
        if (!CryptFileName) CryptFileName = GetCommandLineArgCurr(argc, wargv, L"-name_base");
        if (CryptFileName) global::SetCryptName(Name::BASE64_NAME);
    }
    

    WCHAR* B64 = GetCommandLineArgCurr(argc, wargv, L"-B64");
    if (!B64)B64 = GetCommandLineArgCurr(argc, wargv, L"-Base64");
    if (B64) global::SetRsaBase64(TRUE);

    WCHAR* GenKey = GetCommandLineArgCurr(argc, wargv, L"RSAGenKey");
    if (!GenKey) GenKey = GetCommandLineArgCurr(argc, wargv, L"Gen");
    if (GenKey)
    {
        Gen = TRUE;
        GenKey = GetCommandLineArg(argc, wargv, L"-b");
        if (!GenKey) GenKey = GetCommandLineArg(argc, wargv, L"-bit");
        if (GenKey)
        {
            if (memory::StrStrCW(GenKey, L"2048"))
            {
                global::SetBitKey(2048);
            }
            else if (memory::StrStrCW(GenKey, L"3072"))
            {
                global::SetBitKey(3072);
            }
        }
        GenKey = GetCommandLineArgCurr(argc, wargv, L"-print");
        if (GenKey) global::SetPrintHex(TRUE);

        return;
    }


    WCHAR* EncryptMode = GetCommandLineArg(argc, wargv, L"-m");
    if (!EncryptMode) EncryptMode = GetCommandLineArg(argc, wargv, L"-mode");

    WCHAR* EncryptCat = GetCommandLineArg(argc, wargv, L"-c");
    if (!EncryptCat) EncryptCat = GetCommandLineArg(argc, wargv, L"-cat");

    if (EncryptMode)
    {
        if (memory::StrStrCW(EncryptMode, L"a") || memory::StrStrCW(EncryptMode, L"auto"))
        {
            global::SetEncMode(EncryptModes::AUTO_ENCRYPT);
        }
        else if (memory::StrStrCW(EncryptMode, L"f") || memory::StrStrCW(EncryptMode, L"full"))
        {
            global::SetEncMode(EncryptModes::FULL_ENCRYPT);
        }
        else if (memory::StrStrCW(EncryptMode, L"p") || memory::StrStrCW(EncryptMode, L"part"))
        {
            global::SetEncMode(EncryptModes::PARTLY_ENCRYPT);
        }
        else if (memory::StrStrCW(EncryptMode, L"h") || memory::StrStrCW(EncryptMode, L"head"))
        {
            global::SetEncMode(EncryptModes::HEADER_ENCRYPT);
        }
        else if (memory::StrStrCW(EncryptMode, L"b") || memory::StrStrCW(EncryptMode, L"block"))
        {
            global::SetEncMode(EncryptModes::BLOCK_ENCRYPT);
        }
        else if (memory::StrStrCW(EncryptMode, L"r") || memory::StrStrCW(EncryptMode, L"read"))
        {
            global::SetStatus(TRUE);
        }
    }
    if (EncryptCat)
    {
        if (memory::StrStrCW(EncryptCat, L"dir"))
        {
            global::SetEncCat(EncryptCatalog::DIR_CAT);
        }
        else if (memory::StrStrCW(EncryptCat, L"indir"))
        {
            global::SetEncCat(EncryptCatalog::INDIR_CAT);
        }
        else if (memory::StrStrCW(EncryptCat, L"file"))
        {
            global::SetEncCat(EncryptCatalog::FILE_CAT);
        }
    }
    

    WCHAR* EcnryptChoice = GetCommandLineArg(argc, wargv, L"-algo");    
    if (EcnryptChoice)
    {
        auto funcDeCrypt = ([&EcnryptChoice, &argc, &wargv]
            {
                EcnryptChoice = GetCommandLineArgCurr(argc, wargv, L"crypt");
                if (EcnryptChoice)
                    global::SetDeCrypt(EncryptCipher::CRYPT);
                else if (!EcnryptChoice)
                {
                    EcnryptChoice = GetCommandLineArgCurr(argc, wargv, L"decrypt");
                    if (EcnryptChoice)
                        global::SetDeCrypt(EncryptCipher::DECRYPT);
                    else
                    {
                        printf_s("Type: crypt or decrypt. This is a required field. (default: null)\n");
                        exit(1);
                    }
                }
            });

        auto funcKey = ([&EcnryptChoice, &argc, &wargv]
            {
                EcnryptChoice = GetCommandLineArg(argc, wargv, L"-k");
                if (!EcnryptChoice) EcnryptChoice = GetCommandLineArg(argc, wargv, L"-key");
                if (!EcnryptChoice) { printf_s("Type -key \"C:/path\" RSA private/public key or generate RSA Key\n"); exit(1); }

                WCHAR* signature = GetCommandLineArgCurr(argc, wargv, L"-s");
                if (!signature) signature = GetCommandLineArgCurr(argc, wargv, L"-sign");
                if (signature)
                {
                    Signature = TRUE;
                    WCHAR* smb = GetCommandLineArg(argc, wargv, L"$");
                    if (!smb)
                    {
                        printf("When using the signature, first specify the public key, followed by the private key, separating them with the '$' symbol.\n");
                        printf("example: -key C:\\key\\public_key_rsa.txt $ C:\\key\\private_key_rsa.txt");
                        exit(1);
                    }

                    size_t len = memory::StrLen(EcnryptChoice);
                    WCHAR* public_key = (WCHAR*)memory::m_malloc((len + 1) * sizeof(WCHAR));
                    wmemcpy_s(public_key, len, EcnryptChoice, len);
                    len = memory::StrLen(smb);
                    WCHAR* private_key = (WCHAR*)memory::m_malloc((len + 1) * sizeof(WCHAR));
                    wmemcpy_s(private_key, len, smb, len);
                    printf_s("public key:\t%ls\n", public_key);
                    printf_s("private key:\t%ls\n", private_key);
                    if (global::GetDeCrypt() == EncryptCipher::CRYPT)
                    {
                        global::SetPathRSAKey(public_key);
                        global::SetPathSignRSAKey(private_key);
                    }
                    else
                    {
                        global::SetPathRSAKey(private_key);
                        global::SetPathSignRSAKey(public_key);
                    }
                }
                else
                {
                    size_t len = memory::StrLen(EcnryptChoice);
                    WCHAR* keypath = (WCHAR*)memory::m_malloc((len + 1) * sizeof(WCHAR));
                    wmemcpy_s(keypath, len, EcnryptChoice, len);
                    global::SetPathRSAKey(keypath);
                }
            });

        auto funcKeySym([&argc, &argv]
            {
                CHAR* key = GetCommandLineArgCh(argc, argv, "-k");
                if (!key) key = GetCommandLineArgCh(argc, argv, "-key");
                if (key)
                {
                    size_t size_key = memory::StrLen(key) + 1;
                    BYTE* key_set = (BYTE*)memory::m_malloc(33);
                    memcpy_s(key_set, 32, key, min(size_key, size_t(32)));
                    global::SetKey(key_set);
                }
                else printf_s("Type -key \"...\" for are symmetrical encrypts.Size key must be beetwen 1 nad 32\n");

                CHAR* IV = GetCommandLineArgCh(argc, argv, "-iv");
                if (IV)
                {
                    BYTE* ivbuff = (BYTE*)memory::m_malloc(9);
                    memcpy_s(ivbuff, 9, IV, 8);
                    global::SetIV(ivbuff);
                }
                else
                {
                    unsigned chachaIV = memory::MurmurHash2A(global::GetKey(), 32, HASHING_SEED);
                    std::string s = std::to_string(chachaIV);
                    BYTE* iv = (BYTE*)memory::m_malloc(9);
                    memcpy_s(iv, 9, s.c_str(), min(s.size(), size_t(8)));
                    global::SetIV(iv);
                }
            });

        if (memory::StrStrCW(EcnryptChoice, L"chacha"))
        {
            global::SetEncrypt(EncryptCipher::SYMMETRIC);
            global::SetEncryptMethod(CHACHA);
            funcKeySym();
        }
        else if(memory::StrStrCW(EcnryptChoice, L"aes"))
        {
            global::SetEncrypt(EncryptCipher::SYMMETRIC);
            global::SetEncryptMethod(AES256);
            funcDeCrypt();
            funcKeySym();
        }
        else if (memory::StrStrCW(EcnryptChoice, L"rsa_chacha"))
        {
            global::SetEncrypt(EncryptCipher::ASYMMETRIC);
            global::SetEncryptMethod(RSA_CHACHA);
            funcDeCrypt();
            funcKey();
        }
        else if (memory::StrStrCW(EcnryptChoice, L"rsa_aes"))
        {
            global::SetEncrypt(EncryptCipher::ASYMMETRIC);
            global::SetEncryptMethod(RSA_AES256);
            funcDeCrypt();
            funcKey();
        }
        else if (memory::StrStrCW(EcnryptChoice, L"rsa"))
        {
            global::SetEncrypt(EncryptCipher::RSA_ONLY);
            global::SetEncryptMethod(RSA);
            funcDeCrypt();
            funcKey();
        }
        /*-------------*/
        /*TODO*/
        //    CHAR* key = GetCommandLineArgChCurr(argc, argv, "-r");
        //    if(!key) key = GetCommandLineArgChCurr(argc, argv, "-root");
        //    if (key)
        //    {
        //        BYTE* key = NULL;
        //        BYTE* iv = NULL;
        //        locker::LoadRootSymmetricKey(&key, &iv);
        //        if (key && iv)
        //        {
        //            global::SetKey(key);
        //            global::SetIV(iv);                    
        //        }
        //        else exit(0);
        //    }
        /*-------------*/
    }
    else { printf("[ParsingCommandLine] Miss the command -algo"); exit(1); }

    WCHAR* OverWrite = GetCommandLineArg(argc, wargv, L"-ow");
    if (!OverWrite) OverWrite = GetCommandLineArg(argc, wargv, L"-overwrite");
    if (OverWrite)
    {
        int mode = 0;
        int count = 1;
        if (memory::StrStrCW(OverWrite, L"random"))
        {
            mode = RANDOM;
        }
        else if (memory::StrStrCW(OverWrite, L"DOD"))
        {
            mode = DOD;
        }

        CHAR* Count = GetCommandLineArgCh(argc, argv, "-count");
        if(Count) count = memory::my_stoi2(Count);        
        if (count == 0) {printf("Make sure -ow -count num; num doesnt have symbols\n"); exit(1);}        
        global::SetStatusOverWrite(TRUE, mode, count);
    }

    WCHAR* EnableThreads = GetCommandLineArgCurr(argc, wargv, L"-e");
    if (!EnableThreads) EnableThreads = GetCommandLineArgCurr(argc, wargv, L"-enable");
    if (EnableThreads) THREAD_ENABLE = TRUE;
    WCHAR* FileFlagDelete = GetCommandLineArgCurr(argc, wargv, L"-d");
    if (!FileFlagDelete) FileFlagDelete = GetCommandLineArgCurr(argc, wargv, L"-delete");
    if (FileFlagDelete) global::SetFlagDelete(TRUE);

    if(cmd)
        RtlSecureZeroMemory(cmd, sizeof(cmd));    
}


STATIC BOOL ParseFileConfig(int argc, char** argv, std::vector<CHAR*>* strings, std::vector<WCHAR*>* stringsW)
{
    CHAR* ConfigFullPath = GetCommandLineArgCh(argc, argv, "-path");
    WCHAR* locale = (WCHAR*)memory::m_malloc(MAX_PATH * sizeof(WCHAR));

    if (ConfigFullPath)
    {
        MultiByteToWideChar(CP_UTF8, 0, ConfigFullPath, memory::StrLen(ConfigFullPath), locale, memory::StrLen(ConfigFullPath));        
        printf_s("Path file config:\t%ls\n", locale);
    }
    else
    {
        GetCurrentDirectoryW(MAX_PATH, locale);
        wmemcpy_s(&locale[memory::StrLen(locale)], 13, L"\\config.laced", 13);
        printf_s("locale:\t%ls\n", locale);
    }
    
    
    HANDLE hFile = CreateFileW(locale, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("Failed open config.laced file. Check filename of config: \"config.laced\"\n");
        memory::m_free(locale);
        return FALSE;
    }

    CHAR* FileBuffer = NULL;
    LARGE_INTEGER FileSize;

    if (!GetFileSizeEx(hFile, &FileSize))
    {
        printf_s("The config must be not empty.\n");
        memory::m_free(locale);        
        CloseHandle(hFile);
        return FALSE;
    }
    
    DWORD dwRead;
    FileBuffer = (CHAR*)memory::m_malloc(FileSize.QuadPart);
    VOID* ptrbuff = FileBuffer;
    
    if (!ReadFile(hFile, FileBuffer, FileSize.QuadPart, &dwRead, NULL))
    {
        printf_s("Failed read config.\n");
        memory::m_free(locale);
        memory::m_free(ptrbuff);
        CloseHandle(hFile);
        return FALSE;
    }

    
    std::vector<size_t> indexes;
    CHAR* ptr = NULL;    
    CHAR* buff = NULL;
    CHAR* buff_ = NULL;
    WCHAR* buff_w = NULL;
    WCHAR* buff_w_ = NULL;
    INT j = 0;
    BOOL mark = FALSE;

    do
    {
        ptr = (CHAR*)memory::FindChar(FileBuffer, '\n');
        if (!ptr) break;
        size_t index = memory::FindCharI(FileBuffer, '\n');        
        if (FileBuffer[0] == '*' || FileBuffer[0] == '{' || FileBuffer[0] == '}' || FileBuffer[0] == '\r')
        {            
            FileBuffer += index;
            continue;
        }
        CHAR* line = (CHAR*)memory::m_malloc(index + 1);
        memcpy_s(line, index, FileBuffer, index);
        if (line[index - 1] == '\r') line[index - 1] = 0;
        for (INT i = 0; i < index; ++i) 
        {
            if (line[i] == '"') 
            {
                mark = !mark;
                if (!mark) 
                {
                    indexes.push_back(i - j);       // begin
                    indexes.push_back(j);           // count smb
                    j = 0;
                }
            }
            else if (mark) 
                ++j;
        }
        
        if (!indexes.empty() && indexes.size() == 4)
        {
            buff = (CHAR*)memory::m_malloc(indexes[3] + 1);
            buff_w = (WCHAR*)memory::m_malloc((indexes[3] + 1) * sizeof(WCHAR));
            memcpy_s(buff, indexes[3], &line[indexes[2]], indexes[3]);
            MultiByteToWideChar(CP_UTF8, 0, &line[indexes[2]], indexes[3], buff_w, indexes[3]);
            if (!memory::StrStrC(buff, "false"))
            {
                buff_ = (CHAR*)memory::m_malloc(indexes[1] + 1);
                buff_w_ = (WCHAR*)memory::m_malloc((indexes[1] + 1) * sizeof(WCHAR));
                memcpy_s(buff_, indexes[1], &line[indexes[0]], indexes[1]);
                MultiByteToWideChar(CP_UTF8, 0, &line[indexes[0]], indexes[1], buff_w_, indexes[1]);
                strings->push_back(buff_);
                stringsW->push_back(buff_w_);
                if (!memory::StrStrC(buff, "true"))
                {
                    strings->push_back(buff);
                    stringsW->push_back(buff_w);
                }
                else
                {
                    memory::m_free(buff);
                    memory::m_free(buff_w);
                }
            }
            else
            {
                memory::m_free(buff);
                memory::m_free(buff_w);
            }
        }
        else
        {            
            printf_s("Syntax error: unmatched quotes in line: %s\n", line);
            memory::m_free(locale);
            memory::m_free(ptrbuff);
            CloseHandle(hFile);
            return FALSE;
        }

        indexes.clear();
        FileBuffer += index;
        memory::m_free(line);
    } while (ptr);
     
    memory::m_free(locale);
    memory::m_free(ptrbuff);
    CloseHandle(hFile);
        
    return TRUE;
}


STATIC VOID free_vector(std::vector<CHAR*>* strings, std::vector<WCHAR*>* stringsW);
STATIC VOID free_HashList(SLIST<locker::HLIST>* HashList);
STATIC VOID LeadTime(LONGLONG end, LONGLONG start, LONGLONG freq);
int main(int argc, char** argv)
{    
    CHAR* pars = GetCommandLineArgChCurr(argc, argv, "config");    
    if (pars)    
    {
        std::vector<CHAR*>* strings = new std::vector<CHAR*>;
        std::vector<WCHAR*>* stringsW = new std::vector<WCHAR*>;
        if (!ParseFileConfig(argc, argv, strings, stringsW))
        {
            printf_s("Failed Parse Config.\n");
            free_vector(strings, stringsW);
            return EXIT_FAILURE;
        }
        
        printf("\nconfig.laced parameters:\n");        
        for(WCHAR* ptr : *stringsW)
            printf_s("\t%ls\n", ptr);
        
        ParsingCommandLine(strings->size(), strings->data(), stringsW->data());
        RtlSecureZeroMemory(argv, sizeof(argv));
        free_vector(strings, stringsW);
    }
    else
        ParsingCommandLine(argc, argv, NULL);

    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    logs::initLog();

    SLIST<HASH_LIST>* HashList = NULL;
    if (Signature)  HashList = new SLIST<HASH_LIST>;
    
    if (static_cast<int>(global::GetCryptName()) || global::GetRsaBase64())
    {
        if (!LoadCrypt32())
        {
            LOG_ERROR(L"Failed to load Crypt32.dll; GetLastError = %lu", GetLastError());
            if (global::GetRsaBase64() && global::GetEncrypt() != EncryptCipher::SYMMETRIC)
                return EXIT_FAILURE;
            global::SetCryptName(Name::NONE);
        }
    }

    CRYPT_INFO* CryptInfo = new CRYPT_INFO;
    if (!locker::GeneratePolicy(CryptInfo))
    {
        LOG_ERROR(L"Failed to Generate Policy.");
        LOG_ERROR(L"EXIT_FAILURE");
        delete CryptInfo;
        return EXIT_FAILURE;
    }


    if (Gen)
    {
        if (!filesystem::HandlerGenKeyPairRSA())
        {
            LOG_ERROR(L"Failed to create keys");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    
    LIST<pathsystem::DRIVE_INFO>* DriveInfo = new LIST<pathsystem::DRIVE_INFO>;
    PDRIVE_INFO data = NULL;
    size_t f = pathsystem::StartLocalSearch(DriveInfo, global::GetPath());
    if (f == 0) { LOG_ERROR(L"No files. null\n");goto exit; }
    LIST_FOREACH(data, DriveInfo)
    {
        LOG_INFO(L"Filename: %ls", data->Filename);
    }
    data = NULL;
    if (f == 1 || THREAD_ENABLE)
    {        
        LIST_FOREACH(data, DriveInfo)
        {
            locker::HandlerCrypt(CryptInfo, data, HashList);
        }
    }
    else
    {
        INT maxThreads = std::thread::hardware_concurrency() - 1;
        INT threads = maxThreads;
        if (f <= maxThreads)
        {
            threads = f - 1;
        }
        ThreadPool pool(threads);
        LIST_FOREACH(data, DriveInfo)
        {
            pool.put_task([=]()
                {
                    locker::HandlerCrypt(CryptInfo, data, HashList);
                });
        }
        pool.run_main_thread();
    }

    
    if (Signature)
    {
        filesystem::sort_hash_list(HashList);
        if(global::GetDeCrypt() == EncryptCipher::CRYPT)
            filesystem::CreateSignatureFile(HashList);
        else if(global::GetDeCrypt() == EncryptCipher::DECRYPT)            
            filesystem::VerificationSignatureFile(HashList);
    }

exit:
    locker::FreeCryptInfo(CryptInfo);
    pathsystem::FreeList(DriveInfo);
    global::free_global();
    UnLoadCrypt32();
    if (HashList) free_HashList(HashList);
    
    LOG_SUCCESS(L"EXIT_SUCCESS");
    QueryPerformanceCounter(&end);
    LeadTime(end.QuadPart, start.QuadPart, freq.QuadPart);
    logs::CloseLog();
    _CrtDumpMemoryLeaks(); 
    
    return EXIT_SUCCESS;
}

STATIC VOID free_vector(std::vector<CHAR*>* strings, std::vector<WCHAR*>* stringsW)
{
    for (VOID* ptr : *strings)
        memory::m_free(ptr);
    for (VOID* ptr : *stringsW)
        memory::m_free(ptr);

    delete strings;
    delete stringsW;
}

STATIC VOID free_HashList(SLIST<locker::HLIST>* HashList)
{
    locker::PHLIST dataHash = NULL;
    SLIST_FOREACH(dataHash, HashList)
        delete[] dataHash->hash;     

    delete HashList;
}

STATIC VOID LeadTime(LONGLONG end, LONGLONG start, LONGLONG freq)
{
    double elapsed_sec = static_cast<double>(end - start) / freq;
    auto total_seconds = static_cast<long long>(elapsed_sec);

    if (total_seconds >= 60)
    {
        auto minutes = total_seconds / 60;
        auto seconds = total_seconds % 60;
        LOG_INFO(L"LeadTime: %d min %d seconds", minutes, seconds);        
    }
    else        
        LOG_INFO(L"LeadTime: %d seconds", total_seconds);

}

VOID CommandLineHelper()
{
    printf("\t\t __           ___      ______  _______  _______\n");
    printf("\t\t|  |         /   \\    /      ||   ____||       \\\n");
    printf("\t\t|  |        /  ^  \\  |  ,----'|  |__   |  .--.  |\n");
    printf("\t\t|  |       /  /_\\  \\ |  |     |   __|  |  |  |  |\n");
    printf("\t\t|  `----. /  _____  \\|  `----.|  |____ |  '--'  |\n");
    printf("\t\t|_______|/__/     \\__\\\\______||_______||_______/\n\n");
    printf("laced ver. 3.0\n");
    printf_s("%s\n\n", std::string(120, '-').c_str());

    /*

    printf(" __           ___       ______  _______  _______\n");
    printf("|  |         /   \\     /      ||   ____||       \\\n");
    printf("|  |        /  ^  \\   |  ,----'|  |__   |  .--.  |\n");
    printf("|  |       /  /_\\  \\  |  |     |   __|  |  |  |  |\n");
    printf("|  `----. /  _____  \\ |  `----.|  |____ |  '--'  |\n");
    printf("|_______|/__/     \\__\\ \\______||_______||_______/\n");


     __           ___      ______  _______  _______
    |  |         /   \    /      ||   ____||       \
    |  |        /  ^  \  |  ,----'|  |__   |  .--.  |
    |  |       /  /_\  \ |  |     |   __|  |  |  |  |
    |  `----. /  _____  \|  `----.|  |____ |  '--'  |
    |_______|/__/     \__\\______||_______||_______/
    */

    printf("GENERAL OPTIONS:\n");
    printf("[*]  -h / -help       Provides Information about program.\n");
    printf("[*]  config           Load parameters from config. Configure from the local path or use\n");
    printf("                      '-path' followed by the path to the configuration.\n");
    printf("[*]  -s / -sign       Signature and Verification (default: false). When using the signature\n");
    printf("                      first specify the public key, followed by the private key, separating them with the '$' symbol.\n");
    printf("[*]  -p / -path       Path to the file to encrypt. Optional field. If null, encrypts in local path.\n");
    printf("[*]  -n_b / -name_base Encrypt FILENAME with Base64. (default: false)\n");
    printf("[*]  -n_h / -name_hash Irrevocably Hash FILENAME with sha256. (default: false)\n");
    printf("[*]  -m / -mode       Select the encryption mode. (default: FULL_ENCRYPT)\n");
    printf("                      a / auto  -- AUTO_ENCRYPT:   File size <= 1 MB uses full, <= 5 MB uses partly and > uses header\n");
    printf("                      f / full  -- FULL_ENCRYPT:   Encrypts the entire file. Recommended for small files.\n");
    printf("                      p / part  -- PARTLY_ENCRYPT: Encrypts only part of the file.\n");
    printf("                      h / head  -- HEADER_ENCRYPT: Encrypts file first 1 MB of the file.\n");
    printf("                      b / block -- BLOCK_ENCRYPT:  Encrypts file 1 MB blocks.\n");
    printf("                      r / read  -- READ_ENCRYPT Read without overwriting a file. Only for symmetric Encrypts.\n");
    printf("[*]  -c / -cat        Encryption Category. (default: dir)\n");
    printf("                      dir       -- Encrypts all files in current directory.\n");
    printf("                      indir     -- Encrypts all files in subdirectories of the current directory.\n");
    printf("                      file      -- Encrypts a single file. The \"-path\" field must contain the full path to the file.\n");
    printf("[*]  -algo            Select the encryption type: chacha, aes, rsa_chacha, rsa_aes or rsa. (default: null)\n");
    printf("                      chacha    -- SYMMETRIC: uses ChaCha20 encryption.\n");
    printf("                      aes       -- SYMMETRIC: uses AES256 CBE encryption.\n");
    printf("                                   Type: crypt or decrypt. This is a required field. (default: null)\n");
    printf("                      rsa_chacha -- HYBRID: uses RSA and ChaCha20 encryption.\n");
    printf("                                   Type: crypt or decrypt. This is a required field. (default: null)\n");
    printf("                      rsa_aes   -- HYBRID: uses RSA and AES256 CBE encryption.\n");
    printf("                                   Type: crypt or decrypt. This is a required field. (default: null)\n");
    printf("                      rsa       -- RSA_ONLY: uses only RSA encryption.\n");
    printf("                                   Type: crypt or decrypt. This is a required field. (default: null)\n");
    printf("[*]  -k / -key        Required for HYBRID, ASYMMETRIC & SYMMETRIC encryption. This is a required field.\n");
    printf("                      For HYBRID & ASYMMETRIC: the full path to private/public RSA key.\n");
    printf("                      For SYMMETRIC   the secret key. The key size must be between 1 and 32 bytes.\n");
    printf("[*]  -iv              For SYMMETRIC   The initialization vector (IV). Size must be between 1 & 8 bytes. Optional field.\n");
    printf("[*]  -r / root        TODO;For SYMMETRIC   Command option for load Root key and iv\n");
    printf("[*]  -e / -enable     Enable the Thread Pool. By default, all logical CPU cores are used. (default: false)\n");
    printf("[*]  -B64 / -Base64   If RSA key in Base64 format. (default: false)\n");
    printf("[*]  -d / -delete     File flag delete on close if success. (default: false)\n");
    printf("[*]  -ow / -overwrite Overwriting the original file. (default: false; -zeros, count: 1)\n");
    printf("                      zeros    -- ZEROS: overwrite the file with zeros.\n");
    printf("                      random   -- RANDOM: overwrite the file with random crypt symbols.\n");
    printf("                      DOD      -- DOD: overwrite the file with zeros and random crypt symbols.\n");
    printf("                      -count       Number of times to overwrite the file.\n\n");
    

    printf("EXAMPLE USAGE     Config:  laced config -path C:\\Config.laced\tlaced.exe config\n");
    printf("EXAMPLE USAGE     HYBRID:  laced -path C:/FolderFiles -name_base -mode full -cat dir -algo rsa_chacha -key \"C:/FullPathToRSAkeys\" crypt\n");
    printf("EXAMPLE USAGE  SYMMETRIC:  laced -path C:/FolderFiles -name_base -mode full -cat dir -algo chacha -key \"secret key\"\n");
    printf("EXAMPLE USAGE   RSA_ONLY:  laced -path C:/File.txt -name_base -algo rsa -key \"C:/FullPathToRSAkeys\" crypt\n");
    printf("EXAMPLE USAGE  Signature:  laced -p C:/FolderFiles -algo rsa -k C:\\key\\public_RSA $ C:\\key\\private_RSA -s crypt\n");
    printf("EXAMPLE USAGE  Overwrite:  laced -p C:/FolderFiles -w sym -k \"...\" -ow random -count 2 -delete\n\n\n");

    printf("RSA Generate Keys OPTIONS:\n");
    printf("[*]  Gen / RSAGenKey     Command generate RSA keys. This is a required field.\n");
    printf("[*]  -B64 / -Base64      Save RSA keys in Base64 format. (default: false)\n");
    printf("[*]  -b / -bit           RSA bit(key) length. Available options: 2048, 3072 or 4096. (default: 4096)\n");
    printf("[*]  -p / -path          Path to save the generated keys. Optional field. If null, saves in local path.\n");
    printf("[*]  -print              Print the generated keys in HEX format. (default: false)\n");
    printf("EXAMPLE USAGE:           laced.exe RSAGenKey -path C:/GenTofolder -B64 -bit 3072\n\n");
    
    printf("TODO:;Signature with Root RSA keys. Before signing the public key, you must first generate a key pair using the -print command");
    printf("and then insert the byte array into the locker::LoadRootKey function and compile it.\n");
    printf("[*]    -s_g / -sign_root    Command options for signing with RootRSAKey.\n");
    printf("[*]    -sign                Signature with Root private key. (default: -sign)\n");
    printf("[*]    -verify              Verification with Root public key. (default: -sign)\n");
    printf("[*]    -p / -path           Path to the public key file. Required field.\n");
    printf("EXAMPLE USAGE Signature:   laced.exe -sign_root -p C:/key/RSA_public_key_laced.txt -sign/-verify\n\n");
    printf_s("%s\n", std::string(120, '-').c_str());
    exit(0);
}

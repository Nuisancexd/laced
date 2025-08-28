#include "CommandParser.h"
#ifdef __linux__
#include "network/port_scanner.h"
#endif
#include <string>


VOID parser::subCommandHelper()
{
    printf("\t\t __         ___     _____  _______ _____\n");
    printf("\t\t|  |       /   \\   /     ||   ___||     \\\n");
    printf("\t\t|  |      /  /\\ \\  |  ,--'|  |__  | .--. |\n");
    printf("\t\t|  `---. /  ____ \\ |  `--.|  |___ | '--' |\n");
    printf("\t\t|______|/_/     \\_\\\\_____||______||_____/\n\n");
    printf("laced - crypto line program. version 1.0\n");
    printf("laced -h/--help -- provides general instructions\n");

    printf("laced [command] [options ... ] [ parameters ... ]\n"
          "DESCRIPTION\n"
          "\tLACED is a cryptography toolkit implementing crpyto standarts.\n"
          "\tThe laced program is a command-line utility providing various crypto funcs:\n"
          "\to  Uses for RSA crypt/gen OpenSSL for Linux, BCrypt for Win\n"
          "\to  Creation of public/private RSA keys\n"
          "\to  Symmetric encryption (ChaCha20, AES256)\n"
          "\to  Hybrid encryption (RSA + ChaCha20 / AES256)\n"
          "\to  Pure RSA encryption and decryption\n"
          "\to  Digital sigantures and verification\n"
          "\to  File hashing with SHA256\n"
          "\to  Base64 encoding/decoding\n"
          "\to  Secure file overwrite\n"
          "\to  Recursive directory encryption\n"
          "\to  Thread pool parallel processing\n"
          "\to  ThreadPipeLine - Multithreaded File processing Pipeline\n\n");
    exit(0);
}


VOID parser::CommandLineHelper()
{
    printf("\t\t __           ___      ______  _______  _______\n");
    printf("\t\t|  |         /   \\    /      ||   ____||       \\\n");
    printf("\t\t|  |        /  ^  \\  |  ,----'|  |__   |  .--.  |\n");
    printf("\t\t|  |       /  /_\\  \\ |  |     |   __|  |  |  |  |\n");
    printf("\t\t|  `----. /  _____  \\|  `----.|  |____ |  '--'  |\n");
    printf("\t\t|_______|/__/     \\__\\\\______||_______||_______/\n\n");
    printf("laced version 1.0\n");
    printf("%s\n\n", std::string(120, '-').c_str());

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
    printf("[*]  --h / --help       Provides Information about program.\n"
           "[*]  -p / --path        Path to the file to encrypt. Optional field. If null, encrypts in local path.\n"
           "[*]  -o / --out         Path to directory for encrypted files. (default: false)\n"
           "[*]  -conf / --config   Load parameters from config. Configure from the local path or use\n"
           "                        '--path' followed by the path to the configuration.\n"
           "[*]  -s / --sign        Signature and Verification (default: false). When using the signature\n"
           "                        first specify the public key, followed by the private key, separating them with the '$'/'$$' symbol.\n"
           "[*]  -n / --name        Encrypt FILENAME with: (default: false)\n"
           "                        hash Irrevocably Hash FILENAME with sha256. (default: false)\n"
           "                        encrypt FILENAME with Base64. (default: false)\n"
           "[*]  -m / --mode        Select the encryption mode. (default: FULL_ENCRYPT)\n"
           "                        a / auto  -- AUTO_ENCRYPT:   File size <= 1 MB uses full, <= 5 MB uses partly and > uses header\n"
           "                        f / full  -- FULL_ENCRYPT:   Encrypts the entire file. Recommended for small files.\n"
           "                        p / part  -- PARTLY_ENCRYPT: Encrypts only part of the file.\n"
           "                        h / head  -- HEADER_ENCRYPT: Encrypts file first 1 MB of the file.\n"
           "                        b / block -- BLOCK_ENCRYPT:  Encrypts file 1 MB blocks.\n"
           "[*]  -c / --cat         Encryption Category. (default: dir)\n"
           "                        dir       -- Encrypts all files in current directory.\n"
           "                        indir     -- Encrypts all files in subdirectories of the current directory.\n"
           "                        file      -- Encrypts a single file. The \"-path\" field must contain the full path to the file.\n"
           "[*]  -al / --algo       Select the encryption type: chacha, aes, rsa_chacha, rsa_aes or rsa. (default: null)\n"
           "                        chacha    -- SYMMETRIC: uses ChaCha20 encryption.\n"
           "                        aes       -- SYMMETRIC: uses AES256 CBE encryption.\n"
           "                        rsa_chacha -- HYBRID: uses RSA and ChaCha20 encryption.\n"
           "                        rsa_aes   -- HYBRID: uses RSA and AES256 CBE encryption.\n"
           "                        rsa       -- RSA_ONLY: uses only RSA encryption.\n"
           "                                     Type:(for aes&rsa) crypt or decrypt. This is a required field. (default: null)\n"
           "[*]  -b64 / --base64    If RSA key in Base64 format. (default: false)\n"
           "[*]  -k / --key         Required for HYBRID, ASYMMETRIC & SYMMETRIC encryption. This is a required field.\n"
           "                        For HYBRID & ASYMMETRIC: the full path to private/public RSA key.\n"
           "                        For SYMMETRIC   the secret key. The key size must be between 1 and 32 bytes.\n"
           "[*]  --iv               For SYMMETRIC   The initialization vector (IV). Size must be between 1 & 8 bytes. Optional field.\n"
           "[*]  -r / --root        TODO;For SYMMETRIC   Command option for load Root key and iv\n"
           "[*]  -e / --enable      Enable the Thread Pool. By default, all logical CPU cores are used. (default: false)\n"
           "[*]  -pl / --pipeline   ThreadPipeLine - Multithreaded File processing Pipeline (only for symmetric). (default: false)\n"
           "                        NOTE: encrypts file with block 1 MB\n"
           "[*]  -d / --delete      File flag delete on close if success. (default: false)\n"
           "[*]  -ow / --overwrite  Overwriting the original file. (default: false; -zeros, count: 1)\n"
           "[*]  -rw / --rewrite    Only Overwriting the files. (default: false)\n"
           "                        zeros    -- ZEROS: overwrite the file with zeros.\n"
           "                        random   -- RANDOM: overwrite the file with random crypt symbols.\n"
           "                        DOD      -- DOD: overwrite the file with zeros and random crypt symbols.\n"
           "                        -count       Number of times to overwrite the file.\n\n");

    printf("EXAMPLE USAGE     Config:  laced config --path C:\\Config.laced\t\tlaced config\n"
           "EXAMPLE USAGE     HYBRID:  laced --path C:/FolderFiles --name hash --mode full --cat dir --algo rsa_chacha --key \"C:/FullPathToRSAkeys\" crypt\n"
           "EXAMPLE USAGE  SYMMETRIC:  laced --path C:/FolderFiles -name base --mode full --cat dir --algo chacha --key \"secret key\"\n"
           "EXAMPLE USAGE   RSA_ONLY:  laced --path C:/File.txt -n hash -al rsa -k \"C:/FullPathToRSAkeys\" crypt\n"
           "EXAMPLE USAGE  Signature:  laced --p C:/FolderFiles -al rsa -k C:\\key\\public_RSA $ C:\\key\\private_RSA -s crypt\n"
           "EXAMPLE USAGE  Overwrite:  laced --p C:/FolderFiles --overwrite random -rw -e\n\n\n");

    printf("RSA Generate Keys OPTIONS:\n"
           "[*]  -g / --gen           Command generate RSA keys. This is a required field.\n"
           "[*]  -b64 / --base64      Save RSA keys in Base64 format. (default: false)\n"
           "[*]  -b / --bit           RSA bit(key) length. Available options: 2048, 3072 or 4096. (default: 4096)\n"
           "[*]  -p / --path          Path to save the generated keys. Optional field. If null, saves in local path.\n"
           "[*]  -print               Print the generated keys in HEX format. (default: false)\n"
           "EXAMPLE USAGE:            laced -g --p C:/GenTofolder -b64 -b 4096\n\n");
    printf("%s\n", std::string(120, '-').c_str());
    exit(0);
}



#define min(a,b) (((a) < (b)) ? (a) : (b))

bool THREAD_ENABLE = false;
bool O_REWRITE = false;
bool GEN = false;
bool signature = false;
bool PIPELINE = false;

#ifdef __linux__
#include <sys/stat.h>
constexpr int MAX_PATH = 255;
#endif

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


template<typename Tstr, typename func>
std::pair<bool, Tstr*> GetCommands(int argc, Tstr** argv, const Tstr* fstr, const Tstr* sstr, func f)
{
    Tstr* ptr = NULL;
    if (ptr = f(argc, argv, fstr))
        return { true, ptr };
    else if (ptr = f(argc, argv, sstr))
        return { true, ptr };
    else return { false, NULL };
}


std::pair<bool, WCHAR*> WGetCommandsCurr(int argc, WCHAR* argv[], const WCHAR* fstr, const WCHAR* sstr)
{
    return GetCommands<WCHAR>(argc, argv, fstr, sstr, GetCommandLineArgCurr);
}

std::pair<bool, WCHAR*> WGetCommandsNext(int argc, WCHAR* argv[], const WCHAR* fstr, const WCHAR* sstr)
{
    return GetCommands<WCHAR>(argc, argv, fstr, sstr, GetCommandLineArg);
}

std::pair<bool, char*> GetCommandsCurr(int argc, char* argv[], const char* fstr, const char* sstr)
{
    return GetCommands<char>(argc, argv, fstr, sstr, GetCommandLineArgChCurr);
}

std::pair<bool, char*> GetCommandsNext(int argc, char* argv[], const char* fstr, const char* sstr)
{
    return GetCommands<char>(argc, argv, fstr, sstr, GetCommandLineArgCh);
}



#ifdef _WIN32
#define GetCommandsC(argc, argv, fstr, sstr) WGetCommandsCurr(argc, argv, fstr, sstr)
#define GetCommandsN(argc, argv, fstr, sstr) WGetCommandsNext(argc, argv, fstr, sstr)
#else
#define GetCommandsC(argc, argv, fstr, sstr) GetCommandsCurr(argc, argv, fstr, sstr)
#define GetCommandsN(argc, argv, fstr, sstr) GetCommandsNext(argc, argv, fstr, sstr)
#endif

bool ParsingOtherCommandLine(int argc, char** argv);
void parser::ParsingCommandLine(int argc, char** argv)
{
    if (!argv || argc <= 1)
        subCommandHelper();

    TCHAR** argument = NULL;

#ifdef _WIN32
    argument = CommandLineToArgvW(GetCommandLineW(), &argc);
#else
    argument = argv;
#endif

    std::pair<bool, char*> pair;
    pair = GetCommandsCurr(argc, argv, "-h", "--help");
    if (pair.first) CommandLineHelper();

    pair = GetCommandsCurr(argc, argv, "-conf", "--config");
    bool config = false;
    if (pair.first)
    {
        std::pair<int, char**> pair_c = parser::ParseFileConfig(argc, argv);
        if (pair_c.second == NULL)
        {
            LOG_ERROR("[ParseFileConfig] Failed;"); exit(1);
        }
        argv = pair_c.second;
        argc = pair_c.first;
#ifdef _WIN32
        if (argument)
            LocalFree(argument);
        argument = (WCHAR**)memory::m_malloc(argc * sizeof(WCHAR*));
        int wlen;
        for (int i = 0; i < argc; ++i)
        {
            wlen = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
            WCHAR* wstr = (WCHAR*)memory::m_malloc(wlen * sizeof(WCHAR));
            MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wstr, wlen);
            argument[i] = wstr;
        }
#else
        argument = argv;
#endif
        config = true;
    }

    if(ParsingOtherCommandLine(argc, argv))
    {
        scan();
        free_port_info();
        exit(1);

    }
    
    {
        auto p = GetCommandsN(argc, argument, T("-p"), T("--path"));
        if (!p.first)
        {
            TCHAR* locale = (TCHAR*)memory::m_malloc(MAX_PATH * Tsize);
            api::GetCurrentDir(locale, MAX_PATH);
            GLOBAL_PATH.g_Path = locale;
        }
        else
        {
            size_t len = memory::StrLen(p.second);
            TCHAR* spath = (TCHAR*)memory::m_malloc((len + 1) * Tsize);
            memc(spath, p.second, len);
            GLOBAL_PATH.g_Path = spath;
        }

        p = GetCommandsN(argc, argument, T("-o"), T("--out"));
        if(p.first)
        {
            TCHAR* outpath = (TCHAR*)memory::m_malloc(MAX_PATH * Tsize);
            memc(outpath, p.second, memory::StrLen(p.second));
            GLOBAL_PATH.g_Path_out = outpath;
        }
    }
    pair = GetCommandsCurr(argc, argv, "-b64", "--base64");
    if (pair.first) GLOBAL_STATE.g_RsaBase64 = true;

    pair = GetCommandsCurr(argc, argv, "-g", "--gen");
    if (pair.first)
    {
        pair = GetCommandsNext(argc, argv, "-b", "--bit");
        if (pair.first)
        {
            if (memory::StrStrC(pair.second, "2048"))
                GLOBAL_KEYS.g_BitKey = 2048;
            else if (memory::StrStrC(pair.second, "3072"))
                GLOBAL_KEYS.g_BitKey = 3072;
        }
        pair = GetCommandsCurr(argc, argv, "-pr", "--print");
        if (pair.first) GLOBAL_STATE.g_print_hex = true;
        GEN = true;
        return;
    }

    pair = GetCommandsCurr(argc, argv, "-ow", "--overwrite");
    if (pair.first)
    {
        int mode = 0;
        int count = 1;

        auto mod_ow = GetCommandLineArgChCurr(argc, argv, "random");
        if (mod_ow)
            mode = RANDOM;
        else if (mod_ow = GetCommandLineArgChCurr(argc, argv, "dod"))
            mode = DOD;
        else
            mode = ZEROS;

        char* Count = GetCommandLineArgCh(argc, argv, "-count");
        if (Count) count = memory::my_stoi2(Count);
        if (count == 0) { LOG_ERROR("Make sure -ow -count num; num doesnt have symbols\n"); exit(1); }
        GLOBAL_OVERWRITE.g_OverWrite = true;
        GLOBAL_OVERWRITE.g_OverWriteMode = mode;
        GLOBAL_OVERWRITE.g_OverWriteCount = count;

        pair = GetCommandsCurr(argc, argv, "-rw", "--rewrite");
        if (pair.first)
        {
            pair = GetCommandsCurr(argc, argv, "-e", "--enable");
            if (pair.first) THREAD_ENABLE = TRUE;
            O_REWRITE = true; return;
        }
    }


    pair = GetCommandsNext(argc, argv, "-n", "--name");
    if (pair.first)
    {
        if (memory::StrStrC(pair.second, "hash"))
            GLOBAL_ENUM.g_CryptName = NAME::HASH_NAME;
        else if (memory::StrStrC(pair.second, "base"))
            GLOBAL_ENUM.g_CryptName = NAME::BASE64_NAME;
    }

    pair = GetCommandsNext(argc, argv, "-m", "--mode");
    if (pair.first)
    {
        if (memory::StrStrC(pair.second, "a") || memory::StrStrC(pair.second, "auto"))
            GLOBAL_ENUM.g_EncryptMode = EncryptModes::AUTO_ENCRYPT;
        else if (memory::StrStrC(pair.second, "f") || memory::StrStrC(pair.second, "full"))
            GLOBAL_ENUM.g_EncryptMode = EncryptModes::FULL_ENCRYPT;
        else if (memory::StrStrC(pair.second, "p") || memory::StrStrC(pair.second, "part"))
            GLOBAL_ENUM.g_EncryptMode = EncryptModes::PARTLY_ENCRYPT;
        else if (memory::StrStrC(pair.second, "h") || memory::StrStrC(pair.second, "head"))
            GLOBAL_ENUM.g_EncryptMode = EncryptModes::HEADER_ENCRYPT;
        else if (memory::StrStrC(pair.second, "b") || memory::StrStrC(pair.second, "block"))
            GLOBAL_ENUM.g_EncryptMode = EncryptModes::BLOCK_ENCRYPT;
    }
    pair = GetCommandsNext(argc, argv, "-c", "--cat");
    if (pair.first)
    {
        if (memory::StrStrC(pair.second, "dir"))
            GLOBAL_ENUM.g_EncryptCat = EncryptCatalog::DIR_CAT;            
        else if (memory::StrStrC(pair.second, "indir"))
            GLOBAL_ENUM.g_EncryptCat = EncryptCatalog::INDIR_CAT;
        else if (memory::StrStrC(pair.second, "file"))
            GLOBAL_ENUM.g_EncryptCat = EncryptCatalog::FILE_CAT;
    }

    pair = GetCommandsNext(argc, argv, "-al", "--algo");
    if (pair.first)
    {
        auto funcDeCrypt = ([&argc, &argv]
            {
                auto EcnryptChoice = GetCommandLineArgChCurr(argc, argv, "crypt");
                if (EcnryptChoice)
                    GLOBAL_ENUM.g_DeCrypt = EncryptCipher::CRYPT; 
                else if (!EcnryptChoice)
                {
                    EcnryptChoice = GetCommandLineArgChCurr(argc, argv, "decrypt");
                    if (EcnryptChoice)
                        GLOBAL_ENUM.g_DeCrypt = EncryptCipher::DECRYPT;
                    else
                    {
                        LOG_ERROR("Type: crypt or decrypt. This is a required field. (default: null)");
                        exit(1);
                    }
                }
            });

        auto funcKey = ([&argc, &argument]
            {
                std::pair<bool, TCHAR*> pair = GetCommandsN(argc, argument, T("-k"), T("--key"));
                if (!pair.first) { LOG_ERROR("Type -key \"/path\" RSA private/public key or generate RSA Key"); exit(1); }
                auto pair_sign = GetCommandsC(argc, argument, T("-s"), T("--sign"));
                if (pair_sign.first)
                {
                    signature = true;
                    pair_sign = GetCommandsN(argc, argument, T("$"), T("$$"));
                    if (!pair_sign.first)
                    {
                        LOG_ERROR("When using the signature, first specify the public key, followed by the private key, separating them with the '$' symbol.\n");
                        LOG_ERROR("example: --key /home/user/key/public_key_rsa.txt $ /home/user/key/private_key_rsa.txt");
                        exit(1);
                    }

                    size_t len = memory::StrLen(pair.second);
                    TCHAR* public_key = (TCHAR*)memory::m_malloc((len + 1) * Tsize);
                    memc(public_key, pair.second, len);
                    len = memory::StrLen(pair_sign.second);
                    TCHAR* private_key = (TCHAR*)memory::m_malloc((len + 1) * Tsize);
                    memc(private_key, pair_sign.second, len);

                    LOG_INFO("public  key:\t" log_str, public_key);
                    LOG_INFO("private key:\t" log_str, private_key);

                    if (GLOBAL_ENUM.g_DeCrypt == EncryptCipher::CRYPT)
                    {
                        GLOBAL_PATH.g_PathRSAKey = public_key;
                        GLOBAL_PATH.g_PathSignRSAKey = private_key;
                    }
                    else
                    {
                        GLOBAL_PATH.g_PathRSAKey = private_key;
                        GLOBAL_PATH.g_PathSignRSAKey = public_key;
                    }
                }
                else
                {
                    size_t len = memory::StrLen(pair.second);
                    TCHAR* keypath = (TCHAR*)memory::m_malloc((len + 1) * Tsize);
                    memc(keypath, pair.second, len);
                    GLOBAL_PATH.g_PathRSAKey = keypath;
                }
            });

        auto funcKeySym([&argc, &argv]
            {   
                auto pair = GetCommandsNext(argc, argv, "-r", "--root");
                if(pair.first)
                {
                    BYTE* key = NULL;
                    BYTE* iv = NULL;
                    locker::LoadRootSymmetricKey(&key, &iv);
                    if(key && iv)
                    {
                        GLOBAL_KEYS.g_Key = key;
                        GLOBAL_KEYS.g_IV = iv;
                        return;
                    } else exit(0);
                }
                pair = GetCommandsNext(argc, argv, "-k", "--key");
                if (pair.first)
                {
                    size_t size_key = memory::StrLen(pair.second) + 1;
                    BYTE* key_set = (BYTE*)memory::m_malloc(33);
                    memcpy(key_set, pair.second, min(size_key, size_t(32)));
                    GLOBAL_KEYS.g_Key = key_set;
                }
                else { LOG_ERROR("Type -key \"...\" for are symmetrical encrypts. Size key must be beetwen 1 nad 32"); exit(0); };

                CHAR* IV = GetCommandLineArgCh(argc, argv, "--iv");
                if (IV)
                {
                    BYTE* ivbuff = (BYTE*)memory::m_malloc(9);
                    memcpy(ivbuff, IV, 8);
                    GLOBAL_KEYS.g_IV = ivbuff;
                }
                else
                {
                    unsigned chachaIV = memory::MurmurHash2A(GLOBAL_KEYS.g_Key, 32, HASHING_SEED);
                    std::string s = std::to_string(chachaIV);
                    BYTE* iv = (BYTE*)memory::m_malloc(9);
                    memcpy(iv, s.c_str(), min(s.size(), size_t(8)));
                    GLOBAL_KEYS.g_IV = iv;
                }
            });

        if (memory::StrStrC(pair.second, "chacha") || memory::StrStrC(pair.second, "CHACHA"))
        {
            GLOBAL_ENUM.g_Encrypt = EncryptCipher::SYMMETRIC;
            GLOBAL_ENUM.g_EncryptMethod = CryptoPolicy::CHACHA;
            funcKeySym();
        }
        else if (memory::StrStrC(pair.second, "aes") || memory::StrStrC(pair.second, "AES"))
        {
            GLOBAL_ENUM.g_Encrypt = EncryptCipher::SYMMETRIC;
            GLOBAL_ENUM.g_EncryptMethod = CryptoPolicy::AES256;
            funcDeCrypt();
            funcKeySym();
        }
        else if (memory::StrStrC(pair.second, "rsa_chacha") || memory::StrStrC(pair.second, "RSA_CHACHA"))
        {
            GLOBAL_ENUM.g_Encrypt = EncryptCipher::ASYMMETRIC;
            GLOBAL_ENUM.g_EncryptMethod = CryptoPolicy::RSA_CHACHA;
            funcDeCrypt();
            funcKey();
        }
        else if (memory::StrStrC(pair.second, "rsa_aes") || memory::StrStrC(pair.second, "RSA_AES"))
        {
            GLOBAL_ENUM.g_Encrypt = EncryptCipher::ASYMMETRIC;
            GLOBAL_ENUM.g_EncryptMethod = CryptoPolicy::RSA_AES256;
            funcDeCrypt();
            funcKey();
        }
        else if (memory::StrStrC(pair.second, "rsa") || memory::StrStrC(pair.second, "RSA"))
        {
            GLOBAL_ENUM.g_Encrypt = EncryptCipher::RSA_ONLY;
            GLOBAL_ENUM.g_EncryptMethod = CryptoPolicy::RSA;
            funcDeCrypt();
            funcKey();
        }
    }
    else { LOG_ERROR("[ParsingCommandLine] Miss the command --algo"); exit(1); }

    pair = GetCommandsCurr(argc, argv, "-hs", "--hashsum");
    if (pair.first) GLOBAL_STATE.g_print_hash = true;

    pair = GetCommandsCurr(argc, argv, "-d", "--delete");
    if (pair.first) GLOBAL_STATE.g_FlagDelete = true;

    pair = GetCommandsCurr(argc, argv, "-e", "--enable");
    if (pair.first)THREAD_ENABLE = TRUE;

    pair = GetCommandsCurr(argc, argv, "-pl", "--pipeline");
    if(pair.first) 
    {
        GLOBAL_ENUM.g_EncryptMode = EncryptModes::PIPELINE_ENCRYPT;
        PIPELINE = true;
    }

    if (config)
    {
        for (int i = 0; i < argc; ++i)
        {
            memory::memzero_explicit(argv[i], memory::StrLen(argv[i]));
            memory::m_free(argv[i]);
#ifdef _WIN32
            memory::m_free(argument[i]);
#endif
        }
        memory::m_free(argv);
#ifdef _WIN32
        memory::m_free(argument);
#endif
    }
    else
    {
        for (int i = 0; i < argc; ++i)
            memory::memzero_explicit(argv[i], memory::StrLen(argv[i]));
        /*char* ptr_start = argv[0];
        char* ptr_end = argv[argc - 1] + strlen(argv[argc - 1]);
        memory::memzero_explicit(argv, ptr_end - ptr_start);*/
#ifdef _WIN32
        if (argument)
            LocalFree(argument);
#endif
    }
    logs::call_log();
    LOG_INFO("DIR to execute:\t" log_str, GLOBAL_PATH.g_Path);
}

bool ParsingOtherCommandLine(int argc, char** argv)
{
    std::pair<bool, char*> pair;
    pair = GetCommandsNext(argc, argv, "-ip", "--ip");
    if(pair.first)
    {
        size_t len = memory::StrLen(pair.second);
        char* tg_ip = (char*)memory::m_malloc(len + 1);
        memcpy(tg_ip, pair.second, len);
        GLOBAL_SCAN_PORT.g_scan_ip = tg_ip;

        pair = GetCommandsCurr(argc, argv, "-s", "--system");
        if(pair.first)
        {
            GLOBAL_SCAN_PORT.sport = 0;
            GLOBAL_SCAN_PORT.eport = 1023;
        }
        else if((pair = GetCommandsCurr(argc, argv, "-u", "--user")).first)
        {
            GLOBAL_SCAN_PORT.sport = 1024;
            GLOBAL_SCAN_PORT.eport = 49151;
        }
        else if((pair = GetCommandsCurr(argc, argv, "-p", "--private")).first)
        {
            GLOBAL_SCAN_PORT.sport = 49152;
            GLOBAL_SCAN_PORT.eport = 65535;
        }
        else // -a / --all
        {
            GLOBAL_SCAN_PORT.sport = 0;
            GLOBAL_SCAN_PORT.eport = 65535;
        }

        return true;
    }

    return false;
}

std::pair<int, char**> parser::ParseFileConfig(int argc, char** argv)
{
    std::pair<bool, char*> pair;
    pair = GetCommandsNext(argc, argv, "-p", "--path");

    char* locale = (char*)memory::m_malloc(MAX_PATH + MAX_PATH);
    if (pair.first)
    {
        memcpy(locale, pair.second, memory::StrLen(pair.second));
    }
    else
    {
        if (!api::GetCurrentDir(locale, MAX_PATH))
        {
            LOG_ERROR("Failed get current directory config");
            memory::m_free(locale);
            return { 0, NULL };
        }
        memcpy(&locale[memory::StrLen(locale)], "/config.laced", 13);
    }

    LOG_INFO("File config:\t%s", locale);

    unsigned long size;

#ifdef _WIN32
    HANDLE desc = INVALID_HANDLE_VALUE;
    if ((desc = api::OpenFile(locale)) == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("Failed open config; %s", locale);
        memory::m_free(locale);
        return { 0, NULL };
    }

    LARGE_INTEGER FileSize;
    if (!GetFileSizeEx(desc, &FileSize))
    {
        LOG_ERROR("[GetParseFile] Failed GetFileSize");
        memory::m_free(locale);
        return { 0, NULL };
    }

    size = FileSize.QuadPart;
#else
    int desc = -1;
    if ((desc = api::OpenFile(locale)) == -1)
    {
        LOG_ERROR("Failed open config; %s", locale);
        memory::m_free(locale);
        return { 0, NULL };
    }

    struct stat st;
    if (fstat(desc, &st) == -1)
    {
        LOG_ERROR("[GetParseFile] Failed fstat");
        memory::m_free(locale);
        return { 0, NULL };
    }
    size = st.st_size;
#endif

    char* FileBuffer = (char*)memory::m_malloc(size + 1);
    size_t b_read;
    if (!api::ReadFile(desc, FileBuffer, size, &b_read) || b_read != size)
    {
        LOG_ERROR("[ReadFile] Failed;");
        memory::m_free(FileBuffer);
        memory::m_free(locale);
        return { 0, NULL };
    }

    void* ptr_f = FileBuffer;
    char* ptr;
    char* line = (char*)memory::m_malloc(MAX_PATH + MAX_PATH);
    char** argv_ret = (char**)memory::m_malloc(sizeof(char*) * 100);
    int count = 0;
    int count_q = 0;
    int q_array[4] = { 0 };
    size_t index;
    do
    {
        ptr = (char*)memory::FindChar(FileBuffer, '\n');
        if (ptr == NULL) break;
        index = memory::FindCharI(FileBuffer, '\n');
        if (index == 1 || FileBuffer[0] == '*' || FileBuffer[0] == '{' || FileBuffer[0] == '}' || FileBuffer[0] == '\r')
        {
            FileBuffer += index; continue;
        }
        memcpy(line, FileBuffer, index);
        if (line[index - 1] == '\r') line[index - 1] = 0;
#ifdef DEBUG
        printf("%s", line);
#endif
        for (int i = 0; i < index; ++i)
        {
            if (line[i] == '"')
            {
                if (count_q >= 4)
                {
                    line[index - 1] = '\0';
                    LOG_ERROR("Syntax error: unmatched quotes in line: %s", line);
                    goto end;
                }
                q_array[count_q] = i;
                ++count_q;
            }
        }

        if (count_q != 4)
        {
            line[index - 1] = '\0';
            LOG_ERROR("Syntax error: missed quotes in line: %s", line);
            goto end;
        }

        char* arg_c = (char*)memory::m_malloc((q_array[1] - q_array[0]));
        char* arg_n = (char*)memory::m_malloc((q_array[3] - q_array[2]));
        memcpy(arg_c, &line[q_array[0] + 1], (q_array[1] - q_array[0] - 1));
        memcpy(arg_n, &line[q_array[2] + 1], (q_array[3] - q_array[2] - 1));
        if (memory::StrStrC(arg_n, "false") || memory::StrStrC(arg_n, "FALSE"))
        {
            memory::m_free(arg_c);
            memory::m_free(arg_n);
        }
        else if (memory::StrStrC(arg_n, "true") || memory::StrStrC(arg_n, "TRUE"))
        {
            argv_ret[count++] = arg_c;
            memory::m_free(arg_n);
        }
        else
        {
            argv_ret[count++] = arg_c;
            argv_ret[count++] = arg_n;
        }

        count_q = 0;
        memset(q_array, 0x00, 4);
        memset(line, 0x00, index);
        FileBuffer += index;
    } while (ptr);

end:

    memory::m_free(locale);
    memory::m_free(line);
    memory::m_free(ptr_f);
    api::CloseDesc(desc);


    return { count, argv_ret };
}
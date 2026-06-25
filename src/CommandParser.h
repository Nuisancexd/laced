#ifndef _COMMAND_PARSER_H_
#define _COMMAND_PARSER_H_

#include "memory.h"
#include "crypto/base64/base64.h"
#include <queue>
#include <memory>



extern bool THREAD_ENABLE;
extern bool O_REWRITE;
extern bool GEN;
extern bool signature;
extern bool PIPELINE;
extern bool HASH_FILE;
extern bool NO_LOG;
extern bool NOUT;
extern bool PPATH;
extern bool NOMETA;
extern bool OUTPUT_META;
extern bool OUTPUT_META_SHORT;
extern bool DELETE_FILE_EXST;
extern bool WATHCER;
extern bool UNSAFE;
extern bool DEMONIZE;

class FileParser
{
public:
    FileParser(int argc_, char** argv_) : argc(argc_), argv(argv_) 
    {
        method = &FileParser::parse_config_data;
        q_array = (int*)memory::m_malloc(4 * sizeof(int));
        count_q = 0;
    }
    FileParser(char* filepath_) : filepath(filepath_) 
    {
        method = &FileParser::parse_paths_data;
    }
    ~FileParser()
    {
        if(q_array)
            memory::m_free(q_array);
    }

    std::pair<size_t, char**> parse_config_file();
    bool parse_paths_file(std::queue<std::pair<size_t, std::unique_ptr<char[]>>>& auto_pair_path);

private:
    typedef bool (FileParser::*method_parse_file)(char*, size_t, char**); 
    bool parse_config_data(char* line, size_t index, char** argv_ret);
    bool parse_paths_data(char* line, size_t index, char** argv_ret);

    void parse_file(char* filepath);
    std::pair<size_t, char**> parse_data_file();

    std::unique_ptr<char[]> filebuffer;
    size_t filesize;

    int argc = 0;
    char** argv = NULL;
    char* filepath = NULL;

    int count = 0;

    int* q_array = NULL;
    int count_q;

    method_parse_file method = NULL;
};

class CommandParser
{
private:

    VOID subCommandHelper();
    VOID CommandLineHelper();

    void commands_state(int* argumentc, char** argument);
    void commands_state_t(int* argumentc, char** argument);
    static CHAR* GetCommandLineArgCh(int argc, CHAR** argv, const CHAR* argv_name);
    static CHAR* GetCommandLineArgChCurr(int argc, CHAR** argv, const CHAR* argv_name);
    static WCHAR* GetCommandLineArg(int argc, WCHAR** argv, const WCHAR* argv_name);
    static WCHAR* GetCommandLineArgCurr(int argc, WCHAR** argv, const WCHAR* argv_name);
    template<typename Tstr, typename func>
    static std::pair<bool, Tstr*> GetCommands(int argc, Tstr** argv, const Tstr* fstr, const Tstr* sstr, func f);
    static std::pair<bool, WCHAR*> WGetCommandsCurr(int argc, WCHAR* argv[], const WCHAR* fstr, const WCHAR* sstr);
    static std::pair<bool, WCHAR*> WGetCommandsNext(int argc, WCHAR* argv[], const WCHAR* fstr, const WCHAR* sstr);
    static std::pair<bool, char*> GetCommandsCurr(int argc, char* argv[], const char* fstr, const char* sstr);
    
public:
    
    static std::pair<bool, char*> GetCommandsNext(int argc, char* argv[], const char* fstr, const char* sstr);
    CommandParser(int argc_, char** argv_) : argc(argc_), argv(argv_) 
    {
        
    }
    CommandParser(){};
    ~CommandParser()
    {};
    bool ParsingCommandLine();

    int argc = 0;
    char** argv = NULL;
    bool config = false;
    std::queue<std::pair<size_t, std::unique_ptr<char[]>>> q_paths;
    int argc_conf = 0;
    char** argv_conf = NULL;

    static bool NOUT;
    static bool NO_LOG;
    static bool THREAD_ENABLE;
    static bool O_REWRITE;
    static bool BASE64;
    static bool signature;
    static bool PIPELINE;
    static bool HASH_FILE;
    static bool PPATH;
    static bool NOMETA;
    static bool OUTPUT_META;
    static bool OUTPUT_META_SHORT;
    static bool DELETE_FILE_EXST;
    static bool WATHCER;
    static bool UNSAFE;
    static bool DEMONIZE;
};

#endif

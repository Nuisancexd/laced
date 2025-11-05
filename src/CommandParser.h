#ifndef _COMMAND_PARSER_H_
#define _COMMAND_PARSER_H_
#include "global_parameters.h"
#include "memory.h"
#include "logs.h"



extern bool THREAD_ENABLE;
extern bool O_REWRITE;
extern bool GEN;
extern bool signature;
extern bool PIPELINE;
extern bool HASH_FILE;
extern bool NO_LOG;
extern bool PPATH;

//class FileParser
class Parser
{
public:
    Parser(int argc_, char** argv_) : argc(argc_), argv(argv_) 
    {
        method = &Parser::parse_config_data;
        q_array = (int*)memory::m_malloc(4 * sizeof(int));
        count_q = 0;
    }
    Parser(const char* filepath_) : filepath(filepath_) 
    {
        method = &Parser::parse_paths_data;
    }
    ~Parser()
    {
        if(q_array)
            memory::m_free(q_array);
        if(ptr_free)
            memory::m_free(ptr_free);
    }

    std::pair<size_t, char**> parse_config_file();
    std::pair<size_t, char**> parse_paths_file();

private:
    typedef bool (Parser::*method_parse_file)(char*, size_t, char**); 
    bool parse_config_data(char* line, size_t index, char** argv_ret);
    bool parse_paths_data(char* line, size_t index, char** argv_ret);

    std::pair<char*, size_t> parse_file(const char* filepath);
    std::pair<size_t, char**> parse_data_file(char* file_buffer);


    int argc = 0;
    char** argv = NULL;
    const char* filepath = NULL;

    int count = 0;
    void* ptr_free = NULL;

    int* q_array = NULL;
    int count_q;

    method_parse_file method = NULL;
};

class CommandParser
{

};

namespace parser
{
    void ParsingCommandLine(int argc, char** argv);
    VOID subCommandHelper();
    VOID CommandLineHelper();
}


#endif

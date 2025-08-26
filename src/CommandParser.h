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

namespace parser
{
    std::pair<int, char**> ParseFileConfig(int argc, char** argv);
    void ParsingCommandLine(int argc, char** argv);
    VOID subCommandHelper();
    VOID CommandLineHelper();
}


#endif

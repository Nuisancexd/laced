#ifndef _LOGS_H_
#define _LOGS_H_

#include "api.h"
#include "macro.h"


enum class LogLevel : size_t
{
	LOG_INFO = 0,
	LOG_ERROR = 1,
	LOG_SUCCESS = 2,
	LOG_NONE = 3,
	LOG_DISABLE = 4,
	LOG_CMD_DIS = 5
};


namespace logs
{
	VOID call_log();
	VOID initLog(BOOL append = FALSE);
	VOID CloseLog();
	VOID WriteLog(LogLevel log, CONST char* Format, ...);
}

#ifdef _MSC_VER
#define LOG_INFO(...)		logs::WriteLog(LogLevel::LOG_INFO,	  __VA_ARGS__)
#define LOG_SUCCESS(...)    logs::WriteLog(LogLevel::LOG_SUCCESS, __VA_ARGS__)
#define LOG_ERROR(...)		logs::WriteLog(LogLevel::LOG_ERROR,	  __VA_ARGS__)
#define LOG_NONE(...)		logs::WriteLog(LogLevel::LOG_NONE,    __VA_ARGS__)
#define LOG_DISABLE(...)	logs::WriteLog(LogLevel::LOG_DISABLE, __VA_ARGS__)
#define LOG_CMD_DIS(...)    losg::WriteLog(LogLevel::LOG_CMD_DIS, __VA_ARGS__);
#else //__GNUC__
#define LOG_INFO(...)		logs::WriteLog(LogLevel::LOG_INFO,	  __VA_ARGS__)
#define LOG_SUCCESS(...)    logs::WriteLog(LogLevel::LOG_SUCCESS, __VA_ARGS__)
#define LOG_ERROR(...)		logs::WriteLog(LogLevel::LOG_ERROR,	  __VA_ARGS__)
#define LOG_NONE(...)		logs::WriteLog(LogLevel::LOG_NONE,    __VA_ARGS__)
#define LOG_DISABLE(...)	logs::WriteLog(LogLevel::LOG_DISABLE, __VA_ARGS__)
#endif

#endif

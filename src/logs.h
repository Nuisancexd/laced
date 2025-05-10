#ifndef _LOGS_H_
#define _LOGS_H_

#include <Windows.h>
#include "memory.h"

enum class LogLevel : size_t
{
	LOG_INFO	= 0,
	LOG_ERROR	= 1,
	LOG_SUCCESS = 2,
	LOG_NONE	= 3
};


namespace logs
{
	VOID initLog(BOOL append = FALSE);
	VOID CloseLog();
	VOID WriteLog(LogLevel log, CONST WCHAR* Format, ...);
}

#ifndef _LOG_ENABLE_
#define LOG_INFO(...)		logs::WriteLog(LogLevel::LOG_INFO,	  __VA_ARGS__)
#define LOG_SUCCESS(...)    logs::WriteLog(LogLevel::LOG_SUCCESS, __VA_ARGS__)
#define LOG_ERROR(...)		logs::WriteLog(LogLevel::LOG_ERROR,	  __VA_ARGS__)
#define LOG_NONE(...)		logs::WriteLog(LogLevel::LOG_NONE,   __VA_ARGS__)
#else
#define LOG_INFO(...)		logs::WriteLog(LogLevel::LOG_INFO,	  __VA_ARGS__)
#define LOG_SUCCESS(...)    logs::WriteLog(LogLevel::LOG_SUCCESS, __VA_ARGS__)
#define LOG_ERROR(...)		logs::WriteLog(LogLevel::LOG_ERROR,	  __VA_ARGS__)
#define LOG_NONE(...)		logs::WriteLog(LogLevel::LOG_NONE,   __VA_ARGS__)

#endif

#endif

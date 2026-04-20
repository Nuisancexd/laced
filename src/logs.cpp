#include "logs.h"
#include "memory.h"
#include "CommandParser.h"

#include <mutex>
#include <cstring>


#include <fcntl.h>
#include <wchar.h>


STATIC DESC g_LogHandle = INVALID_HANDLE_VALUE;

#ifdef __linux__
#include <unistd.h> 
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#endif

STATIC CONST CHAR* crlf = "\r\n";
constexpr size_t LogSizeStr = 10;

STATIC CONST CHAR* LogLevelStr[] =
{
	"[INFO]    ",
	"[ERROR]   ",
	"[SUCCESS] ",
	"[NONE]    ",
	"[DISABLE] ",
	"[CMD_DIS] ",
	"[LOG_OUT]"
};


STATIC std::mutex mtx;
#ifdef __linux__
constexpr int MAX_PATH = 255;
#endif

constexpr size_t LogSize = sizeof(LogLevelStr) / sizeof(LogLevelStr[0]);
static char* ptr_dir = NULL;

VOID logs::call_log()
{
	LOG_DISABLE("LOGs saved in: " log_str, ptr_dir);
}


static bool check_file_exist(char* path)
{
	DESC desc = api::OpenFile(path);
	if (desc == INVALID_HANDLE_VALUE)
		return false;
	api::CloseDesc(desc);
	return true;
}


VOID logs::initLog(BOOL append)
{
	CONST unsigned max_path = MAX_PATH + MAX_PATH;
	char* curr_dir = (char*)memory::m_malloc(max_path);
	if (!api::GetExecPath(curr_dir, MAX_PATH))
	{
		printf("FAILED iNIT log\n");
		memory::m_free(curr_dir);
		return;
	}
	memcpy(&curr_dir[memory::StrLen(curr_dir)], slash, 1);
	memcpy(&curr_dir[memory::StrLen(curr_dir)], "LACED_LOG.txt", 13);
	ptr_dir = curr_dir;

	if (!check_file_exist(curr_dir))
		append = false;

#ifdef _WIN32
	DWORD flag = append ? OPEN_ALWAYS : CREATE_ALWAYS;
	g_LogHandle = CreateFileA
	(
		curr_dir,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		flag,
		FILE_FLAG_WRITE_THROUGH,
		NULL
	);

	if (g_LogHandle == INVALID_HANDLE_VALUE)
	{
		printf("Failed INIT LOG\n");
		return;
	}
	if (append)
		SetFilePointer(g_LogHandle, 0, NULL, FILE_END);
#else
	int flags = O_RDWR | O_SYNC;
	flags |= append ? O_APPEND : O_CREAT;
	if ((g_LogHandle = open(curr_dir, flags, S_IRWXU)) == -1)
	{
		printf("Failed INIT LOG\n");
		return;
	}
#endif
}

VOID logs::CloseLog()
{
#ifdef __linux__
	if (g_LogHandle != -1)
		api::CloseDesc(g_LogHandle);
	g_LogHandle = -1;
	fprintf(stderr, "\033[0;29m");
#elif _WIN32
	if (g_LogHandle && g_LogHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_LogHandle);
		g_LogHandle = INVALID_HANDLE_VALUE;
	}
#endif
	if (ptr_dir)
		memory::m_free(ptr_dir);
}

VOID SetConsoleColor(LogLevel level)
{
#ifdef __linux__
	switch (level)
	{
	case LogLevel::LOG_STDOUT:
		break;
	case LogLevel::LOG_INFO:
		fprintf(stderr,"\033[0;34m");
		break;
	case LogLevel::LOG_ERROR:
		fprintf(stderr,"\033[0;31m");
		break;
	case LogLevel::LOG_SUCCESS:
		fprintf(stderr,"\033[0;32m");
		break;
	case LogLevel::LOG_NONE:
		fprintf(stderr,"\033[0;36m");
		break;
	case LogLevel::LOG_DISABLE:
		fprintf(stderr,"\033[0;29m");
		break;
	case LogLevel::LOG_CMD_DIS:
		fprintf(stderr,"\033[0;29m");
		break;
	default:
		break;
	}
#elif _WIN32
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

	switch (level)
	{
	case LogLevel::LOG_INFO:
		color = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
		break;
	case LogLevel::LOG_ERROR:
		color = FOREGROUND_RED | FOREGROUND_INTENSITY;
		break;
	case LogLevel::LOG_SUCCESS:
		color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
		break;
	case LogLevel::LOG_NONE:
		break;
	case LogLevel::LOG_DISABLE:
		break;
	default:
		break;
	}

	SetConsoleTextAttribute(hConsole, color);
#endif
}

VOID ResetConsoleColor()
{
#ifdef __linux__
	fprintf(stderr, "\033[0");
#elif _WIN32
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#endif
}

VOID logs::WriteLog(LogLevel log, CONST CHAR* Format, ...)
{
	static bool b_stdout = (log == LogLevel::LOG_STDOUT);
	static bool b_console = !CommandParser::NOUT;
	static bool b_logfile = true;/*todo*/
                     		
                     		
	
	if(!b_stdout && !b_console && !b_logfile)
		return;

	size_t size_log = static_cast<size_t>(log);
	va_list args;
	char Buffer[1024];
	va_start(args, Format);
	int size = vsprintf(Buffer, Format, args);
	va_end(args);
	
	if (size == 0)
		return;
	if(b_stdout)
	{
		fprintf(stdout, "%s", Buffer);
	}
	
	if(b_console)
	{
		SetConsoleColor(log);
        fprintf(stderr, "%s\n", Buffer);
        ResetConsoleColor();
	}
	
	if(!b_logfile)
		return;
#ifdef __linux__
	char time_b[64];
	time_t now = time(NULL);
	struct tm* lt = localtime(&now);
	int written = 0;
	int TimeSize = sprintf(time_b,
		"[%04d-%02d-%02d %02d:%02d:%02d]\t",
		lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
		lt->tm_hour, lt->tm_min, lt->tm_sec);
#elif _WIN32
	CHAR time_b[128];
	SYSTEMTIME st;
	GetLocalTime(&st);
	INT TimeSize = sprintf(time_b, "[%04d-%02d-%02d %02d:%02d:%02d]\t",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	DWORD written = 0;
#endif

	api::WriteFile(g_LogHandle, time_b, TimeSize, &written);
	api::WriteFile(g_LogHandle, (CONST CHAR*)LogLevelStr[size_log], LogSizeStr, &written);
	api::WriteFile(g_LogHandle, Buffer, size, &written);
	api::WriteFile(g_LogHandle, crlf, 2, &written);
}

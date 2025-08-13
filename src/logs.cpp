#include "logs.h"
#include "memory.h"

#include <mutex>
#include <cstring>


#include <fcntl.h>
#include <wchar.h>
#ifdef _WIN32

STATIC HANDLE g_LogHandle = INVALID_HANDLE_VALUE;

#else
#include <unistd.h> 
#include <stdarg.h>
#include <time.h>
#include <locale.h>

STATIC int g_LogHandle = -1;

#endif

STATIC CONST CHAR* crlf = "\r\n";
constexpr size_t LogSizeStr = 10;

STATIC CONST CHAR* LogLevelStr[] =
{
	"[INFO]    ",
	"[ERROR]   ",
	"[SUCCESS] ",
	"[NONE]    ",
	"[ENABLE]  "
};


STATIC std::mutex mtx;
#ifdef __linux__
constexpr int MAX_PATH = 255;
#endif

constexpr size_t LogSize = sizeof(LogLevelStr) / sizeof(LogLevelStr[0]);
static TCHAR* ptr_dir = NULL;

VOID logs::call_log()
{
	LOG_ENABLE("LOGs saved in: " log_str, ptr_dir);
}


static bool check_file_exist(TCHAR* path)
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
	TCHAR* curr_dir = (TCHAR*)memory::m_malloc(max_path);

	if (!api::GetCurrentDir(curr_dir, MAX_PATH))
	{
		printf("FAILED iNIT log\n");
		return;
	}

	memc(&curr_dir[memory::StrLen(curr_dir)], slash, 1);
	memc(&curr_dir[memory::StrLen(curr_dir)], T("LACED_LOG.txt"), 13);
	ptr_dir = curr_dir;
	if (!check_file_exist(curr_dir))
		append = false;

#ifdef _WIN32
	DWORD flag = append ? OPEN_ALWAYS : CREATE_ALWAYS;
	g_LogHandle = CreateFileW
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

#ifdef __linux__
VOID logs::CloseLog()
{
	if (g_LogHandle != -1)
		api::CloseDesc(g_LogHandle);
	g_LogHandle = -1;
	if (ptr_dir)
		memory::m_free(ptr_dir);
}

VOID SetConsoleColor(LogLevel level);
VOID ResetConsoleColor();
VOID logs::WriteLog(LogLevel log, CONST CHAR* Format, ...)
{
	if (g_LogHandle == -1)
	{
		printf("Failed Handle WriteLog\n");
		ResetConsoleColor();
		return;
	}

	size_t size_log = static_cast<size_t>(log);
	if (size_log >= LogSize)
	{
		printf("Doesnt exists the log level\n");
		ResetConsoleColor();
		return;
	}

	va_list args;
	CHAR Buffer[1024];

	va_start(args, Format);

	int size = vsprintf(Buffer, Format, args);

	va_end(args);

	if (size == 0)
		return;

	std::lock_guard<std::mutex> lock(mtx);
	SetConsoleColor(log);
	printf("%s\n", Buffer);
	if (log == LogLevel::LOG_ENABLE)
		return;
	ResetConsoleColor();
	CHAR time_b[64];
	time_t now = time(NULL);
	struct tm* lt = localtime(&now);
	int written = 0;
	int TimeSize = sprintf(time_b,
		"[%04d-%02d-%02d %02d:%02d:%02d]\t",
		lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
		lt->tm_hour, lt->tm_min, lt->tm_sec);

	api::WriteFile(g_LogHandle, time_b, TimeSize, &written);
	api::WriteFile(g_LogHandle, LogLevelStr[size_log], LogSizeStr, &written);
	api::WriteFile(g_LogHandle, Buffer, size, &written);
	api::WriteFile(g_LogHandle, crlf, 2, &written);
}

VOID SetConsoleColor(LogLevel level)
{
	switch (level)
	{
	case LogLevel::LOG_INFO:
		printf("\033[0;34m");
		break;
	case LogLevel::LOG_ERROR:
		printf("\033[0;31m");
		break;
	case LogLevel::LOG_SUCCESS:
		printf("\033[0;32m");
		break;
	case LogLevel::LOG_NONE:
		printf("\033[0;36m");
		break;
	case LogLevel::LOG_ENABLE:
		printf("\033[0;29m");
		break;
	default:
		break;
	}
}

VOID ResetConsoleColor()
{
	printf("\033[0");
}

#endif

#ifdef _WIN32
VOID logs::CloseLog()
{
	if (g_LogHandle && g_LogHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_LogHandle);
		g_LogHandle = INVALID_HANDLE_VALUE;
	}
	if (ptr_dir)
		memory::m_free(ptr_dir);
}

VOID SetConsoleColor(LogLevel level);
VOID ResetConsoleColor();
VOID logs::WriteLog(LogLevel log, CONST CHAR* Format, ...)
{
	if (g_LogHandle == INVALID_HANDLE_VALUE)
	{
		printf("Failed Handle WriteLog\n");
		return;
	}

	size_t size_log = static_cast<size_t>(log);
	if (size_log >= LogSize)
	{
		printf("Doesnt exists the log level\n");
		return;
	}

	va_list args;
	CHAR Buffer[1024];

	va_start(args, Format);

	INT size = vsprintf(Buffer, Format, args);

	va_end(args);

	if (size == 0)
		return;

	std::lock_guard<std::mutex> lock(mtx);
	SetConsoleColor(log);
	printf("%s\n", Buffer);
	if (log == LogLevel::LOG_ENABLE)
		return;
	ResetConsoleColor();
	CHAR time[128];
	SYSTEMTIME st;
	GetLocalTime(&st);
	INT TimeSize = sprintf(time, "[%04d-%02d-%02d %02d:%02d:%02d]\t",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	DWORD Written;

	if (TimeSize)
		WriteFile(g_LogHandle, time, TimeSize, &Written, NULL);

	WriteFile(g_LogHandle, LogLevelStr[size_log], LogSizeStr, &Written, NULL);
	WriteFile(g_LogHandle, Buffer, size, &Written, NULL);
	WriteFile(g_LogHandle, crlf, 2, &Written, NULL);
}


VOID SetConsoleColor(LogLevel level)
{
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
	case LogLevel::LOG_ENABLE:
		break;
	default:
		break;
	}

	SetConsoleTextAttribute(hConsole, color);
}


VOID ResetConsoleColor()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}
#endif
#include "logs.h"

#include <mutex>

STATIC HANDLE g_LogHandle = NULL;
STATIC CONST WCHAR* crlf = L"\r\n";
STATIC std::mutex mtx;

STATIC CONST WCHAR* LogLevelStr[] = 
{	
	L"[INFO]    ",	
	L"[ERROR]   ",
	L"[SUCCESS] ",
	L"[NONE]    "
};
constexpr size_t LogSize = sizeof(LogLevelStr) / sizeof(LogLevelStr[0]);
constexpr size_t wLogSizeStr = 10 * sizeof(WCHAR);

VOID logs::initLog(BOOL append)
{
	if (g_LogHandle && g_LogHandle != INVALID_HANDLE_VALUE)
	{
		printf("Failed INIT LOG1\n");
		return;
	}

	CONST unsigned max_path = MAX_PATH + MAX_PATH;
	WCHAR curr_dir[max_path];
	INT size = GetCurrentDirectoryW(max_path, curr_dir);
	if (size == 0 || size >= max_path || (size + 14) > max_path)
	{
		printf("Failed INIT LOG2\n");
		return;
	}
	wmemcpy(&curr_dir[size], L"\\LACED_LOG.txt", 15);
	printf("LOGs saved in:  %ls\n", curr_dir);
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
		printf("Failed INIT LOG3\n");
		return;
	}

	if (append)
		SetFilePointer(g_LogHandle, 0, NULL, FILE_END);
	else
		SetFilePointer(g_LogHandle, 0, NULL, FILE_BEGIN);
}

VOID logs::CloseLog()
{
	if (g_LogHandle && g_LogHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(g_LogHandle);
		g_LogHandle = INVALID_HANDLE_VALUE;
	}
}

VOID SetConsoleColor(LogLevel level);
VOID ResetConsoleColor();
VOID logs::WriteLog(LogLevel log, CONST WCHAR* Format, ...)
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
	WCHAR Buffer[1024];

	va_start(args, Format);

	INT size = wvsprintfW(Buffer, Format, args);

	va_end(args);

	if (size == 0)
		return;

	std::lock_guard<std::mutex> lock(mtx);
	SetConsoleColor(log);
	printf("%ls\n", Buffer);
	ResetConsoleColor();
	WCHAR time[128];
	SYSTEMTIME st;
	GetLocalTime(&st);
	INT TimeSize = wsprintfW(time, L"[%04d-%02d-%02d %02d:%02d:%02d]\t",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	DWORD Written;
	
	if (TimeSize)
		WriteFile(g_LogHandle, time, TimeSize * sizeof(WCHAR), &Written, NULL);

	
	WriteFile(g_LogHandle, LogLevelStr[size_log], wLogSizeStr, &Written, NULL);
	WriteFile(g_LogHandle, Buffer, size * sizeof(WCHAR), &Written, NULL);
	WriteFile(g_LogHandle, crlf, 4, &Written, NULL);
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

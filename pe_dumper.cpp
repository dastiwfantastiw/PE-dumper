#include "pe_dumper.h"

VOID print_error(CONST CHAR* FailedFunctionName)
{
	DWORD ErrorCode = GetLastError();
	CHAR* Message = 0;

	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, ErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&Message, 0, NULL);
	printf("[-] %s failed with errorcode = 0x%08X (%s)\n", ErrorCode, Message);
}

int main()
{
	INT args_count = 0;
	LPWSTR* lpCmdLine = CommandLineToArgvW(GetCommandLineW(), &args_count);
	if (args_count > 1)
		dump(lpCmdLine[1]);
	else
		printf("usage: pe_dumper.exe <PID or processname>\n");
    return 0;
}

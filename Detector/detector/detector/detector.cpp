#include <Windows.h>
#include <fltuser.h>
#include <psapi.h>
#include <stdio.h>
#include <winternl.h>
#include <atomic>
#include <algorithm>
#include <thread>
#include <tdh.h>
#include <vector>
#include <comdef.h>
#include <tlhelp32.h>

#define PORT_NAME L"\\MyFilterPort"
#define BUFFER_SIZE 1024
#define MAX_MSG_LEN 512

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

HANDLE gPort = NULL;
static std::atomic<bool> g_Running(true);

PPEB GetPebAddress(HANDLE hProcess) {
	// Tải hàm từ ntdll.dll
	NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		wprintf(L"Failed to load NtQueryInformationProcess: %lu\n", GetLastError());
		return nullptr;
	}

	PROCESS_BASIC_INFORMATION pbi;
	ULONG returnLength = 0;
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
	if (NT_SUCCESS(status)) {
		return (PPEB)pbi.PebBaseAddress;
	}
	return nullptr;
}

PVOID GetImageBaseAddress(HANDLE hProcess) {
	HMODULE hModule;
	DWORD cbNeeded;
	if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded)) {
		MODULEINFO moduleInfo;
		if (GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
			return moduleInfo.lpBaseOfDll; // Đây là ImageBaseAddress
		}
	}
	return nullptr;
}

BOOL EnableDebugPrivilege() {
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	BOOL success = (GetLastError() == ERROR_SUCCESS);
	CloseHandle(hToken);
	return success;
}

void PrintLastError(DWORD error, DWORD pid, LPCWSTR exeName, PVOID allocationBase) {
	LPWSTR messageBuffer = nullptr;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, nullptr);
	wprintf(L"[ALERT - MEM] PID %lu (%ws): Main module at %p unbacked! Error %lu: %ws\n",
		pid, exeName, allocationBase, error, messageBuffer);
	LocalFree(messageBuffer);
}

void ScanRunningProcesses() {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
		return;
	}

	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	if (!Process32First(hProcessSnap, &pe32)) {
		printf("Process32First failed: %lu\n", GetLastError());
		CloseHandle(hProcessSnap);
		return;
	}

	printf("Scanning running processes...\n");
	do {
		if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4) continue;
		if (!EnableDebugPrivilege()) {
			wprintf(L"Failed to enable SeDebugPrivilege\n");
			return;
		}
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
		if (!hProcess) continue;

		PPEB pPeb = GetPebAddress(hProcess);
		if (pPeb) {
			PEB pebCopy;
			if (ReadProcessMemory(hProcess, pPeb, &pebCopy, sizeof(PEB), NULL)) {
				PVOID imageBaseInPeb = GetImageBaseAddress(hProcess);

				MEMORY_BASIC_INFORMATION mbi;
				unsigned char* addr = 0;
				while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
					if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE && mbi.AllocationBase == imageBaseInPeb) {
						WCHAR mappedFileName[MAX_PATH] = { 0 };
						DWORD len = GetMappedFileNameW(hProcess, mbi.AllocationBase, mappedFileName, MAX_PATH);
						if (len == 0) {
							DWORD error = GetLastError();
							wprintf(L"[ALERT - MEM] PID %lu (%ws): Main module at %p unbacked! Error: %lu\n",
								pe32.th32ProcessID, pe32.szExeFile, mbi.AllocationBase, error);
							PrintLastError(error, pe32.th32ProcessID, pe32.szExeFile, mbi.AllocationBase);
						}
					}
					addr += mbi.RegionSize;
					if (mbi.RegionSize == 0) break;
				}
			}
		}
		CloseHandle(hProcess);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
}

void ScanThreadFunc() {
	while (TRUE) {
		ScanRunningProcesses();
		// Sleep để tránh quét quá nhanh
		Sleep(10000);
	}
}

bool kill_process_by_pid(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProcess == NULL) {
		printf("OpenProcess failed: %lu\n",GetLastError());
		return false;
	}

	BOOL result = TerminateProcess(hProcess, 0);
	if (!result) {
		printf("TerminateProcess failed: %lu\n", GetLastError());
		CloseHandle(hProcess);
		return false;
	}

	CloseHandle(hProcess);
	return true;
}

void Mornitor() {
	HRESULT hr;
	DWORD bytesReturned;
	BYTE messageBuffer[BUFFER_SIZE] = { 0 };

	// Kết nối đến MiniFilter
	hr = FilterConnectCommunicationPort(
		PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&gPort
	);

	if (FAILED(hr)) {
		wprintf(L"[!] Failed to connect to port: 0x%x\n", hr);
		return;
	}

	wprintf(L"[+] Suceeded to connect to  mini-filter port.\n");

	while (TRUE) {
		// Nhận message từ driver
		WCHAR message[MAX_MSG_LEN] = { 0 };
		hr = FilterGetMessage(
			gPort,
			(PFILTER_MESSAGE_HEADER)message,
			sizeof(message),
			NULL
		);

		if (SUCCEEDED(hr)) {
			PFILTER_MESSAGE_HEADER header = (PFILTER_MESSAGE_HEADER)message;
			WCHAR* content = (WCHAR*)(header + 1);
			ULONG pid;
			wchar_t imagePath[MAX_PATH] = L"";
			if (wcsstr(content, L"DOPPELGANGING DETECTED")) {
				WCHAR* pidStart = wcsstr(content, L"PID ");
				if (pidStart != NULL) {
					if (swscanf_s(pidStart, L"PID %lu", &pid) == 1) {
						HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
						if (hProcess) {
							DWORD size = MAX_PATH;
							if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &size)) {
								// Nối đường dẫn vào cuối message
								wcscat_s(content, 1024, L" - Path: ");
								wcscat_s(content, 1024, imagePath);
							}
							CloseHandle(hProcess);
						}
						if (kill_process_by_pid(pid)) {
							wprintf(L"Kill Process PID = %lu\n", pid);
						}

					}
					else {
						wprintf(L"[!] Failed to parse PID from: %s\n", pidStart);
					}
				}
				else {
					wprintf(L"[!] 'PID ' substring not found in message\n");
				}
			}
			// Xử lý payload (ví dụ: in ra string)
			wprintf(L"[>] message: %s\n", content);
		}
		else {
			wprintf(L"[!] Error message: 0x%x\n", hr);
			break;
		}
	}

	CloseHandle(gPort);
}

int wmain(int argc, wchar_t* argv[]) {

	Mornitor();

	
	return 0;
}

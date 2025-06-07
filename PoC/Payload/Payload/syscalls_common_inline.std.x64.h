#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>

#define SW2_SEED 0xD713E92B
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(PCSTR FunctionName);
BOOL SW2_PopulateSyscallList(void);
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemHandleInformation = 16,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS NtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL);

EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtTestAlert();

EXTERN_C NTSTATUS NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtSuspendProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount);

EXTERN_C NTSTATUS NtResumeProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext);

EXTERN_C NTSTATUS NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context);

EXTERN_C NTSTATUS NtClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

EXTERN_C NTSTATUS NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

EXTERN_C NTSTATUS NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress);

EXTERN_C NTSTATUS NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

#endif



#include <time.h>
#include <stdint.h>

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW2_SYSCALL_LIST SW2_SyscallList = { 0, 1 };

#ifdef RANDSYSCALL
#ifndef _WIN64
uint32_t ntdllBase = 0;
#else
uint64_t ntdllBase = 0;
#endif
#endif

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

BOOL SW2_PopulateSyscallList(void)
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

#if defined(_WIN64)
    PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
#else
    PSW2_PEB Peb = (PSW2_PEB)__readfsdword(0x30);
#endif
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;
    
#ifdef RANDSYSCALL
#ifdef _WIN64
    ntdllBase = (uint64_t)DllBase;
#else
    ntdllBase = (uint64_t)DllBase;
#endif
#endif

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

#ifdef RANDSYSCALL
#ifdef _WIN64
EXTERN_C uint64_t SW2_GetRandomSyscallAddress(void)
#else
EXTERN_C DWORD SW2_GetRandomSyscallAddress(int callType)
#endif
{
    int instructOffset = 0;
    int instructValue = 0;
#ifndef _WIN64
    // Wow64
    if (callType == 0)
    {
        instructOffset = 0x05;
        instructValue = 0x0E8;
    }
    // x86
    else if (callType == 1)
    {
        instructOffset = 0x05;
        instructValue = 0x0BA;
    }
#else
    instructOffset = 0x12;
    instructValue = 0x0F;
#endif
    srand(time(0));
    do
    {
        int randNum = (rand() % (SW2_SyscallList.Count + 1));
        if (*(unsigned char*)(ntdllBase + SW2_SyscallList.Entries[randNum].Address + instructOffset) == instructValue)
            return (ntdllBase + SW2_SyscallList.Entries[randNum].Address + instructOffset);
    } while(1);
}
#endif


#define WhisperMain
__asm__(".intel_syntax noprefix \n\
.global WhisperMain \n\
WhisperMain: \n\
    pop rax \n\
    mov [rsp+ 8], rcx \n\
    mov [rsp+16], rdx \n\
    mov [rsp+24], r8 \n\
    mov [rsp+32], r9 \n\
    sub rsp, 0x28 \n\
    mov rcx, r10 \n\
    call SW2_GetSyscallNumber \n\
    add rsp, 0x28 \n\
    mov rcx, [rsp+ 8] \n\
    mov rdx, [rsp+16] \n\
    mov r8, [rsp+24] \n\
    mov r9, [rsp+32] \n\
    mov r10, rcx \n\
    syscall \n\
    ret \n\
");

#define ZwCreateProcess NtCreateProcess
__asm__(".intel_syntax noprefix \n\
NtCreateProcess: \n\
    mov r10, 0x01D867E68 \n\
    call WhisperMain \n\
");


#define ZwCreateThreadEx NtCreateThreadEx
__asm__(".intel_syntax noprefix \n\
NtCreateThreadEx: \n\
    mov r10, 0x064BB286E \n\
    call WhisperMain \n\
");


#define ZwOpenProcess NtOpenProcess
__asm__(".intel_syntax noprefix \n\
NtOpenProcess: \n\
    mov r10, 0x0FDB713D7 \n\
    call WhisperMain \n\
");


#define ZwOpenProcessToken NtOpenProcessToken
__asm__(".intel_syntax noprefix \n\
NtOpenProcessToken: \n\
    mov r10, 0x06BD92F10 \n\
    call WhisperMain \n\
");


#define ZwTestAlert NtTestAlert
__asm__(".intel_syntax noprefix \n\
NtTestAlert: \n\
    mov r10, 0x088ABEB74 \n\
    call WhisperMain \n\
");


#define ZwOpenThread NtOpenThread
__asm__(".intel_syntax noprefix \n\
NtOpenThread: \n\
    mov r10, 0x0FADEF66E \n\
    call WhisperMain \n\
");


#define ZwSuspendProcess NtSuspendProcess
__asm__(".intel_syntax noprefix \n\
NtSuspendProcess: \n\
    mov r10, 0x021BE2A22 \n\
    call WhisperMain \n\
");


#define ZwSuspendThread NtSuspendThread
__asm__(".intel_syntax noprefix \n\
NtSuspendThread: \n\
    mov r10, 0x0FB47A9FE \n\
    call WhisperMain \n\
");


#define ZwResumeProcess NtResumeProcess
__asm__(".intel_syntax noprefix \n\
NtResumeProcess: \n\
    mov r10, 0x0843F85B3 \n\
    call WhisperMain \n\
");


#define ZwResumeThread NtResumeThread
__asm__(".intel_syntax noprefix \n\
NtResumeThread: \n\
    mov r10, 0x06AD62275 \n\
    call WhisperMain \n\
");


#define ZwGetContextThread NtGetContextThread
__asm__(".intel_syntax noprefix \n\
NtGetContextThread: \n\
    mov r10, 0x02CBB262D \n\
    call WhisperMain \n\
");


#define ZwSetContextThread NtSetContextThread
__asm__(".intel_syntax noprefix \n\
NtSetContextThread: \n\
    mov r10, 0x0158F4B3C \n\
    call WhisperMain \n\
");


#define ZwClose NtClose
__asm__(".intel_syntax noprefix \n\
NtClose: \n\
    mov r10, 0x09CCD834F \n\
    call WhisperMain \n\
");


#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtReadVirtualMemory: \n\
    mov r10, 0x0C851EEF0 \n\
    call WhisperMain \n\
");


#define ZwWriteVirtualMemory NtWriteVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtWriteVirtualMemory: \n\
    mov r10, 0x07D9F6B31 \n\
    call WhisperMain \n\
");


#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtAllocateVirtualMemory: \n\
    mov r10, 0x019902919 \n\
    call WhisperMain \n\
");


#define ZwProtectVirtualMemory NtProtectVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtProtectVirtualMemory: \n\
    mov r10, 0x0252ED226 \n\
    call WhisperMain \n\
");


#define ZwFreeVirtualMemory NtFreeVirtualMemory
__asm__(".intel_syntax noprefix \n\
NtFreeVirtualMemory: \n\
    mov r10, 0x084969009 \n\
    call WhisperMain \n\
");


#define ZwQuerySystemInformation NtQuerySystemInformation
__asm__(".intel_syntax noprefix \n\
NtQuerySystemInformation: \n\
    mov r10, 0x0C28AE046 \n\
    call WhisperMain \n\
");


#define ZwQueryDirectoryFile NtQueryDirectoryFile
__asm__(".intel_syntax noprefix \n\
NtQueryDirectoryFile: \n\
    mov r10, 0x0AA38996E \n\
    call WhisperMain \n\
");


#define ZwQueryInformationFile NtQueryInformationFile
__asm__(".intel_syntax noprefix \n\
NtQueryInformationFile: \n\
    mov r10, 0x070E47872 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationProcess NtQueryInformationProcess
__asm__(".intel_syntax noprefix \n\
NtQueryInformationProcess: \n\
    mov r10, 0x051AA6008 \n\
    call WhisperMain \n\
");


#define ZwQueryInformationThread NtQueryInformationThread
__asm__(".intel_syntax noprefix \n\
NtQueryInformationThread: \n\
    mov r10, 0x02E8A0C0B \n\
    call WhisperMain \n\
");


#define ZwCreateSection NtCreateSection
__asm__(".intel_syntax noprefix \n\
NtCreateSection: \n\
    mov r10, 0x074245EF9 \n\
    call WhisperMain \n\
");


#define ZwOpenSection NtOpenSection
__asm__(".intel_syntax noprefix \n\
NtOpenSection: \n\
    mov r10, 0x09F18DFCA \n\
    call WhisperMain \n\
");


#define ZwMapViewOfSection NtMapViewOfSection
__asm__(".intel_syntax noprefix \n\
NtMapViewOfSection: \n\
    mov r10, 0x00E972807 \n\
    call WhisperMain \n\
");


#define ZwUnmapViewOfSection NtUnmapViewOfSection
__asm__(".intel_syntax noprefix \n\
NtUnmapViewOfSection: \n\
    mov r10, 0x036AA3C0F \n\
    call WhisperMain \n\
");


#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__(".intel_syntax noprefix \n\
NtAdjustPrivilegesToken: \n\
    mov r10, 0x03F850B1C \n\
    call WhisperMain \n\
");


#define ZwDeviceIoControlFile NtDeviceIoControlFile
__asm__(".intel_syntax noprefix \n\
NtDeviceIoControlFile: \n\
    mov r10, 0x0C8D8C04E \n\
    call WhisperMain \n\
");


#define ZwQueueApcThread NtQueueApcThread
__asm__(".intel_syntax noprefix \n\
NtQueueApcThread: \n\
    mov r10, 0x0F673A445 \n\
    call WhisperMain \n\
");


#define ZwWaitForMultipleObjects NtWaitForMultipleObjects
__asm__(".intel_syntax noprefix \n\
NtWaitForMultipleObjects: \n\
    mov r10, 0x03D80C5ED \n\
    call WhisperMain \n\
");



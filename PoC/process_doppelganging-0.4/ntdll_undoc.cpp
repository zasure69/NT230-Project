#include "ntdll_undoc.h"

NTSTATUS (NTAPI *NtCreateProcessEx)
(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes  OPTIONAL,
    IN HANDLE   ParentProcess,
    IN ULONG    Flags,
    IN HANDLE   SectionHandle OPTIONAL,
    IN HANDLE   DebugPort OPTIONAL,
    IN HANDLE   ExceptionPort OPTIONAL,
    IN BOOLEAN  InJob
) = NULL;

NTSTATUS (NTAPI *RtlCreateProcessParametersEx)(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
) = NULL;

NTSTATUS (NTAPI *NtCreateThreadEx) (
    OUT  PHANDLE ThreadHandle, 
    IN  ACCESS_MASK DesiredAccess, 
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
    IN  HANDLE ProcessHandle,
    IN  PVOID StartRoutine,
    IN  PVOID Argument OPTIONAL,
    IN  ULONG CreateFlags,
    IN  ULONG_PTR ZeroBits, 
    IN  SIZE_T StackSize OPTIONAL,
    IN  SIZE_T MaximumStackSize OPTIONAL, 
    IN  PVOID AttributeList OPTIONAL
) = NULL;

NTSTATUS(NTAPI* NtResumeThread)(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
) = NULL;

NTSTATUS(NTAPI* NtRollbackTransaction)(
    IN HANDLE TransactionHandle,
    IN BOOLEAN Wait
) = NULL;

NTSTATUS(NTAPI* NtCreateTransaction)(
    OUT PHANDLE TransactionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN LPGUID Uow OPTIONAL,
    IN HANDLE TmHandle OPTIONAL,
    IN ULONG CreateOptions OPTIONAL,
    IN ULONG IsolationLevel OPTIONAL,
    IN ULONG IsolationFlags OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    IN PUNICODE_STRING Description OPTIONAL
) = NULL;

bool init_ntdll_func()
{
    HMODULE lib = LoadLibraryA("ntdll.dll");
    if (lib == nullptr) {
        return false;
    }
    FARPROC proc = GetProcAddress(lib, "NtCreateProcessEx");
    if (proc == nullptr) {
        return false;
    }
    NtCreateProcessEx = (NTSTATUS (NTAPI *)(
        PHANDLE,
        ACCESS_MASK,
        POBJECT_ATTRIBUTES,
        HANDLE,
        ULONG,
        HANDLE,
        HANDLE,
        HANDLE,
        BOOLEAN
    )) proc;

    proc = GetProcAddress(lib, "RtlCreateProcessParametersEx");
    if (proc == nullptr) {
        return false;
    }
    RtlCreateProcessParametersEx = (NTSTATUS (NTAPI *)(
        PRTL_USER_PROCESS_PARAMETERS*,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PVOID,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        PUNICODE_STRING,
        ULONG 
    )) proc;

    proc = GetProcAddress(lib, "NtCreateThreadEx");
    if (proc == nullptr) {
        return false;
    }
    NtCreateThreadEx = (NTSTATUS (NTAPI *)(
      PHANDLE, 
      ACCESS_MASK, 
      POBJECT_ATTRIBUTES, 
      HANDLE,
      PVOID,
      PVOID,
      ULONG,
      ULONG_PTR, 
      SIZE_T,
      SIZE_T, 
      PVOID
    )) proc;

    proc = GetProcAddress(lib, "NtResumeThread");
    if (proc == nullptr) {
        return false;
    }
    NtResumeThread = (NTSTATUS(NTAPI*)(
        HANDLE,
        PULONG
        )) proc;

    proc = GetProcAddress(lib, "NtRollbackTransaction");
    if (proc == nullptr) {
        return false;
    }
    NtRollbackTransaction = (NTSTATUS(NTAPI*)(
        IN HANDLE,
        IN BOOLEAN 
    )) proc;

    proc = GetProcAddress(lib, "NtCreateTransaction");
    if (proc == nullptr) {
        return false;
    }
    NtCreateTransaction = (NTSTATUS(NTAPI*)(
        OUT PHANDLE,
        IN ACCESS_MASK,
        IN POBJECT_ATTRIBUTES,
        IN LPGUID,
        IN HANDLE,
        IN ULONG,
        IN ULONG,
        IN ULONG,
        IN PLARGE_INTEGER,
        IN PUNICODE_STRING
    )) proc;
    return true;
}

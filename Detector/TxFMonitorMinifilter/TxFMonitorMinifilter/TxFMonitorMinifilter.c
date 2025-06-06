/*++

Module Name:

    TxFMonitorMinifilter.c

Abstract:

    This is the main module of the TxFMonitorMinifilter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include <initguid.h> 
#include <ntifs.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define IOCTL_TOCTOU_REPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FILE_TRACK_FLAG_OPENED              0x00000001  // File đã được mở
#define FILE_TRACK_FLAG_WRITTEN				0x00000002  // Section đã được tạo từ file
#define FILE_TRACK_FLAG_SECTION_CREATED     0x00000004  // File thuộc transaction đã rollback
#define FILE_TRACK_FLAG_ROLLBACKED          0x00000008  // Section image đã bị rollback nhưng được thực thi
#define MAX_MSG_LEN 512

DEFINE_GUID(GUID_ECP_CREATE_USER_PROCESS, 0xe0e429ff, 0x6ddc, 0x4e65, 0xaa, 0xb6, 0x45, 0xd0, 0x5a, 0x3, 0x8a, 0x8);

typedef struct _TOCTOU_PROCESS_INFO {
	ULONG ProcessId;
} TOCTOU_PROCESS_INFO;

typedef struct _MY_TRANSACTION_CONTEXT {
	USHORT miniTransactionID;
	PFILE_OBJECT FileObject;
} MY_TRANSACTION_CONTEXT, *PMY_TRANSACTION_CONTEXT;

typedef struct _TX_INFO {
	LIST_ENTRY ListEntry;
	PFILE_OBJECT FileObject;
	HANDLE Pid;
	USHORT miniTransactionID;
	ULONG Flags;
} TX_INFO, *PTX_INFO;

LIST_ENTRY g_TxFileList;
FAST_MUTEX g_ListLock;

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;

// Connection callback
NTSTATUS ConnectNotifyCallback(
	PFLT_PORT ClientPort,
	PVOID ServerPortCookie,
	PVOID ConnectionContext,
	ULONG SizeOfContext,
	PVOID *ConnectionPortCookie
) {
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	g_ClientPort = ClientPort;
	return STATUS_SUCCESS;
}

// Disconnection callback
VOID DisconnectNotifyCallback(PVOID ConnectionPortCookie) {
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	if (g_ClientPort) {
		FltCloseClientPort(gFilterHandle, &g_ClientPort);
		g_ClientPort = NULL;
	}
}

// Message callback
NTSTATUS MessageNotifyCallback(
	PVOID PortCookie,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength,
	PULONG ReturnOutputBufferLength
) {
	UNREFERENCED_PARAMETER(PortCookie);

	if (InputBufferLength < sizeof(CHAR)) {
		return STATUS_INVALID_PARAMETER;
	}

	DbgPrint("Mini-Filter received: %s\n", (char*)InputBuffer);

	if (OutputBuffer && OutputBufferLength >= sizeof("ACK")) {
		RtlCopyMemory(OutputBuffer, "ACK", 3);
		*ReturnOutputBufferLength = 3;
	}

	return STATUS_SUCCESS;
}

// Create communication port
NTSTATUS CreateCommunicationPort() {
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\MyFilterPort");

	

	PSECURITY_DESCRIPTOR sd;
	FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	InitializeObjectAttributes(&objAttr, &portName, OBJ_KERNEL_HANDLE, NULL, sd);
	NTSTATUS status = FltCreateCommunicationPort(
		gFilterHandle,
		&g_ServerPort,
		&objAttr,
		NULL,
		ConnectNotifyCallback,
		DisconnectNotifyCallback,
		MessageNotifyCallback,
		1
	);

	FltFreeSecurityDescriptor(sd);
	return status;
}

// Send message from kernel to user-mode
void SendMessageToUserMode(ULONG ProcessId) {
	if (g_ClientPort) {
		WCHAR message[MAX_MSG_LEN] = { 0 };
		LARGE_INTEGER systemTime, localTime;
		TIME_FIELDS tf;

		KeQuerySystemTime(&systemTime);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &tf);
		swprintf_s(
			message, MAX_MSG_LEN,
			L"[%04d-%02d-%02d %02d:%02d:%02d] DOPPELGANGING DETECTED - PID %lu",
			tf.Year, tf.Month, tf.Day,
			tf.Hour, tf.Minute, tf.Second,
			ProcessId
		);

		ULONG replyLength = 0;

		NTSTATUS status = FltSendMessage(
			gFilterHandle,
			&g_ClientPort,
			message,
			(ULONG)(wcslen(message) + 1) * sizeof(WCHAR),  // gửi cả null terminator
			NULL,
			&replyLength,
			NULL
		);

		if (NT_SUCCESS(status)) {
			DbgPrint("Sent message to user: %ws\n", message);
		}
		else {
			DbgPrint("FltSendMessage failed: 0x%x\n", status);
		}
	}
	else {
		DbgPrint("Client not connected\n");
	}
}



void SendAlertOpenFileMessageToUserMode(
	ULONG ProcessId,
	UNICODE_STRING ImagePath,
	USHORT miniTransactionID
) {
	if (g_ClientPort) {
		WCHAR message[MAX_MSG_LEN] = { 0 };
		LARGE_INTEGER systemTime, localTime;
		TIME_FIELDS tf;

		KeQuerySystemTime(&systemTime);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &tf);
		swprintf_s(
			message, MAX_MSG_LEN,
			L"[%04d-%02d-%02d %02d:%02d:%02d] PID: %lu open file %wZ in transaction %lu",
			tf.Year, tf.Month, tf.Day,
			tf.Hour, tf.Minute, tf.Second,
			ProcessId,
			ImagePath,
			miniTransactionID
		);

		ULONG replyLength = 0;

		NTSTATUS status = FltSendMessage(
			gFilterHandle,
			&g_ClientPort,
			message,
			(ULONG)(wcslen(message) + 1) * sizeof(WCHAR),  // gửi cả null terminator
			NULL,
			&replyLength,
			NULL
		);

		if (NT_SUCCESS(status)) {
			DbgPrint("Sent message to user: %ws\n", message);
		}
		else {
			DbgPrint("FltSendMessage failed: 0x%x\n", status);
		}
	}
	else {
		DbgPrint("Client not connected\n");
	}
}

void SendAlertWriteFileMessageToUserMode(
	ULONG ProcessId,
	UNICODE_STRING ImagePath,
	USHORT miniTransactionID
) {
	if (g_ClientPort) {
		WCHAR message[MAX_MSG_LEN] = { 0 };
		LARGE_INTEGER systemTime, localTime;
		TIME_FIELDS tf;

		KeQuerySystemTime(&systemTime);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &tf);
		swprintf_s(
			message, MAX_MSG_LEN,
			L"[%04d-%02d-%02d %02d:%02d:%02d] PID: %lu wrote file %wZ in transaction %lu",
			tf.Year, tf.Month, tf.Day,
			tf.Hour, tf.Minute, tf.Second,
			ProcessId,
			ImagePath,
			miniTransactionID
		);

		ULONG replyLength = 0;

		NTSTATUS status = FltSendMessage(
			gFilterHandle,
			&g_ClientPort,
			message,
			(ULONG)(wcslen(message) + 1) * sizeof(WCHAR),  // gửi cả null terminator
			NULL,
			&replyLength,
			NULL
		);

		if (NT_SUCCESS(status)) {
			DbgPrint("Sent message to user: %ws\n", message);
		}
		else {
			DbgPrint("FltSendMessage failed: 0x%x\n", status);
		}
	}
	else {
		DbgPrint("Client not connected\n");
	}
}

void SendAlertCreateSectionMessageToUserMode(
	ULONG ProcessId,
	UNICODE_STRING ImagePath,
	USHORT miniTransactionID
) {
	if (g_ClientPort) {
		WCHAR message[MAX_MSG_LEN] = { 0 };
		LARGE_INTEGER systemTime, localTime;
		TIME_FIELDS tf;

		KeQuerySystemTime(&systemTime);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &tf);
		swprintf_s(
			message, MAX_MSG_LEN,
			L"[%04d-%02d-%02d %02d:%02d:%02d] PID: %lu create section from file %wZ open in transaction %lu",
			tf.Year, tf.Month, tf.Day,
			tf.Hour, tf.Minute, tf.Second,
			ProcessId,
			ImagePath,
			miniTransactionID
		);

		ULONG replyLength = 0;

		NTSTATUS status = FltSendMessage(
			gFilterHandle,
			&g_ClientPort,
			message,
			(ULONG)(wcslen(message) + 1) * sizeof(WCHAR),  // gửi cả null terminator
			NULL,
			&replyLength,
			NULL
		);

		if (NT_SUCCESS(status)) {
			DbgPrint("Sent message to user: %ws\n", message);
		}
		else {
			DbgPrint("FltSendMessage failed: 0x%x\n", status);
		}
	}
	else {
		DbgPrint("Client not connected\n");
	}
}

void SendAlertRollbackMessageToUserMode(
	ULONG ProcessId,
	USHORT miniTransactionID
) {
	if (g_ClientPort) {
		WCHAR message[MAX_MSG_LEN] = { 0 };
		LARGE_INTEGER systemTime, localTime;
		TIME_FIELDS tf;

		KeQuerySystemTime(&systemTime);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &tf);
		swprintf_s(
			message, MAX_MSG_LEN,
			L"[%04d-%02d-%02d %02d:%02d:%02d] PID: %lu rollback transaction %lu", 
			tf.Year, tf.Month, tf.Day,
			tf.Hour, tf.Minute, tf.Second,
			ProcessId,
			miniTransactionID
		);

		ULONG replyLength = 0;

		NTSTATUS status = FltSendMessage(
			gFilterHandle,
			&g_ClientPort,
			message,
			(ULONG)(wcslen(message) + 1) * sizeof(WCHAR),  // gửi cả null terminator
			NULL,
			&replyLength,
			NULL
		);

		if (NT_SUCCESS(status)) {
			DbgPrint("Sent message to user: %ws\n", message);
		}
		else {
			DbgPrint("FltSendMessage failed: 0x%x\n", status);
		}
	}
	else {
		DbgPrint("Client not connected\n");
	}
}

NTSTATUS
TxFMonitorUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);
	
	ExAcquireFastMutex(&g_ListLock);
	PLIST_ENTRY entry = g_TxFileList.Flink;
	while (entry != &g_TxFileList) {
		PTX_INFO info = CONTAINING_RECORD(entry, TX_INFO, ListEntry);
		PLIST_ENTRY next = entry->Flink;
		RemoveEntryList(entry);
		ObDereferenceObject(info->FileObject);
		ExFreePool(info);
		entry = next;
	}
	ExReleaseFastMutex(&g_ListLock);
	FltUnregisterFilter(gFilterHandle);
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
TxFMonitorPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);
	NTSTATUS status;

	PTX_INFO newEntry;

	if (FltObjects->Transaction) {
		DbgPrint("[TxFmonitor] File open in transaction, pid = %lu\n", PsGetCurrentProcessId());
		PFLT_CONTEXT pTxnCtx = NULL;

		status = FltAllocateContext(
			gFilterHandle,
			FLT_TRANSACTION_CONTEXT,
			sizeof(MY_TRANSACTION_CONTEXT),
			PagedPool,
			&pTxnCtx
		);

		if (NT_SUCCESS(status)) {
			RtlZeroMemory(pTxnCtx, sizeof(MY_TRANSACTION_CONTEXT));
			((PMY_TRANSACTION_CONTEXT)pTxnCtx)->miniTransactionID = FltObjects->TransactionContext; 
			((PMY_TRANSACTION_CONTEXT)pTxnCtx)->FileObject = FltObjects->FileObject;
			ObReferenceObject(((PMY_TRANSACTION_CONTEXT)pTxnCtx)->FileObject);
			status = FltSetTransactionContext(
				FltObjects->Instance,
				FltObjects->Transaction,
				FLT_SET_CONTEXT_KEEP_IF_EXISTS,
				pTxnCtx,
				NULL
			);

			status = FltEnlistInTransaction(FltObjects->Instance, FltObjects->Transaction, pTxnCtx, TRANSACTION_NOTIFY_ROLLBACK);
			if (!NT_SUCCESS(status)) {
				DbgPrint("[TxFMonitor] FltEnlistInTransaction failed: 0x%x\n", status);
			}
			else {
				DbgPrint("[TxFMonitor] Enlisted in transaction\n");
			}

			newEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(TX_INFO), 'txnt');
			if (newEntry) {
				RtlZeroMemory(newEntry, sizeof(TX_INFO));
				newEntry->FileObject = FltObjects->FileObject;
				ObReferenceObject(newEntry->FileObject);
				newEntry->miniTransactionID = FltObjects->TransactionContext;
				newEntry->Pid = PsGetCurrentProcessId();
				newEntry->Flags = FILE_TRACK_FLAG_OPENED;
				ExAcquireFastMutex(&g_ListLock);
				InsertTailList(&g_TxFileList, &newEntry->ListEntry);
				ExReleaseFastMutex(&g_ListLock);
				SendAlertOpenFileMessageToUserMode(HandleToULong(PsGetCurrentProcessId()), FltObjects->FileObject->FileName, FltObjects->TransactionContext);
			}


		}
		else {
			FltReleaseContext(pTxnCtx);
		}

		
	}
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
TxFMonitorPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Data);



	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
TxFMonitorTransactionNotificationCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_CONTEXT TransactionContext,
	_In_ ULONG TransactionNotification
)
{

	UNREFERENCED_PARAMETER(FltObjects);
	switch (TransactionNotification) {
	case TRANSACTION_NOTIFY_COMMIT:
		DbgPrint("[TxFMonitor] Transaction COMMIT for pid %lu\n", PsGetCurrentProcessId());
		// TODO: Check ECP và MmDoesFileHaveUserWritableReferences tại đây
		break;

	case TRANSACTION_NOTIFY_ROLLBACK:
		DbgPrint("[TxFMonitor] Transaction ROLLBACK for pid %lu\n", PsGetCurrentProcessId());
		ExAcquireFastMutex(&g_ListLock);
		PMY_TRANSACTION_CONTEXT txnCtx = (PMY_TRANSACTION_CONTEXT)TransactionContext;
		for (PLIST_ENTRY entry = g_TxFileList.Flink; entry != &g_TxFileList; entry = entry->Flink) {
			PTX_INFO info = CONTAINING_RECORD(entry, TX_INFO, ListEntry);
			DbgPrint("[Notify rollback] tracked file object: %p, current file object: %p\n", info->FileObject, txnCtx->FileObject);
			if (info->FileObject == txnCtx->FileObject) {
				DbgPrint("Tracked file object rollback, flag: %lu", info->Flags);
				if ((info->Flags & 0x7) == 0x7) {
					SendAlertRollbackMessageToUserMode(HandleToULong(PsGetCurrentProcessId()), info->miniTransactionID);
					SendMessageToUserMode(HandleToULong(PsGetCurrentProcessId()));
				}
				else {
					SendAlertRollbackMessageToUserMode(HandleToULong(PsGetCurrentProcessId()), info->miniTransactionID);
				}
				info->Flags |= FILE_TRACK_FLAG_ROLLBACKED;

			}
		}

		ExReleaseFastMutex(&g_ListLock);
		break;

	default:
		break;
	}
	return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
PreAcquireForSectionSynchronization(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Outptr_result_maybenull_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects);
	PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
	ExAcquireFastMutex(&g_ListLock);

	for (PLIST_ENTRY entry = g_TxFileList.Flink; entry != &g_TxFileList; entry = entry->Flink) {
		PTX_INFO info = CONTAINING_RECORD(entry, TX_INFO, ListEntry);
		DbgPrint("[callback of section]tracked file object: %p, current file object: %p\n", info->FileObject, fileObject);
		if (info->FileObject == fileObject) {
			info->Flags |= FILE_TRACK_FLAG_SECTION_CREATED;
			DbgPrint("Section created from tracked file object");
			SendAlertCreateSectionMessageToUserMode(HandleToULong(PsGetCurrentProcessId()), info->FileObject->FileName, info->miniTransactionID);
		}
	}

	ExReleaseFastMutex(&g_ListLock);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
PostWriteCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (!NT_SUCCESS(Data->IoStatus.Status)) {
		// Ghi không thành công, log lỗi nếu cần
		DbgPrint("PostWrite - Write failed: 0x%x\n", Data->IoStatus.Status);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (FltObjects->Transaction) {
		DbgPrint("fileobject write in transaction");
		PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
		if (fileObject) {
			ExAcquireFastMutex(&g_ListLock);

			for (PLIST_ENTRY entry = g_TxFileList.Flink; entry != &g_TxFileList; entry = entry->Flink) {
				PTX_INFO info = CONTAINING_RECORD(entry, TX_INFO, ListEntry);
				DbgPrint("[callback of write]tracked file object: %p, current file object: %p\n", info->FileObject, fileObject);
				if (info->FileObject == fileObject) {
					info->Flags |= FILE_TRACK_FLAG_WRITTEN;
					DbgPrint("tracked file object written");
					SendAlertWriteFileMessageToUserMode(HandleToULong(PsGetCurrentProcessId()), info->FileObject->FileName, info->miniTransactionID);
				}
			}

			ExReleaseFastMutex(&g_ListLock);
		}
		else {
			DbgPrint("fileobject write null");
		}
	}
	
	

	return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID FLTAPI MyTransactionContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
) {
	UNREFERENCED_PARAMETER(ContextType);
	PMY_TRANSACTION_CONTEXT txnCtx = (PMY_TRANSACTION_CONTEXT)Context;
	ObDereferenceObject(txnCtx->FileObject);

}

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	  0,
	  TxFMonitorPreCreate,
	  TxFMonitorPostCreate,
	},
	{ IRP_MJ_WRITE, 
	  0, 
	  NULL, 
	  PostWriteCallback 
    },
	{
		IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
		0,
		PreAcquireForSectionSynchronization,
		NULL,
	},
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
	{
		FLT_TRANSACTION_CONTEXT,         // Context type
		0,                               // Flags
		MyTransactionContextCleanup,     // CleanupCallback
		sizeof(MY_TRANSACTION_CONTEXT),  // ContextSize
		'txc1'                           // Pool Tag
	},
	{ FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	ContextRegistration,                // Context
	Callbacks,           // Operation callbacks
	TxFMonitorUnload,    // FilterUnloadCallback
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	TxFMonitorTransactionNotificationCallback,
	NULL,
	NULL
};



NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	InitializeListHead(&g_TxFileList);
	ExInitializeFastMutex(&g_ListLock);
	DbgPrint("Driver Entry");

	NTSTATUS status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);
	if (NT_SUCCESS(status)) {
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status)) {
			FltUnregisterFilter(gFilterHandle);
		}
	}

	status = CreateCommunicationPort();
	if (!NT_SUCCESS(status)) {
		DbgPrint("[TxFMonitor] Create communication port failed: 0x%x\n", status);
		FltUnregisterFilter(gFilterHandle);
		return status;
	}
	return status;
}

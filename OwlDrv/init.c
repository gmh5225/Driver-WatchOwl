/*++

Copyright (c) 2022 Rad K.

Module Name:

	DrvMain.c

Abstract:

	This module initializes the dependencies for WatchOwl Driver.

Author:

	Rad K. (rad98)			14-Nov-2022

Revision History:

--*/

#include "precomp.h"	
#include "odp.h"		
#include "types.h"

//
// Private constants.
//
static const WCHAR ntdllImageName[] = L"NTDLL.dll";
static const WCHAR kernel32ImageName[] = L"KERNEL32.dll";
static const WCHAR kernelbaseImageName[] = L"KERNELBASE.dll";

//
// Private types.
//
typedef struct _ODP_MODULE_INFORMATION
{
	UNICODE_STRING  DllName;
	PVOID           TxtBase;
	DWORD           DllSize;
} ODP_MODULE_INFORMATION;

//
// Private prototypes.
//
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
EXTERN_C NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID OwlDrvUnload(
	_In_ PDRIVER_OBJECT DriverObject
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OwlDrvCleanup(
	VOID
);

_Function_class_(PLOAD_IMAGE_NOTIFY_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OwlImageLoadHandler(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
);

_Function_class_(PCREATE_THREAD_NOTIFY_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OwlNewThreadHandler(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
);

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
OdpVerifyImageMapStackTrace(
	VOID
);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
OdpCaptureStack(
	_Out_ PVOID* Frames,
	_In_ ULONG Count
);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
OdpSystemProcessInformationWrapper(
	_Out_ PVOID* buffer
);

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID OdpResolveSymbol(
	_In_z_ PCWSTR DllName,
	_In_z_ PCSTR RoutineName,
	_In_ PVOID buffer
);

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID OdpGetSystemRoutineAddress(
	_In_z_ PCWSTR SystemRoutineName
);

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID OdpGetProcedureAddress(
	_In_ PVOID BaseAddress,
	_In_z_ PCSTR RoutineName
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OdpTryPopulateModuleInfo(
	_In_ PCUNICODE_STRING basename,
	_In_ LDR_DATA_TABLE_ENTRY* entry
);

// 
// Private globals.
//

RTL_OSVERSIONINFOEXW OdpOsVersionInfo;
PVOID ImageLoadCallbackExpectedFrames[2];
ODP_MODULE_INFORMATION ModuleInformation[3];

// 
// Public globals.
//

//
// Callback routines bools
//
BOOLEAN OwlImageLoadHandlerSet = FALSE;
BOOLEAN OwlNewThreadHandlerSet = FALSE;

//
// Module information bool
//
BOOLEAN ModuleInformationSet = FALSE;

//
// Public functions.
//

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for OwlDrv device driver.

Arguments:

	DriverObject - Supplies a pointer to driver object created by the
		system.

	RegistryPath - Supplies the name of the driver's configuration
		registry tree.

Return Value:

	NTSTATUS - Completion status.

--*/
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	PVOID buffer = NULL;
	USHORT retOffset = 0x10;
	PAGED_PASSIVE();

	DbgPrintLine("Driver Loading...");

	//
	// Create Dispatch Points
	//
	DriverObject->DriverUnload = OwlDrvUnload;

	OdpOsVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)&OdpOsVersionInfo);
	if (!NT_SUCCESS(status))
	{
		DbgPrintLine("RtlGetVersion failed: status=0x%x",
			status);

		goto Exit;
	}
	

	if (OdpOsVersionInfo.dwMajorVersion >= 10)
	{
		retOffset = 0x14;
	}
	
	RtlInitUnicodeString(&ModuleInformation[0].DllName, ntdllImageName);
	RtlInitUnicodeString(&ModuleInformation[1].DllName, kernel32ImageName);
	RtlInitUnicodeString(&ModuleInformation[2].DllName, kernelbaseImageName);
	ModuleInformationSet = FALSE;

	status = OdpSystemProcessInformationWrapper(&buffer);
	if (!NT_SUCCESS(status) &&
		buffer == NULL)
	{
		goto Exit;
	}

	ImageLoadCallbackExpectedFrames[0] = (PVOID)((ULONG_PTR)OdpResolveSymbol(ntdllImageName, "NtMapViewOfSection", buffer) + retOffset);
	DbgPrintLine("ImageLoadCallbackExpectedFrames[0]: 0x%p", ImageLoadCallbackExpectedFrames[0]);
	ImageLoadCallbackExpectedFrames[1] = (PVOID)((ULONG_PTR)OdpResolveSymbol(ntdllImageName, "RtlUserThreadStart", buffer));
	DbgPrintLine("ImageLoadCallbackExpectedFrames[1]: 0x%p", ImageLoadCallbackExpectedFrames[1]);



	if (buffer)
		ExFreePoolWithTag(buffer, FILTER_TAG);

	status = PsSetLoadImageNotifyRoutine(OwlImageLoadHandler);
	if (!NT_SUCCESS(status))
	{
		DbgPrintLine("PsSetLoadImageNotifyRoutine failed: status=0x%x",
			status);

		goto Exit;
	} else {
		OwlImageLoadHandlerSet = TRUE;
	}

	status = PsSetCreateThreadNotifyRoutine(OwlNewThreadHandler);
	if (!NT_SUCCESS(status))
	{
		DbgPrintLine("PsSetCreateThreadNotifyRoutine failed: status=0x%x",
			status);

		goto Exit;
	} else {
		OwlNewThreadHandlerSet = TRUE;
	}

Exit:
	if (!NT_SUCCESS(status))
	{		
		OwlDrvCleanup();

		DbgPrintLine("Driver Loading Error: status=0x%x",
			status);
	}
	else
	{
		DbgPrintLine("Driver Loaded...");
	}

	return status;
}

_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID OwlDrvUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
/*++

Routine Description:

	Routine to free all resources allocated to the driver

Arguments:

	DriverObject - pointer to the driver object originally passed
				   to the DriverEntry routine

Return Value:

	VOID

--*/
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrintLine("Driver Unloading...");

	OwlDrvCleanup();

	DbgPrintLine("Driver Unloaded...");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OwlDrvCleanup(
	VOID
)
/*++

Routine Description:

	Cleans up the driver state

Return Value:

	VOID

--*/
{
	NTSTATUS status;

	PAGED_PASSIVE();
	if (OwlImageLoadHandlerSet == TRUE)
	{
		status = PsRemoveLoadImageNotifyRoutine(OwlImageLoadHandler);
		if (!NT_SUCCESS(status)) {
			DbgPrintLine("PsRemoveLoadImageNotifyRoutine Error: status=0x%x",
				status);
		}
		OwlImageLoadHandlerSet = FALSE;
	}
	//OwlNewThreadHandlerSet
	if (OwlNewThreadHandlerSet == TRUE)
	{
		status = PsRemoveCreateThreadNotifyRoutine(OwlNewThreadHandler);
		if (!NT_SUCCESS(status)) {
			DbgPrintLine("PsRemoveCreateThreadNotifyRoutine Error: status=0x%x",
				status);
		}
		OwlNewThreadHandlerSet = FALSE;
	}
}


_Function_class_(PLOAD_IMAGE_NOTIFY_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OwlImageLoadHandler(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
/*++

Routine Description:

	Callback on image load notifications

Arguments:

	Process - pointer to the executable image name

	ProcessId - process ID of the process in which the image has been mapped

	CreateInfo - structure supplied by the callback containing information about
		the image

Return Value:

	VOID

--*/
{
	if (FullImageName != NULL && 
		ImageInfo != NULL &&
		ProcessId != 0 &&
		ImageInfo->SystemModeImage == 0)
		//
		// We only want user space images
		//
	{
		// ImageInfo->ImageSignatureLevel < SE_SIGNING_LEVEL_WINDOWS

		BOOLEAN valid = OdpVerifyImageMapStackTrace();
		DbgPrintLine("(PID %d) %s\t%wZ", (ULONG)(ULONG_PTR)ProcessId,
			valid ? "Legitimate" : "Illegitimate", FullImageName);
		if (!valid) {
			if (ImageInfo->ImageSignatureLevel < SE_SIGNING_LEVEL_WINDOWS)
			{
				DbgPrintLine("!!!!!!!!!!\nSignature Level: 0x%x\n!!!!!!!!!!",
					ImageInfo->ImageSignatureLevel);
				DbgBreakPoint();
			}
		}
	
	}
}

_Function_class_(PCREATE_THREAD_NOTIFY_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OwlNewThreadHandler(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
)
/*++

Routine Description:

	Callback on thread execution

Arguments:

	ProcessId - The process ID of the process of new thread

	ThreadId - The thread ID of the new thread

	Create - Specifies if the thread was created or deleted

Return Value:

	VOID

--*/
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);

	PAGED_PASSIVE();

	NTSTATUS status;
	PETHREAD threadObject = NULL;
	HANDLE threadHandle = NULL;
	PVOID address;
	ULONG returnLength;

	if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &threadObject)))
	{
		status = ObOpenObjectByPointer(threadObject, OBJ_KERNEL_HANDLE, NULL,
			STANDARD_RIGHTS_ALL, *PsThreadType, KernelMode,
			&threadHandle);
		if (!NT_SUCCESS(status))
		{
			goto Exit;
		}

		status = ZwQueryInformationThread(threadHandle, ThreadQuerySetWin32StartAddress,
			&address, sizeof(PVOID), &returnLength);

		ObCloseHandle(threadHandle, KernelMode);

		if (NT_SUCCESS(status))
		{
			DbgPrintLine("Thread Start Address: 0x%p", address);
		}
	}

Exit:
	if (threadObject)
	{
		ObDereferenceObject(threadObject);
	}
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
OdpVerifyImageMapStackTrace(
	VOID
)
/*++

Routine Description:

	Captures and verifies a stack trace using various measures

Return Value:

	VOID

--*/
{
	ULONG count;
	PVOID frames[150];
	BOOLEAN originating = FALSE;

	count = OdpCaptureStack(frames, ARRAYSIZE(frames));

	for (ULONG i = 0; i < count; i++)
	{
		if (frames[i] == ImageLoadCallbackExpectedFrames[0])
		{
			//
			// frames[i - 1] -> nt!KiSystemServiceCopyEnd
			//
			// frames[i] -> ntdll!NtMapViewOfSection
			//
			// frames[i + 1] -> ntdll/kernel32/kernelbase .text section
			//

			if ((i + 1) < count) DbgPrintLine("frames[i+1]: 0x%p", frames[i + 1]);
			if (ModuleInformationSet &&
				(i + 1) < count) {
				for (unsigned j = 0; j < ARRAYSIZE(ModuleInformation); j++)
				{
					if (frames[i + 1] >= ModuleInformation[j].TxtBase &&
						frames[i + 1] <= (PVOID)((ULONG_PTR)ModuleInformation[j].TxtBase 
											+ ModuleInformation[j].DllSize))
					{
						originating = TRUE;
					}
				}
			}
			else {
				originating = TRUE;
			}
			break;
		}
		else if (frames[i] == ImageLoadCallbackExpectedFrames[1])
		{
			originating = TRUE;
			//
			// RtlUserThreadStart is the last frame
			//
			break;
		}
	}

	return originating;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
OdpCaptureStack(
	_Out_ PVOID* Frames,
	_In_ ULONG Count
)
/*++

Routine Description:

	Callback on image load notifications

Arguments:

	Frames - Array of PVOIDs 

	Count - Size of the Frames Array

Return Value:

	ULONG - number of frames captured

--*/
{
	ULONG frames;

	PAGED_CODE();

	frames = RtlWalkFrameChain(Frames, Count, 0);

	if (KeGetCurrentIrql() < DISPATCH_LEVEL)
	{
		if (frames >= Count)
		{
			return frames;
		}

		frames += RtlWalkFrameChain(&Frames[frames],
									(Count - frames),
									0x1);
	}

	return frames;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS 
OdpSystemProcessInformationWrapper(
	_Out_ PVOID* buffer
)
/*++

Routine Description:

	Populates the provided buffer with a snapshot of the running processes

Arguments:

	buffer - Buffer to be allocated with paged pool memory. Must be deallocated 
		once finished.

Return Value:

	NTSTATUS - Completion status

--*/
{
	ULONG size;
	NTSTATUS status;

	PAGED_PASSIVE();

	size = (PAGE_SIZE * 4);
	*buffer = ExAllocatePoolZero(PagedPool, size, FILTER_TAG);
	if (!*buffer)
	{
		DbgPrintLine("Error allocating buffer.");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	for (;;)
	{
		status = ZwQuerySystemInformation(SystemProcessInformation,
			*buffer,
			size,
			&size);

		if (NT_SUCCESS(status))
		{
			break;
		}

		if ((status != STATUS_BUFFER_TOO_SMALL) &&
			(status != STATUS_INFO_LENGTH_MISMATCH))
		{
			goto Exit;
		}

		if (size == 0)
		{
			NT_ASSERT(!NT_SUCCESS(status));
			goto Exit;
		}

		ExFreePoolWithTag(*buffer, FILTER_TAG);
		*buffer = ExAllocatePoolZero(PagedPool, size, FILTER_TAG);
		if (!*buffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto Exit;
		}
	}

	NT_ASSERT(size >= sizeof(SYSTEM_PROCESS_INFORMATION));

Exit:
	return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID OdpResolveSymbol(
	_In_z_ PCWSTR DllName,
	_In_z_ PCSTR RoutineName,
	_In_ PVOID buffer
)
/*++

Routine Description:

	Resolve the address of a function exported by a DLL loaded into CSRSS.exe

Arguments:

	DllName - Name of userland DLL

	RoutineName - Exported Function Name

	buffer - buffer containing PSYSTEM_PROCESS_INFORMATION

Return Value:

	PVOID - Userland address of function (NULL in event of failure)

--*/
{
	PVOID address = NULL;
	NTSTATUS status = STATUS_INVALID_ADDRESS;
	PSYSTEM_PROCESS_INFORMATION systemInfo;
	UNICODE_STRING csrssName;
	UNICODE_STRING dllName;
	const WCHAR csrssImage[] = L"csrss.exe";
	
	RtlInitUnicodeString(&csrssName, csrssImage);
	RtlInitUnicodeString(&dllName, DllName);

	PAGED_PASSIVE();

	systemInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

	while (1)
	{
		if (address) break;
		if (RtlEqualUnicodeString(&systemInfo->ImageName, &csrssName, TRUE))
		{
			PEPROCESS processObject;
			KAPC_STATE apcState;

			DbgPrintLine("Image: %wZ Pid: %d",
				systemInfo->ImageName, (PVOID)systemInfo->UniqueProcessId);

			status = PsLookupProcessByProcessId(systemInfo->UniqueProcessId,
				&processObject);
			KeStackAttachProcess(processObject, &apcState);

			if (!NT_SUCCESS(status))
				continue;

			PEB* csrssPeb = (PEB*)PsGetProcessPeb(processObject);

			__try
			{
				LIST_ENTRY* head = &csrssPeb->Ldr->InMemoryOrderModuleList;
				LIST_ENTRY* next = head->Flink;

				while (next != head)
				{
					LDR_DATA_TABLE_ENTRY* entry =
						CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
					const UNICODE_STRING* basename = (UNICODE_STRING*)((BYTE*)&entry->FullDllName
						+ sizeof(UNICODE_STRING));

					OdpTryPopulateModuleInfo(basename, entry);

					if (RtlEqualUnicodeString(basename, &dllName, TRUE)) {
						DbgPrintLine("Name: %wZ Base: 0x%p", basename, entry->DllBase);
						address = OdpGetProcedureAddress(entry->DllBase, RoutineName);
						if (address != NULL) {
							status = STATUS_SUCCESS;
						}
						else {
							status = STATUS_INVALID_ADDRESS;
						}
					}

					next = next->Flink;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrintLine("Critical Error Parsing Peb: 0x%x", GetExceptionCode());
				status = STATUS_INVALID_ADDRESS;
			}

			KeUnstackDetachProcess(&apcState);

			DbgPrintLine("CSRSS PEB: 0x%p", csrssPeb);

			ObDereferenceObject(processObject);
		}
		if (systemInfo->NextEntryOffset)
		{
			systemInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)systemInfo + systemInfo->NextEntryOffset);
		}
		else
		{
			break;
		}
	}


	if (!NT_SUCCESS(status))
	{
		DbgPrintLine("OdpResolveSymbol Erorr: status=0x%x", status);
	}
	if (!ModuleInformationSet) {
		ModuleInformationSet = TRUE;
	}
	return address;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID OdpGetSystemRoutineAddress(
	_In_z_ PCWSTR SystemRoutineName
)
/*++

Routine Description:

	Resolve a system routine function address

Arguments:

	SystemRoutineName - Exported Function Name

Return Value:

	PVOID - Kernel mode address of function (NULL in event of failure)

--*/
{
	UNICODE_STRING systemRoutineName;

	PAGED_PASSIVE();

	RtlInitUnicodeString(&systemRoutineName, SystemRoutineName);

	return MmGetSystemRoutineAddress(&systemRoutineName);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID OdpGetProcedureAddress(
	_In_ PVOID BaseAddress,
	_In_z_ PCSTR RoutineName
)
/*++

Routine Description:

	Locates the userland address of the provided routine 

Arguments:

	BaseAddress - Base of DLL in userland

	RoutineName - Exported Function Name

Return Value:

	PVOID - Userland mode address of function (NULL in event of failure)

--*/
{
	PAGED_PASSIVE();

	if ((BaseAddress != NULL) &&
		(RoutineName != NULL))
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)BaseAddress;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + dos->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)BaseAddress +
			nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		if (exports->NumberOfNames != 0 &&
			exports->AddressOfNames != 0 &&
			exports->AddressOfFunctions != 0)
		{
			PUSHORT ordinals = (PUSHORT)((ULONG_PTR)BaseAddress + exports->AddressOfNameOrdinals);
			PULONG names = (PULONG)((ULONG_PTR)BaseAddress + exports->AddressOfNames);
			PULONG functions = (PULONG)((ULONG_PTR)BaseAddress + exports->AddressOfFunctions);

			for (DWORD i = 0; i < exports->NumberOfNames; i++) {
				LPSTR name = (LPSTR)((ULONG_PTR)BaseAddress + names[i]);
				int diff = strcmp(name, RoutineName);
				if (diff == 0) {
					return (PVOID)((ULONG_PTR)BaseAddress + functions[ordinals[i]]);
				}
			}
		}
	}
	return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID OdpTryPopulateModuleInfo(
	_In_ PCUNICODE_STRING basename,
	_In_ LDR_DATA_TABLE_ENTRY* entry
)
/*++

Routine Description:

	Tries to populate ModuleInformation with information if ModuleInformationSet
	is unset.

Arguments:

	basename - DLL to look for 

	entry - Pointer to LDTE to lookup against

--*/
{
	PAGED_PASSIVE();

	if (!ModuleInformationSet &&
		basename != NULL && 
		entry != NULL)
	{
		for (unsigned i = 0; i < ARRAYSIZE(ModuleInformation); i++)
		{

			if (ModuleInformation[i].DllName.Buffer != NULL &&	// short-circuit eval
				RtlEqualUnicodeString(basename, &ModuleInformation[i].DllName, TRUE))
			{
				PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)entry->DllBase
					+ ((PIMAGE_DOS_HEADER)entry->DllBase)->e_lfanew);

				for (int j = 0; j < nt->FileHeader.NumberOfSections; j++) {
					const PIMAGE_SECTION_HEADER section =
						(PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt) +
							(DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * j);

					if ((*(ULONG*)section->Name | 0x20202020) == 'xet.') {
						ModuleInformation[i].DllSize = section->Misc.VirtualSize;
						ModuleInformation[i].TxtBase = (PVOID)((ULONG_PTR)entry->DllBase
							+ section->VirtualAddress);

						DbgPrintLine("%wZ .text 0x%p 0x%x", basename,
							ModuleInformation[i].TxtBase,
							ModuleInformation[i].DllSize);

						break;
					}
				}
			}
		}
	}
}
#include <ntddk.h>
#include "List.h"
#include "Callbacks.h"

HANDLE          gDllHandle = NULL;

extern "C"
NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
	NTSTATUS            Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES   ObjectAttributes = { 0 };
    UNICODE_STRING      DllPath = RTL_CONSTANT_STRING(L"\\dosdevices\\c:\\Beholder_Eye.dll");
    IO_STATUS_BLOCK     IoStatusBlock = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    InitializeObjectAttributes(&ObjectAttributes, &DllPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(&gDllHandle, GENERIC_EXECUTE, &ObjectAttributes, &IoStatusBlock, NULL, 0, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;

	Status = PsSetCreateThreadNotifyRoutine(ThreadNotification);
	if (!NT_SUCCESS(Status))
		return Status;

    InitContextList();
    if (!NT_SUCCESS(Status))
        return Status;

    Status = PsSetLoadImageNotifyRoutine(LoadImageNotification);
    if (!NT_SUCCESS(Status))
        return Status;

	return STATUS_SUCCESS;
}
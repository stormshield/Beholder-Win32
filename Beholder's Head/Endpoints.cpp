#include <ntddk.h>
#include "List.h"
#include "Callbacks.h"

HANDLE          gDllHandle32 = NULL;
#ifdef _AMD64_
HANDLE          gDllHandle64 = NULL;
#endif

extern "C"
NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
    NTSTATUS            Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES   ObjectAttributes = { 0 };
    UNICODE_STRING      DllPath32 = RTL_CONSTANT_STRING(L"\\dosdevices\\c:\\Beholder_Eye32.dll");
#ifdef _AMD64_
    UNICODE_STRING      DllPath64 = RTL_CONSTANT_STRING(L"\\dosdevices\\c:\\Beholder_Eye64.dll");
#endif
    IO_STATUS_BLOCK     IoStatusBlock = { 0 };

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    __debugbreak();

    InitializeObjectAttributes(&ObjectAttributes, &DllPath32, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(&gDllHandle32, GENERIC_EXECUTE, &ObjectAttributes, &IoStatusBlock, NULL, 0, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;

#ifdef _AMD64_
    InitializeObjectAttributes(&ObjectAttributes, &DllPath64, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(&gDllHandle64, GENERIC_EXECUTE, &ObjectAttributes, &IoStatusBlock, NULL, 0, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(gDllHandle32);
        return Status;
    }
#endif

    InitContextList();
    if (!NT_SUCCESS(Status))
    {
        ZwClose(gDllHandle32);
#ifdef _AMD64_
        ZwClose(gDllHandle64);
#endif
        return Status;
    }

    Status = PsSetCreateThreadNotifyRoutine(ThreadNotification);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(gDllHandle32);
#ifdef _AMD64_
        ZwClose(gDllHandle64);
#endif
        return Status;
    }

    Status = PsSetLoadImageNotifyRoutine(LoadImageNotification);
    if (!NT_SUCCESS(Status))
    {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotification);
        ZwClose(gDllHandle32);
#ifdef _AMD64_
        ZwClose(gDllHandle64);
#endif
        return Status;
    }

    return STATUS_SUCCESS;
}
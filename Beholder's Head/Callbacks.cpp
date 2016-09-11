#include <ntddk.h>
#include "List.h"
#include "Injector.h"

VOID ThreadNotification(__in HANDLE ProcessID, __in HANDLE ThreadID, __in BOOLEAN Create)
{
    PINJECT_CONTEXT InjectContext = NULL;

    if (Create == TRUE)
        return;

    InjectContext = SearchForContext(ProcessID, ThreadID);
    if (InjectContext == NULL)
        return;

    ZwUnmapViewOfSection(InjectContext->ProcessHandle, InjectContext->DllSectionHandle);
    ZwUnmapViewOfSection(InjectContext->ProcessHandle, InjectContext->InputMappingAddress);
    ZwClose(InjectContext->InputSectionHandle);
    ZwClose(InjectContext->DllSectionHandle);
    ZwClose(InjectContext->ProcessHandle);

    ExFreePoolWithTag(InjectContext, 'ewom');
}

VOID    LoadImageNotification(__in_opt PUNICODE_STRING FullImageName, __in HANDLE ProcessId, __in PIMAGE_INFO ImageInfo)
{
    const UNICODE_STRING Kernel32SysRootString = RTL_CONSTANT_STRING(L"\\kernel32.dll");
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(ProcessId);

    if (FullImageName == NULL ||
        FullImageName->Buffer == NULL ||
        FullImageName->Length < (sizeof(L"kernel32.dll") - 2) ||
        !wcswcs(FullImageName->Buffer, L"kernel32.dll"))
        return;

    Status = LoadDllInCurrentProcess(ImageInfo->ImageBase, ImageInfo->ImageSize);
}
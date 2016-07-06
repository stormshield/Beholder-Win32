#pragma once

#include <ntddk.h>

typedef struct
{
    HANDLE      ProcessHandle;
    HANDLE      DllSectionHandle;
    PVOID       DllMappingAddress;
    HANDLE      InputSectionHandle;
    PVOID       InputMappingAddress;
    HANDLE      ThreadHandle;
    CLIENT_ID   ClientID;
}   INJECT_CONTEXT, *PINJECT_CONTEXT;


NTSTATUS			LoadDllInCurrentProcess(__in PVOID Kernel32Address, __in SIZE_T Kernel32Size);
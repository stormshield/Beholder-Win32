#include <ntifs.h>
#include <ntddk.h>
#include "Injector.h"
#include "List.h"
#include "../Beholder's Eye/DllParams.h"

extern HANDLE gDllHandle32;
#ifdef _AMD64_
extern HANDLE gDllHandle64;
#endif

#define SEC_IMAGE       0x01000000
#define SEC_NO_CHANGE   0x00400000

typedef NTSTATUS(NTAPI *RtlCreateUserThreadFunc)(__in		HANDLE                  ProcessHandle,
                                                 __in_opt	PSECURITY_DESCRIPTOR    SecurityDescriptor,
                                                 __in		BOOLEAN                 CreateSuspended,
                                                 __in		ULONG                   StackZeroBits,
                                                 __inout	PULONG                  StackReserved,
                                                 __inout	PULONG                  StackCommit,
                                                 __in		PVOID                   StartAddress,
                                                 __in_opt	PVOID                   StartParameter,
                                                 __out		PHANDLE                 ThreadHandle,
                                                 __out		PCLIENT_ID              ClientID);


NTSTATUS                LoadDllInCurrentProcess(__in PVOID Kernel32Address, __in SIZE_T Kernel32Size)
{
    NTSTATUS            Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES   ObjectAttributes = { 0 };
    PMDL                ParamMDL = NULL;
    PVOID               SystemAddress = NULL;
    CLIENT_ID           ClientID = { 0 };
    SIZE_T              ViewSize = 0;
    PDLL_PARAMS         DllParam = NULL;
    LARGE_INTEGER       MappingSize = { 0 };
    PINJECT_CONTEXT     InjectContext = NULL;
    HANDLE              ThreadHandle = NULL;
    HANDLE              ProcessHandle = NULL;
    PVOID               DllMappingAddress = NULL;
    HANDLE              DllSectionHandle = NULL;
    HANDLE              InputSectionHandle = NULL;
    PVOID               InputMappingAddress = NULL;
    static RtlCreateUserThreadFunc RtlCreateUserThreadPtr = NULL;

    __debugbreak();

    if (RtlCreateUserThreadPtr == NULL)
    {
        UNICODE_STRING	RtlCreateUserThreadStr = RTL_CONSTANT_STRING(L"RtlCreateUserThread");
        RtlCreateUserThreadFunc RtlCreateUserThreadTemp = NULL;

        RtlCreateUserThreadTemp = (RtlCreateUserThreadFunc)MmGetSystemRoutineAddress((PUNICODE_STRING)&RtlCreateUserThreadStr);
        InterlockedCompareExchangePointer((PVOID*)&RtlCreateUserThreadPtr, (PVOID)RtlCreateUserThreadTemp, NULL);
    }

    Status = ObOpenObjectByPointer(PsGetCurrentProcess(), OBJ_KERNEL_HANDLE, NULL, STANDARD_RIGHTS_READ, NULL, KernelMode, &ProcessHandle);
    if (!NT_SUCCESS(Status))
        return Status;

    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
#ifdef _AMD64_
    if (IoIs32bitProcess(NULL) == FALSE)
        Status = ZwCreateSection(&DllSectionHandle, SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY, &ObjectAttributes, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, gDllHandle64);
    else
#endif
        Status = ZwCreateSection(&DllSectionHandle, SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY, &ObjectAttributes, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, gDllHandle32);

    if (!NT_SUCCESS(Status))
    {
        ZwClose(ProcessHandle);
        return Status;
    }

    Status = ZwMapViewOfSection(DllSectionHandle, ProcessHandle, &DllMappingAddress, 0, 0, NULL, &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(DllSectionHandle);
        ZwClose(ProcessHandle);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    MappingSize.QuadPart = PAGE_SIZE;
    Status = ZwCreateSection(&InputSectionHandle, SECTION_MAP_READ | SECTION_QUERY, &ObjectAttributes, &MappingSize, PAGE_READONLY, SEC_COMMIT | SEC_NO_CHANGE, NULL);
    if (!NT_SUCCESS(Status))
    {
        ZwUnmapViewOfSection(ProcessHandle, DllSectionHandle);
        ZwClose(DllSectionHandle);
        ZwClose(ProcessHandle);
        return Status;
    }

    InputMappingAddress = NULL;
    ViewSize = PAGE_SIZE;
    Status = ZwMapViewOfSection(InputSectionHandle, ProcessHandle, &InputMappingAddress, 0, PAGE_SIZE, 0, &ViewSize, ViewUnmap, 0, PAGE_READONLY);
    if (!NT_SUCCESS(Status))
    {
        ZwUnmapViewOfSection(ProcessHandle, DllSectionHandle);
        ZwClose(InputSectionHandle);
        ZwClose(DllSectionHandle);
        ZwClose(ProcessHandle);
        return Status;
    }

    ParamMDL = IoAllocateMdl(InputMappingAddress, PAGE_SIZE, FALSE, FALSE, NULL);
    if (ParamMDL == NULL)
    {
        ZwUnmapViewOfSection(ProcessHandle, DllSectionHandle);
        ZwUnmapViewOfSection(ProcessHandle, InputMappingAddress);
        ZwClose(InputSectionHandle);
        ZwClose(DllSectionHandle);
        ZwClose(ProcessHandle);
        return STATUS_UNSUCCESSFUL;
    }

    MmProbeAndLockPages(ParamMDL, UserMode, IoReadAccess);

    SystemAddress = MmGetSystemAddressForMdlSafe(ParamMDL, NormalPagePriority);
    if (SystemAddress == NULL)
    {
        IoFreeMdl(ParamMDL);
        ZwUnmapViewOfSection(ProcessHandle, DllSectionHandle);
        ZwUnmapViewOfSection(ProcessHandle, InputMappingAddress);
        ZwClose(InputSectionHandle);
        ZwClose(DllSectionHandle);
        ZwClose(ProcessHandle);
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(SystemAddress, PAGE_SIZE);
    DllParam = (PDLL_PARAMS)SystemAddress;

    DllParam->Kernel32Address = Kernel32Address;
    DllParam->Kernel32Size = Kernel32Size;

    IoFreeMdl(ParamMDL);

    Status = RtlCreateUserThreadPtr(ProcessHandle, NULL, FALSE, 0, 0, 0, (PUCHAR)DllMappingAddress + 0x11005, InputMappingAddress, &ThreadHandle, &ClientID);
    if (!NT_SUCCESS(Status))
    {
        ZwUnmapViewOfSection(ProcessHandle, DllSectionHandle);
        ZwUnmapViewOfSection(ProcessHandle, InputMappingAddress);
        ZwClose(InputSectionHandle);
        ZwClose(DllSectionHandle);
        ZwClose(ProcessHandle);
        return Status;
    }

    ZwClose(ThreadHandle);

    InjectContext = (PINJECT_CONTEXT)ExAllocatePoolWithTag(PagedPool, sizeof(INJECT_CONTEXT), 'ewom');
    if (InjectContext == NULL)
    {
        ZwUnmapViewOfSection(ProcessHandle, DllSectionHandle);
        ZwUnmapViewOfSection(ProcessHandle, InputMappingAddress);
        ZwClose(InputSectionHandle);
        ZwClose(DllSectionHandle);
        ZwClose(ProcessHandle);
        return STATUS_NO_MEMORY;
    }

    InjectContext->ClientID = ClientID;
    InjectContext->DllMappingAddress = DllMappingAddress;
    InjectContext->DllSectionHandle = DllSectionHandle;
    InjectContext->InputMappingAddress = InputMappingAddress;
    InjectContext->InputSectionHandle = InputSectionHandle;
    InjectContext->ProcessHandle = ProcessHandle;

    AddNewContext(InjectContext);

    return STATUS_SUCCESS;
}

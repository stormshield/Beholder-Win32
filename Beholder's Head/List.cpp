#include <ntddk.h>
#include "Injector.h"

typedef struct
{
    LIST_ENTRY     ListEntry;
    PINJECT_CONTEXT  InjectContext;
}   CTX_LIST, *PCTX_LIST;

static ERESOURCE    ContextListLock = { 0 };
static LIST_ENTRY  ContextHeadList = { 0 };

NTSTATUS AddNewContext(__in PINJECT_CONTEXT NewContext)
{
    PCTX_LIST   NewElement = NULL;
    
    NewElement = (PCTX_LIST)ExAllocatePoolWithTag(PagedPool, sizeof(CTX_LIST), 'ewom');
    if (NewElement == NULL)
        return STATUS_NO_MEMORY;

    NewElement->InjectContext = NewContext;

    ExAcquireResourceExclusiveLite(&ContextListLock, TRUE);
    InsertTailList(&ContextHeadList, &NewElement->ListEntry);
    ExReleaseResourceLite(&ContextListLock);

    return STATUS_SUCCESS;
}

PINJECT_CONTEXT SearchForContext(__in HANDLE ProcessID, __in HANDLE ThreadID)
{
    PLIST_ENTRY CurrentElement = NULL;
    PCTX_LIST   CurrentContext = NULL;

    ExAcquireResourceExclusiveLite(&ContextListLock, TRUE);

    for (CurrentElement = ContextHeadList.Flink; CurrentElement != &ContextHeadList; CurrentElement = CurrentElement->Flink)
    {
        CurrentContext = (PCTX_LIST)CONTAINING_RECORD(CurrentElement, CTX_LIST, ListEntry);
        if (CurrentContext->InjectContext == NULL)
            continue;
        if (CurrentContext->InjectContext->ClientID.UniqueProcess == ProcessID && CurrentContext->InjectContext->ClientID.UniqueThread == ThreadID)
            break;
        CurrentContext = NULL;
    }

    if (CurrentContext)
        RemoveEntryList(CurrentElement);

    ExReleaseResourceLite(&ContextListLock);

    if (CurrentContext)
        return CurrentContext->InjectContext;
    return NULL;
}

NTSTATUS InitContextList(VOID)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    
    Status = ExInitializeResourceLite(&ContextListLock);
    if (!NT_SUCCESS(Status))
        return Status;

    InitializeListHead(&ContextHeadList);
    return STATUS_SUCCESS;
}

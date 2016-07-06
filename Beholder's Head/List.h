#pragma once

#include <ntddk.h>
#include "Injector.h"

NTSTATUS            InitContextList(VOID);
PINJECT_CONTEXT     SearchForContext(__in HANDLE ProcessID, __in HANDLE ThreadID);
NTSTATUS            AddNewContext(__in PINJECT_CONTEXT NewContext);

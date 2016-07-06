#pragma once

VOID ThreadNotification(__in HANDLE ProcessId, __in HANDLE ThreadId, __in BOOLEAN Create);
VOID    LoadImageNotification(__in_opt PUNICODE_STRING FullImageName, __in HANDLE ProcessId, __in PIMAGE_INFO ImageInfo);
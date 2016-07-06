#include <windows.h>

typedef struct
{
    PVOID   Kernel32Address;
    SIZE_T  Kernel32Size;
}   DLL_PARAMS, *PDLL_PARAMS;

INT main(PDLL_PARAMS DllParams)
{
    if (DllParams == NULL ||
        DllParams->Kernel32Address == NULL ||
        DllParams->Kernel32Size == 0)
        return 0;
    return 1;
}
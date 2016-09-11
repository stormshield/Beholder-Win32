#include <windows.h>
#include "DllParams.h"

INT main(PDLL_PARAMS DllParams)
{
    if (DllParams == NULL ||
        DllParams->Kernel32Address == NULL ||
        DllParams->Kernel32Size == 0)
        return 0;
    return 1;
}
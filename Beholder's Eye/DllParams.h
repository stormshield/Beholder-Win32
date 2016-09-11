#pragma once

typedef struct
{
	PVOID   Kernel32Address;
	SIZE_T  Kernel32Size;
}   DLL_PARAMS, *PDLL_PARAMS;

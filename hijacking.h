#pragma once

#include <windows.h>

#define WAIT_REASON_UNDEFINED (-1)

LPVOID alloc_memory_in_process(DWORD processID);

bool write_shc_into_process(DWORD processID, LPVOID shellcodePtr);

bool run_injected(DWORD pid, ULONGLONG shellcodePtr, DWORD wait_reason);

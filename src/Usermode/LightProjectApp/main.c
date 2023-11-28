#include "common_lib.h"
#include "syscall_if.h"
#include "um_lib_helper.h"

STATUS
__main(
    DWORD       argc,
    char**      argv
    )
{
    STATUS status;

    char processName[50];

    LOG("Hello from your Light Project application!\n");

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    LOG("START:\n\n");
    __try 
    {
        // 1.1. Test with ProcessNameMaxLen = 1
        status = SyscallProcessGetName(processName, 1);
        if (!SUCCEEDED(status) && status != STATUS_TRUNCATED_PROCESS_NAME)
        {
            LOG_FUNC_ERROR("SyscallProcessGetName", status);
            __leave;
        }
        LOG("1.1. Process Name (MaxLen = 1): %s\n", processName);

        // 1.2. Test with ProcessNameMaxLen = 3
        status = SyscallProcessGetName(processName, 3);
        if (!SUCCEEDED(status) && status != STATUS_TRUNCATED_PROCESS_NAME)
        {
            LOG_FUNC_ERROR("SyscallProcessGetName", status);
            __leave;
        }
        LOG("1.2. Process Name (MaxLen = 3): %s\n", processName);

        // 1.3. Test with ProcessName = 0x1234
        status = SyscallProcessGetName((char*)0x1234, 50);
        if (!SUCCEEDED(status))
        {
            LOG("1.3. Function SyscallProcessGetName failed (Buffer not mapped) with status 0x%x\n", status);
            //__leave;
        }

        // 2.1. Display the priority of the current thread
        BYTE threadPriority;
        status = SyscallGetThreadPriority(&threadPriority);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallGetThreadPriority", status);
            __leave;
        }
        LOG("2.1. Thread Priority: %u\n", threadPriority);

        // Change the priority of the current thread
        BYTE newThreadPriority = 10;
        status = SyscallSetThreadPriority(newThreadPriority);
        LOG("\n STATUS1 IS: 0x%x\n", status);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallSetThreadPriority", status);
            __leave;
        }

        // 2.2.Display the priority of the current thread after the change
        status = SyscallGetThreadPriority(&threadPriority);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallGetThreadPriority", status);
            __leave;
        }
        LOG("2.2. Thread Priority (After Change): %u\n", threadPriority);

        // 3. Display the number of threads and current CPU id
        DWORD numberOfThreads;
        status = SyscallGetNumberOfThreadsForCurrentProcess(&numberOfThreads);
        LOG("\n STATUS2 IS: 0x%x\n", status);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallGetNumberOfThreadsForCurrentProcess", status);
            __leave;
        }
        LOG("3. Number of Threads for Current Process: %d\n", numberOfThreads);

        BYTE currentCpuId;
        status = SyscallGetCurrentCPUID(&currentCpuId);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallGetCurrentCPUID", status);
            __leave;
        }
        LOG("4. Current CPU ID: %u\n", currentCpuId);

        // 5. Display the CPU utilization of the current CPU and all CPUs
        BYTE allCpusUtilization;
        status = SyscallGetCPUUtilization(NULL, &allCpusUtilization);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallGetCPUUtilization", status);
            //__leave;
        }
        LOG("5. CPU Utilization (All CPUs): %u\n", allCpusUtilization);

        BYTE currentCpuUtilization;
        BYTE cpuId = 1;
        status = SyscallGetCPUUtilization(&cpuId, &currentCpuUtilization);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("SyscallGetCPUUtilization", status);
            //__leave;
        }
        LOG("6. CPU Utilization (1 CPU): %u\n", currentCpuUtilization);
    }
    __finally
    {
        LOG("\nEND\n");
    }
    return STATUS_SUCCESS;
}
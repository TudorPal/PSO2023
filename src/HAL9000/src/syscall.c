#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "cpumu.h"
#include "thread_internal.h"
#include "smp.h"
#include "vmm.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
        // STUDENT TODO: implement the rest of the syscalls
        case SyscallIdFileWrite:
            status = SyscallFileWrite((UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)pSyscallParameters[0]);
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)pSyscallParameters[0]);
            break;
            // STUDENT TODO: implement the rest of the syscalls
        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid((UM_HANDLE)pSyscallParameters[0],
                (TID*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessGetName:
            status = SyscallProcessGetName((char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1]);
            break;
        case SyscallIdGetThreadPriority:
            status = SyscallGetThreadPriority((BYTE*)pSyscallParameters[0]);
            break;
        case SyscallIdSetThreadPriority:
            status = SyscallSetThreadPriority((BYTE)pSyscallParameters[0]);
            break;
        case SyscallIdGetCurrentCPUID:
            status = SyscallGetCurrentCPUID((BYTE*)pSyscallParameters[0]);
            break;
        case SyscallIdGetNumberOfThreadsForCurrentProcess:
            status = SyscallGetNumberOfThreadsForCurrentProcess((DWORD*)pSyscallParameters[0]);
            break;
        case SyscallIdGetCPUUtilization:
            status = SyscallGetCPUUtilization((BYTE*)pSyscallParameters[0],
                (BYTE*)pSyscallParameters[1]);
            break;
        case SyscallIdVirtualAlloc:
            status = SyscallVirtualAlloc((PVOID)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (VMM_ALLOC_TYPE)pSyscallParameters[2],
                (PAGE_RIGHTS)pSyscallParameters[3],
                (UM_HANDLE)pSyscallParameters[4],
                (QWORD)pSyscallParameters[5],
                (PVOID*)pSyscallParameters[6]
            );
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls
// Useprog 2.
STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                           Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    *BytesWritten = 0;
    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        LOG("%s\n", Buffer);
        *BytesWritten = BytesToWrite;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    UNREFERENCED_PARAMETER(ExitStatus);

    ProcessTerminate(NULL);

    return STATUS_SUCCESS;
}

STATUS
SyscallThreadExit(
    IN      STATUS                  ExitStatus
)
{
    ThreadExit(ExitStatus);

    return STATUS_SUCCESS;
}

STATUS
SyscallThreadGetTid(
    IN_OPT  UM_HANDLE               ThreadHandle,
    OUT     TID* ThreadId
)
{
    if (ThreadHandle != UM_INVALID_HANDLE) {
        //PTHREAD pThread = GetThreadFromHandle(ThreadHandle);
        PTHREAD pThread = GetCurrentThread();

        // Check if the thread handle is valid
        if (pThread == NULL) {
            return STATUS_INVALID_HANDLE;
        }
        *ThreadId = pThread->Id;
    }
    else {
        PTHREAD pCurrentThread = GetCurrentThread();
        *ThreadId = pCurrentThread->Id;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallProcessGetName(
    OUT char* ProcessName,
    IN QWORD ProcessNameMaxLen
)
{
    PPROCESS process = GetCurrentProcess();

    // Check if the buffer is valid and mapped in user-mode
    STATUS status = MmuIsBufferValid(ProcessName, ProcessNameMaxLen, PAGE_RIGHTS_WRITE, process);
    if (!SUCCEEDED(status)) {
        return status;
    }

    QWORD length = strlen(process->ProcessName);
    LOG("Process name length: %d\n", length);
    LOG("Process name: %s\n", process->ProcessName);
    if (length > ProcessNameMaxLen) {
        strncpy(ProcessName, process->ProcessName, (DWORD)ProcessNameMaxLen);
	}
    else {
        strncpy(ProcessName, process->ProcessName, (DWORD)length);
    }

    // finish the string with a null terminator
    ProcessName[length] = '\0';

    // if the name was truncated, return an error
    if (length > ProcessNameMaxLen) {
        return STATUS_TRUNCATED_PROCESS_NAME;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallGetThreadPriority(
    OUT BYTE* ThreadPriority
)
{
    PTHREAD pCurrentThread = GetCurrentThread();
    *ThreadPriority = pCurrentThread->Priority;

    return STATUS_SUCCESS;
}

STATUS
SyscallSetThreadPriority(
    IN BYTE ThreadPriority
)
{
    PTHREAD pCurrentThread = GetCurrentThread();
    pCurrentThread->Priority = ThreadPriority;

    return STATUS_SUCCESS;
}

STATUS
SyscallGetCurrentCPUID(
    OUT BYTE* CpuId
)
{
    *CpuId = GetCurrentPcpu()->ApicId;

    return STATUS_SUCCESS;
}

STATUS
SyscallGetNumberOfThreadsForCurrentProcess(
    OUT DWORD* ThreadNo
)
{
    PPROCESS process = GetCurrentProcess();
    *ThreadNo = process->NumberOfThreads;

    return STATUS_SUCCESS;
}

PPCPU FindCpuById(
    IN BYTE CpuId
)
{
    PLIST_ENTRY pCpuListHead;
    PLIST_ENTRY pCurEntry;

    pCpuListHead = NULL;

    SmpGetCpuList(&pCpuListHead);

    for (pCurEntry = pCpuListHead->Flink; pCurEntry != pCpuListHead; pCurEntry = pCurEntry->Flink)
    {
        PPCPU pCpu = CONTAINING_RECORD(pCurEntry, PCPU, ListEntry);

        if (pCpu->ApicId == CpuId)
        {
            return pCpu;
        }
    }

    return NULL;
}

STATUS
SyscallGetCPUUtilization(
    IN_OPT BYTE* CpuId,
    OUT BYTE* Utilization
)
{
    *Utilization = 0;

    if (CpuId != NULL) {
        PPCPU pCpu = FindCpuById(*CpuId);

        if (pCpu != NULL) {
            // Calculate utilization for the specified CPU
            QWORD totalIdleTicks = pCpu->ThreadData.IdleTicks;
            QWORD totalTicks = pCpu->ThreadData.IdleTicks + pCpu->ThreadData.KernelTicks;

            if (totalTicks != 0) {
                *Utilization = (BYTE)(((totalTicks - totalIdleTicks) * 100) / totalTicks);
                totalTicks = ((totalTicks - totalIdleTicks) * 100) / totalTicks;
                LOG("\n UTILIZATION IN FUNCTION IS: %d\n", totalTicks);
            }
        }
        else {
            LOG("Process with this CPUid was not found!");
        }
    }
    else {
        // all cpus
        PLIST_ENTRY pCpuListHead;
        PLIST_ENTRY pCurEntry;

        // similar to CmdListCpus

        pCpuListHead = NULL;

        SmpGetCpuList(&pCpuListHead);

        QWORD totalIdleTicks = 0;
        QWORD totalTicks = 0;

        for (pCurEntry = pCpuListHead->Flink;
            pCurEntry != pCpuListHead;
            pCurEntry = pCurEntry->Flink)
        {
            PPCPU pCpu = CONTAINING_RECORD(pCurEntry, PCPU, ListEntry);
            totalIdleTicks += pCpu->ThreadData.IdleTicks;
            totalTicks += pCpu->ThreadData.IdleTicks + pCpu->ThreadData.KernelTicks;
        }

        if (totalTicks != 0) {
            *Utilization = (BYTE)(((totalTicks - totalIdleTicks) * 100) / totalTicks);
            totalTicks = ((totalTicks - totalIdleTicks) * 100) / totalTicks;
            LOG("\n UTILIZATION IN FUNCTION IS: %d\n", totalTicks);
        }
    }

    return STATUS_SUCCESS;
}

// lab9 syscall virtual alloc
STATUS
SyscallVirtualAlloc(
    IN_OPT      PVOID                   BaseAddress,
    IN          QWORD                   Size,
    IN          VMM_ALLOC_TYPE          AllocType,
    IN          PAGE_RIGHTS             PageRights,
    IN_OPT      UM_HANDLE               FileHandle,
    IN_OPT      QWORD                   Key,
    OUT         PVOID* AllocatedAddress
) {
    UNREFERENCED_PARAMETER(FileHandle);
    UNREFERENCED_PARAMETER(Key);

    PPROCESS cProcess = GetCurrentProcess();

    *AllocatedAddress = VmmAllocRegionEx(BaseAddress, Size, AllocType, PageRights, FALSE, NULL, cProcess->VaSpace, cProcess->PagingData, NULL);

    return STATUS_SUCCESS;
}

// Userprog 4. SyscallIdMemset
/*Implement a system call SyscallIdMemset which effectively does a memset on a requested virtual address. In the corresponding system call handler check if the pointer receives as a parameter is valid or not.*/
STATUS
SyscallMemset(
    OUT_WRITES(BytesToWrite)    PBYTE   Address,
    IN                          DWORD   BytesToWrite,
    IN                          BYTE    ValueToWrite
) {
    PPROCESS currentProcess = GetCurrentProcess();

    STATUS status = MmuIsBufferValid(Address, BytesToWrite, PAGE_RIGHTS_WRITE, currentProcess);
    if (!SUCCEEDED(status)) {
        return status;
    }

    memset(Address, ValueToWrite, BytesToWrite);

    return STATUS_SUCCESS;
}

#include "common_lib.h"
#include "lock_common.h"
#include "semaphores.h"
#include "synch.h"
#include "HAL9000.h"
#include "thread_internal.h"

// Semaphore using busy waiting
void
SemaphoreInit(
    OUT         PSEMAPHORE       Semaphore,
    IN          DWORD            InitialValue
)
{
    ASSERT(NULL != Semaphore);

    memzero(Semaphore, sizeof(Semaphore));
    Semaphore->Value = InitialValue;
    Semaphore->Count = 0;
    SpinlockInit(&Semaphore->Lock);

    InitializeListHead(&Semaphore->WaitingList);
}

void 
SemaphoreDown(
    OUT         PSEMAPHORE       Semaphore, 
    IN          DWORD            Value
)
{
    INTR_STATE dummyState;
    INTR_STATE oldState;
    PTHREAD pCurrentThread = GetCurrentThread();

    ASSERT(NULL != Semaphore);
    ASSERT(NULL != pCurrentThread);

    oldState = CpuIntrDisable();

    LockAcquire(&Semaphore->Lock, &dummyState);
    if (NULL == Semaphore->Lock->Holder)
    {
        Semaphore->Lock->Holder = pCurrentThread;
    }

    if (Semaphore->Count > 0)
    {
        Semaphore->Count--;
    }
    else
    {
        InsertTailList(&Semaphore->WaitingList, &pCurrentThread->ReadyList);
        ThreadTakeBlockLock();
        LockRelease(&Semaphore->Lock, dummyState);
        ThreadBlock();
        LockAcquire(&Semaphore->Lock, &dummyState);
    }

    _Analysis_assume_lock_acquired_(*Semaphore);

    LockRelease(&Semaphore->Lock, dummyState);

    CpuIntrSetState(oldState);
}

void SemaphoreUp(PSEMAPHORE Semaphore, DWORD Value)
{
    
}

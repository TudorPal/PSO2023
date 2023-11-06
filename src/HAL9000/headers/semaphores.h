#pragma once

#include "list.h"
#include "synch.h"
#include "data_type.h"
#include "spinlock.h"
#include "test_common.h"
#include "io.h"

typedef struct _SEMAPHORE
{
    DWORD           Value;
    DWORD           Count;
    LIST_ENTRY      WaitingList;
    PSPINLOCK       Lock; //cu spinlock

} SEMAPHORE, * PSEMAPHORE;

//void
//SemaphoreInit(
//    OUT     PSEMAPHORE      Semaphore,
//    IN      DWORD           InitialValue
//);
//
//void
//SemaphoreDown(
//    INOUT   PSEMAPHORE      Semaphore,
//    IN      DWORD           Value
//);
//
//void
//SemaphoreUp(
//    INOUT   PSEMAPHORE      Semaphore,
//    IN      DWORD           Value
//);
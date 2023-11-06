#include "test_common.h"
#include "test_thread.h"
#include "test_lp.h"

void
(__cdecl ThreadPrepareFibonacci)(
    OUT_OPT_PTR     PVOID*              Context,
    IN              DWORD               NumberOfThreads,
    IN              PVOID               PrepareContext
    )
{
    ASSERT(NULL != Context);
    ASSERT(PrepareContext == NULL);
    ASSERT(NumberOfThreads > 0);
    PLP_FIB_THREAD_CONTEXT context;
    context = (PLP_FIB_THREAD_CONTEXT)Context;
    context = ExAllocatePoolWithTag(PoolAllocateZeroMemory | PoolAllocatePanicIfFail,
        sizeof(LP_FIB_THREAD_CONTEXT),
        HEAP_TEST_TAG, 0);
    context->Index = 10; // N
    context->Result = 0;
    LOG("Calling fibonacci with Index: %d, Result: %d", context->Index, context->Result);
    *Context = context;
}

STATUS MultithreadFibonacci(
    IN_OPT PVOID Context
    )
{
    STATUS status = STATUS_SUCCESS;
    PLP_FIB_THREAD_CONTEXT context = (PLP_FIB_THREAD_CONTEXT)Context;

    if (context->Index == 0 || context->Index == 1) {
        context->Result = 1;
        return STATUS_SUCCESS;
    }

    LP_FIB_THREAD_CONTEXT context1 = { 0 };
    LP_FIB_THREAD_CONTEXT context2 = { 0 };

    PTHREAD thread1 = (PTHREAD)NULL;
    PTHREAD thread2 = (PTHREAD)NULL;
    char thName[MAX_PATH];

    __try
    {
        snprintf(thName, MAX_PATH, "Fib-%d", context->Index - 1);
        status = ThreadCreate(thName, ThreadPriorityDefault, MultithreadFibonacci, &context1, &thread1);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("ThreadCreate", status);
            __leave;
        }

        snprintf(thName, MAX_PATH, "Fib-%d", context->Index - 2);
        status = ThreadCreate(thName, ThreadPriorityDefault, MultithreadFibonacci, &context2, &thread2);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("ThreadCreate", status);
            __leave;
        }
        STATUS exitStatus1;
        STATUS exitStatus2;

        ThreadWaitForTermination(thread1, &exitStatus1);
        ThreadWaitForTermination(thread2, &exitStatus2);

        context->Result = context1.Result + context2.Result;
    }
    __finally
    {
        if (thread1)
        {
            ThreadCloseHandle(thread1);
        }
        if (thread2)
        {
            ThreadCloseHandle(thread2);
        }
    }
    if (context->Result == 55) {
        LOG("Test passed: Result is correct (expected 55)\n");
        status = STATUS_SUCCESS;
    }
    else {
        LOG("Test failed: Result is incorrect (expected 55, got %d)\n", context->Result);
        status = STATUS_UNSUCCESSFUL;
    }
    return status;
}

#pragma once

#include "thread.h"
#include "common_lib.h"
#include "test_thread.h"

typedef struct _LP_FIB_THREAD_CONTEXT {
    int Index;
    int Result;
} LP_FIB_THREAD_CONTEXT, * PLP_FIB_THREAD_CONTEXT;

FUNC_ThreadPrepareTest ThreadPrepareFibonacci;
FUNC_ThreadStart MultithreadFibonacci;

//////////////////////////////////////////////////////////////////////////////
//
//  Detours Disassembler (disasm.cpp of detours.lib)
//
//  Microsoft Research Detours Package, Version 4.0.1
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

//////////////////////////////////////////////////////////////////////////////
//

#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable:4091) // empty typedef
#endif

#if __has_include(<wdm.h>)
#define DETOURS_KERNEL
#endif

#ifdef DETOURS_KERNEL
#include <ntddk.h>
#include "api_thunks.h"
#endif

#ifdef DETOURS_KERNEL

//////////////////////////////////////////////////////////////////////////////
//

// Set/Get Last Error

static long __Win32Error = NO_ERROR;

VOID WINAPI SetLastError(_In_ LONG Win32Error)
{
    __Win32Error = Win32Error;
}

LONG WINAPI GetLastError(VOID)
{
    return __Win32Error;
}


//////////////////////////////////////////////////////////////////////////////
//

// Process & Thread

HANDLE WINAPI GetCurrentProcess(VOID)
{
    return ZwCurrentProcess();
}

HANDLE WINAPI GetCurrentThread(VOID)
{
    return ZwCurrentThread();
}

DWORD WINAPI GetCurrentProcessId(VOID)
{
    return (DWORD)(ULONG_PTR)PsGetCurrentProcessId();
}

DWORD WINAPI GetCurrentThreadId(VOID)
{
    return (DWORD)(ULONG_PTR)PsGetCurrentThreadId();
}

//////////////////////////////////////////////////////////////////////////////
//

// Processor

DWORD WINAPI GetCurrentProcessorNumber(VOID)
{
    return (DWORD)KeGetCurrentProcessorNumber();
}

#endif

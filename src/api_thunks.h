/////////////////////////////////////////////////////////////////////////////
//
//  Core Detours Functionality (detours.h of detours.lib)
//
//  Microsoft Research Detours Package, Version 4.0.1
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

#pragma once

//////////////////////////////////////////////////////////////////////////////
//

#if __has_include(<wdm.h>)
#define DETOURS_KERNEL
#endif

#ifdef DETOURS_KERNEL
#include <minwindef.h>
#include <ntimage.h>

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////////////////////////////
//

// System Routine

VOID NTAPI KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
);

VOID NTAPI KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
);

LOGICAL NTAPI KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2
);

PVOID NTAPI RtlPcToFileHeader(
    _In_ PVOID PcValue,
    _Out_ PVOID* BaseOfImage
);

PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
    _In_ PVOID Base
);

//////////////////////////////////////////////////////////////////////////////
//

// Handle

#define INVALID_HANDLE_VALUE                ((HANDLE)-1)

// Win32 Error Code -> NT Status

#define NO_ERROR                            STATUS_SUCCESS
#define ERROR_INVALID_HANDLE                STATUS_INVALID_HANDLE
#define ERROR_NOT_ENOUGH_MEMORY             STATUS_INSUFFICIENT_RESOURCES
#define ERROR_OUTOFMEMORY                   STATUS_INSUFFICIENT_RESOURCES
#define ERROR_INVALID_DATA                  STATUS_INVALID_PARAMETER
#define ERROR_INVALID_PARAMETER             STATUS_INVALID_PARAMETER
#define ERROR_INVALID_BLOCK                 STATUS_INVALID_BLOCK_LENGTH
#define ERROR_INVALID_OPERATION             STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION
#define ERROR_MOD_NOT_FOUND                 STATUS_DLL_NOT_FOUND
#define ERROR_EXE_MARKED_INVALID            STATUS_INVALID_IMAGE_FORMAT
#define ERROR_BAD_EXE_FORMAT                STATUS_INVALID_IMAGE_FORMAT
#define ERROR_INVALID_EXE_SIGNATURE         STATUS_INVALID_IMAGE_NOT_MZ
#define ERROR_CALL_NOT_IMPLEMENTED          STATUS_NOT_IMPLEMENTED

#define STILL_ACTIVE                        STATUS_PENDING
#define EXCEPTION_ACCESS_VIOLATION          STATUS_ACCESS_VIOLATION
#define EXCEPTION_DATATYPE_MISALIGNMENT     STATUS_DATATYPE_MISALIGNMENT
#define EXCEPTION_BREAKPOINT                STATUS_BREAKPOINT
#define EXCEPTION_SINGLE_STEP               STATUS_SINGLE_STEP
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     STATUS_ARRAY_BOUNDS_EXCEEDED
#define EXCEPTION_FLT_DENORMAL_OPERAND      STATUS_FLOAT_DENORMAL_OPERAND
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        STATUS_FLOAT_DIVIDE_BY_ZERO
#define EXCEPTION_FLT_INEXACT_RESULT        STATUS_FLOAT_INEXACT_RESULT
#define EXCEPTION_FLT_INVALID_OPERATION     STATUS_FLOAT_INVALID_OPERATION
#define EXCEPTION_FLT_OVERFLOW              STATUS_FLOAT_OVERFLOW
#define EXCEPTION_FLT_STACK_CHECK           STATUS_FLOAT_STACK_CHECK
#define EXCEPTION_FLT_UNDERFLOW             STATUS_FLOAT_UNDERFLOW
#define EXCEPTION_INT_DIVIDE_BY_ZERO        STATUS_INTEGER_DIVIDE_BY_ZERO
#define EXCEPTION_INT_OVERFLOW              STATUS_INTEGER_OVERFLOW
#define EXCEPTION_PRIV_INSTRUCTION          STATUS_PRIVILEGED_INSTRUCTION
#define EXCEPTION_IN_PAGE_ERROR             STATUS_IN_PAGE_ERROR
#define EXCEPTION_ILLEGAL_INSTRUCTION       STATUS_ILLEGAL_INSTRUCTION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  STATUS_NONCONTINUABLE_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW            STATUS_STACK_OVERFLOW
#define EXCEPTION_INVALID_DISPOSITION       STATUS_INVALID_DISPOSITION
#define EXCEPTION_GUARD_PAGE                STATUS_GUARD_PAGE_VIOLATION
#define EXCEPTION_INVALID_HANDLE            STATUS_INVALID_HANDLE
#define EXCEPTION_POSSIBLE_DEADLOCK         STATUS_POSSIBLE_DEADLOCK
#define CONTROL_C_EXIT                      STATUS_CONTROL_C_EXIT


//////////////////////////////////////////////////////////////////////////////
//

// Set/Get Last Error

VOID WINAPI SetLastError(
    _In_ LONG  Win32Error
);

LONG WINAPI GetLastError(
    VOID
);


//////////////////////////////////////////////////////////////////////////////
//

// Process & Thread

HANDLE WINAPI GetCurrentProcess(
    VOID
);

HANDLE WINAPI GetCurrentThread(
    VOID
);

DWORD WINAPI GetCurrentProcessId(
    VOID
);

DWORD WINAPI GetCurrentThreadId(
    VOID
);


//////////////////////////////////////////////////////////////////////////////
//

// Processor

DWORD WINAPI GetCurrentProcessorNumber(
    VOID
);


#ifdef __cplusplus
}
#endif

#endif

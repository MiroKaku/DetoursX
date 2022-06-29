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

#if defined(_KERNEL_MODE)
#define DETOURS_KERNEL
#endif

#ifdef DETOURS_KERNEL
#include <ntifs.h>
#include "api_thunks.h"
#endif

#ifdef DETOURS_KERNEL

//////////////////////////////////////////////////////////////////////////////
//

#define PROCESS_VM_READ                 (0x0010)
#define PROCESS_VM_WRITE                (0x0020)  

// Zw

NTSTATUS NTAPI ZwReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
)
{
    SIZE_T BytesCopied = 0u;
    KPROCESSOR_MODE PreviousMode = KernelMode;
    PEPROCESS Process = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PETHREAD CurrentThread = NULL;

    PAGED_CODE();

    CurrentThread = PsGetCurrentThread();

    //
    // If the buffer size is not zero, then attempt to read data from the
    // specified process address space into the current process address
    // space.
    //

    BytesCopied = 0;
    Status = STATUS_SUCCESS;
    if (BufferSize != 0) {

        //
        // Reference the target process.
        //

        Status = ObReferenceObjectByHandle(
            ProcessHandle,
            PROCESS_VM_READ,
            *PsProcessType,
            PreviousMode,
            (PVOID*)&Process,
            NULL);

        //
        // If the process was successfully referenced, then attempt to
        // read the specified memory either by direct mapping or copying
        // through nonpaged pool.
        //

        if (Status == STATUS_SUCCESS) {

            Status = MmCopyVirtualMemory(
                Process,
                BaseAddress,
                PsGetThreadProcess(CurrentThread),
                Buffer,
                BufferSize,
                PreviousMode,
                &BytesCopied);

            //
            // Dereference the target process.
            //

            ObDereferenceObject(Process);
        }
    }

    //
    // If requested, return the number of bytes read.
    //

    if (ARGUMENT_PRESENT(NumberOfBytesRead)) {
        __try {
            *NumberOfBytesRead = BytesCopied;

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            NOTHING;
        }
    }

    return Status;
}

NTSTATUS NTAPI ZwWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
)
{
    SIZE_T BytesCopied = 0u;
    KPROCESSOR_MODE PreviousMode = KernelMode;
    PEPROCESS Process = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PETHREAD CurrentThread = NULL;

    PAGED_CODE();

    CurrentThread = PsGetCurrentThread();

    //
    // If the buffer size is not zero, then attempt to write data from the
    // current process address space into the target process address space.
    //

    BytesCopied = 0;
    Status = STATUS_SUCCESS;
    if (BufferSize != 0) {

        //
        // Reference the target process.
        //

        Status = ObReferenceObjectByHandle(
            ProcessHandle,
            PROCESS_VM_WRITE,
            *PsProcessType,
            PreviousMode,
            (PVOID*)&Process,
            NULL);

        //
        // If the process was successfully referenced, then attempt to
        // write the specified memory either by direct mapping or copying
        // through nonpaged pool.
        //

        if (Status == STATUS_SUCCESS) {

            Status = MmCopyVirtualMemory(
                PsGetThreadProcess(CurrentThread),
                Buffer,
                Process,
                BaseAddress,
                BufferSize,
                PreviousMode,
                &BytesCopied);

            //
            // Dereference the target process.
            //

            ObDereferenceObject(Process);
        }
    }

    //
    // If requested, return the number of bytes read.
    //

    if (ARGUMENT_PRESENT(NumberOfBytesWritten)) {
        __try {
            *NumberOfBytesWritten = BytesCopied;

        } __except(EXCEPTION_EXECUTE_HANDLER) {
            NOTHING;
        }
    }

    return Status;
}

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

BOOL WINAPI IsWow64Process(
    _In_ HANDLE hProcess,
    _Out_ PBOOL Wow64Process
)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    ULONG_PTR Peb32 = 0u;

    NtStatus = ZwQueryInformationProcess(
        hProcess,
        ProcessWow64Information,
        &Peb32,
        sizeof(Peb32),
        NULL
    );

    *Wow64Process = FALSE;

    if (!NT_SUCCESS(NtStatus)) {

        SetLastError(NtStatus);
    }
    else {

        if (Peb32 == 0) {
            *Wow64Process = FALSE;
        }
        else {
            *Wow64Process = TRUE;
        }
    }

    return (NT_SUCCESS(NtStatus));
}

_Success_(return != FALSE)
BOOL WINAPI ReadProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPCVOID lpBaseAddress,
    _Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T * lpNumberOfBytesRead
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SIZE_T NtNumberOfBytesRead = 0u;

    Status = ZwReadVirtualMemory(
        hProcess,
        (PVOID)lpBaseAddress,
        lpBuffer,
        nSize,
        &NtNumberOfBytesRead
    );

    if (lpNumberOfBytesRead != NULL) {
        *lpNumberOfBytesRead = NtNumberOfBytesRead;
    }

    if (!NT_SUCCESS(Status)) {
        SetLastError(Status);
        return FALSE;
    }
    else {
        return TRUE;
    }
}

_Success_(return != FALSE)
BOOL WINAPI WriteProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T * lpNumberOfBytesWritten
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL, xStatus = STATUS_UNSUCCESSFUL;
    ULONG OldProtect = PAGE_READWRITE;
    SIZE_T RegionSize = 0u;
    PVOID Base = NULL;
    SIZE_T NtNumberOfBytesWritten = 0u;

    //
    // Set the protection to allow writes
    //

    RegionSize = nSize;
    Base = lpBaseAddress;
    Status = ZwProtectVirtualMemory(
        hProcess,
        &Base,
        &RegionSize,
        PAGE_READWRITE,
        &OldProtect
    );
    if (NT_SUCCESS(Status)) {

        //
        // See if previous protection was writable. If so,
        // then reset protection and do the write.
        // Otherwise, see if previous protection was read-only or
        // no access. In this case, don't do the write, just fail
        //

        if ((OldProtect & PAGE_READWRITE) == PAGE_READWRITE ||
            (OldProtect & PAGE_WRITECOPY) == PAGE_WRITECOPY ||
            (OldProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE ||
            (OldProtect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY) {

            Status = ZwProtectVirtualMemory(
                hProcess,
                &Base,
                &RegionSize,
                OldProtect,
                &OldProtect
            );
            Status = ZwWriteVirtualMemory(
                hProcess,
                lpBaseAddress,
                (PVOID)lpBuffer,
                nSize,
                &NtNumberOfBytesWritten
            );

            if (lpNumberOfBytesWritten != NULL) {
                *lpNumberOfBytesWritten = NtNumberOfBytesWritten;
            }

            if (!NT_SUCCESS(Status)) {
                SetLastError(Status);
                return FALSE;
            }
            ZwFlushInstructionCache(hProcess, lpBaseAddress, nSize);
            return TRUE;
        }
        else {

            //
            // See if the previous protection was read only or no access. If
            // this is the case, restore the previous protection and return
            // an access violation error.
            //
            if ((OldProtect & PAGE_NOACCESS) == PAGE_NOACCESS ||
                (OldProtect & PAGE_READONLY) == PAGE_READONLY) {

                Status = ZwProtectVirtualMemory(
                    hProcess,
                    &Base,
                    &RegionSize,
                    OldProtect,
                    &OldProtect
                );
                SetLastError(STATUS_ACCESS_VIOLATION);
                return FALSE;
            }
            else {

                //
                // The previous protection must have been code and the caller
                // is trying to set a breakpoint or edit the code. Do the write
                // and then restore the previous protection.
                //

                Status = ZwWriteVirtualMemory(
                    hProcess,
                    lpBaseAddress,
                    (PVOID)lpBuffer,
                    nSize,
                    &NtNumberOfBytesWritten
                );

                if (lpNumberOfBytesWritten != NULL) {
                    *lpNumberOfBytesWritten = NtNumberOfBytesWritten;
                }

                xStatus = ZwProtectVirtualMemory(
                    hProcess,
                    &Base,
                    &RegionSize,
                    OldProtect,
                    &OldProtect
                );
                if (!NT_SUCCESS(Status)) {
                    SetLastError(STATUS_ACCESS_VIOLATION);
                    return STATUS_ACCESS_VIOLATION;
                }
                ZwFlushInstructionCache(hProcess, lpBaseAddress, nSize);
                return TRUE;
            }
        }
    }
    else {
        SetLastError(Status);
        return FALSE;
    }
}

_Ret_maybenull_
_Post_writable_byte_size_(dwSize)
LPVOID WINAPI VirtualAllocEx(
    _In_ HANDLE hProcess,
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    __try {
        Status = NtAllocateVirtualMemory(hProcess,
            &lpAddress,
            0,
            &dwSize,
            flAllocationType,
            flProtect
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (NT_SUCCESS(Status)) {
        return(lpAddress);
    }

    SetLastError(Status);
    return NULL;
}

BOOL WINAPI VirtualFreeEx(
    _In_ HANDLE hProcess,
    _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD dwFreeType
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ((dwFreeType & MEM_RELEASE) && dwSize != 0) {
        SetLastError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    Status = NtFreeVirtualMemory(
        hProcess,
        &lpAddress,
        &dwSize,
        dwFreeType
    );

    if (NT_SUCCESS(Status)) {
        return(TRUE);
    }

    SetLastError(Status);
    return FALSE;
}

_Success_(return != FALSE)
BOOL WINAPI VirtualProtectEx(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Status = ZwProtectVirtualMemory(
        hProcess,
        &lpAddress,
        &dwSize,
        flNewProtect,
        lpflOldProtect);

    if (NT_SUCCESS(Status)) {
        return(TRUE);
    }

    SetLastError(Status);
    return FALSE;
}

SIZE_T WINAPI VirtualQueryEx(
    _In_ HANDLE hProcess,
    _In_opt_ LPCVOID lpAddress,
    _Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
    _In_ SIZE_T dwLength)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SIZE_T ReturnLength = 0u;

    Status = ZwQueryVirtualMemory(
        hProcess,
        (LPVOID)lpAddress,
        MemoryBasicInformation,
        (PMEMORY_BASIC_INFORMATION)lpBuffer,
        dwLength,
        &ReturnLength);
    if (NT_SUCCESS(Status))
    {
        return(ReturnLength);
    }

    SetLastError(Status);
    return 0;
}

#endif

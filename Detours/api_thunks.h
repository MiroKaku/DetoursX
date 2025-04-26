#pragma once

namespace Detours::Thunks
{
    NTSTATUS NTAPI ZwReadVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _In_opt_ PVOID BaseAddress,
        _Out_writes_bytes_(BufferSize) PVOID Buffer,
        _In_ SIZE_T BufferSize,
        _Out_opt_ PSIZE_T NumberOfBytesRead
    );

    NTSTATUS NTAPI ZwWriteVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _In_opt_ PVOID BaseAddress,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ SIZE_T BufferSize,
        _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

    VOID WINAPI SetLastError(_In_ DWORD Win32Error);
    DWORD WINAPI GetLastError(VOID);

    HANDLE WINAPI GetCurrentProcess(VOID);
    HANDLE WINAPI GetCurrentThread(VOID);
    DWORD WINAPI GetCurrentProcessId(VOID);
    DWORD WINAPI GetCurrentThreadId(VOID);

    BOOL WINAPI IsWow64Process(
        _In_ HANDLE hProcess,
        _Out_ PBOOL Wow64Process
    );

    BOOL WINAPI ReadProcessMemory(
        _In_ HANDLE hProcess,
        _In_ LPCVOID lpBaseAddress,
        _Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
        _In_ SIZE_T nSize,
        _Out_opt_ SIZE_T * lpNumberOfBytesRead
    );

    BOOL WINAPI WriteProcessMemory(
        _In_ HANDLE hProcess,
        _In_ LPVOID lpBaseAddress,
        _In_reads_bytes_(nSize) LPCVOID lpBuffer,
        _In_ SIZE_T nSize,
        _Out_opt_ SIZE_T* lpNumberOfBytesWritten
    );

    LPVOID WINAPI VirtualAllocEx(
        _In_ HANDLE hProcess,
        _In_opt_ LPVOID lpAddress,
        _In_ SIZE_T dwSize,
        _In_ DWORD flAllocationType,
        _In_ DWORD flProtect
    );

    BOOL WINAPI VirtualFreeEx(
        _In_ HANDLE hProcess,
        _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT, _Post_invalid_) _When_(dwFreeType == MEM_RELEASE, _Post_ptr_invalid_) LPVOID lpAddress,
        _In_ SIZE_T dwSize,
        _In_ DWORD dwFreeType
    );

    BOOL WINAPI VirtualProtectEx(
        _In_ HANDLE hProcess,
        _In_ LPVOID lpAddress,
        _In_ SIZE_T dwSize,
        _In_ DWORD flNewProtect,
        _Out_ PDWORD lpflOldProtect
    );

    SIZE_T WINAPI VirtualQueryEx(
        _In_ HANDLE hProcess,
        _In_opt_ LPCVOID lpAddress,
        _Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
        _In_ SIZE_T dwLength
    );

}

#define ZwReadVirtualMemory ::Detours::Thunks::ZwReadVirtualMemory
#define ZwWriteVirtualMemory ::Detours::Thunks::ZwWriteVirtualMemory

#define SetLastError ::Detours::Thunks::SetLastError
#define GetLastError ::Detours::Thunks::GetLastError

#define GetCurrentProcess ::Detours::Thunks::GetCurrentProcess
#define GetCurrentThread ::Detours::Thunks::GetCurrentThread
#define GetCurrentProcessId ::Detours::Thunks::GetCurrentProcessId
#define GetCurrentThreadId ::Detours::Thunks::GetCurrentThreadId

#define IsWow64Process ::Detours::Thunks::IsWow64Process

#define ReadProcessMemory ::Detours::Thunks::ReadProcessMemory
#define WriteProcessMemory ::Detours::Thunks::WriteProcessMemory

#define VirtualAllocEx ::Detours::Thunks::VirtualAllocEx
#define VirtualFreeEx ::Detours::Thunks::VirtualFreeEx
#define VirtualProtectEx ::Detours::Thunks::VirtualProtectEx
#define VirtualQueryEx ::Detours::Thunks::VirtualQueryEx

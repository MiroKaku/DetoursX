#if __has_include(<wdm.h>)
#define KERNEL_MODE
#endif

#ifdef KERNEL_MODE
#include <ntddk.h>
#include "../src/detours.h"
#else
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "../Detours/src/detours.h"

#pragma comment(lib, "ntdll")
#endif


#ifdef KERNEL_MODE
#define LOG(_0, _1, ...) DbgPrintEx(_0, _1, __VA_ARGS__)
#else
static void DbgPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...)
{
    va_list args;
    va_start(args, Format);

    int len = _vscprintf(Format, args);
    if (len < 0)
    {
        return;
    }
    len += sizeof("\0");

    char* buf = (char*)malloc(len);
    if (buf == nullptr)
    {
        return;
    }

    len = vsnprintf_s(buf, len, len, Format, args);
    if (len < 0)
    {
        return;
    }
    buf[len] = '\0';

    OutputDebugStringA(buf);
    va_end(args);
    free(buf);
}

#define LOG(_0, _1, ...) DbgPrint(__VA_ARGS__)
#endif


#ifndef KERNEL_MODE
#define NtCurrentThread GetCurrentThread
#define ZwCurrentThread NtCurrentThread

EXTERN_C NTSTATUS NTAPI ZwOpenFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG ShareAccess,
    _In_ ULONG OpenOptions
);

EXTERN_C NTSTATUS NTAPI ZwCreateFile(
    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength
);
#endif


class DetourLockGuard
{
    volatile long& _Atom;

public:
    explicit DetourLockGuard(volatile long& atom) noexcept
        : _Atom(atom)
    {
        InterlockedCompareExchange(&_Atom, true, false);
    }
    ~DetourLockGuard()
    {
        InterlockedCompareExchange(&_Atom, false, true);
    }
};

namespace Hook
{
    static auto _ZwOpenFile = (decltype(::ZwOpenFile)*)nullptr;
    NTSTATUS NTAPI ZwOpenFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_ ULONG ShareAccess,
        _In_ ULONG OpenOptions
    )
    {
        static volatile long _lock = false;
        if (!InterlockedCompareExchange(&_lock, false, false))
        {
            auto guard = DetourLockGuard(_lock);

            LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwOpenFile(): %wZ\n",
                ObjectAttributes ? ObjectAttributes->ObjectName : nullptr);
        }

        return _ZwOpenFile(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            ShareAccess,
            OpenOptions);
    }

    static auto _ZwCreateFile = (decltype(::ZwCreateFile)*)nullptr;
    NTSTATUS NTAPI ZwCreateFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_opt_ PLARGE_INTEGER AllocationSize,
        _In_ ULONG FileAttributes,
        _In_ ULONG ShareAccess,
        _In_ ULONG CreateDisposition,
        _In_ ULONG CreateOptions,
        _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
        _In_ ULONG EaLength
    )
    {
        static volatile long _lock = false;
        if (!InterlockedCompareExchange(&_lock, false, false))
        {
            auto guard = DetourLockGuard(_lock);

            LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwCreateFile(): %wZ\n",
                ObjectAttributes ? ObjectAttributes->ObjectName : nullptr);
        }

        return _ZwCreateFile(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength);
    }
}


#ifdef KERNEL_MODE
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
#else
EXTERN_C int main(int /*argc*/, char* /*argv*/[])
#endif
{
    Hook::_ZwOpenFile   = ZwOpenFile;
    Hook::_ZwCreateFile = ZwCreateFile;

    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());

    DetourAttach((void**)&Hook::_ZwOpenFile, Hook::ZwOpenFile);
    DetourAttach((void**)&Hook::_ZwCreateFile, Hook::ZwCreateFile);

    DetourTransactionCommit();

#ifdef KERNEL_MODE
    DriverObject->DriverUnload = [](PDRIVER_OBJECT)
#endif
    {
#ifndef KERNEL_MODE
        (void)getchar();
#endif
        DetourTransactionBegin();
        DetourUpdateThread(ZwCurrentThread());

        DetourDetach((void**)&Hook::_ZwOpenFile, Hook::ZwOpenFile);
        DetourDetach((void**)&Hook::_ZwCreateFile, Hook::ZwCreateFile);

        DetourTransactionCommit();
    };

    LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __FUNCTION__ "(): Final.\n");
    return 0;
}

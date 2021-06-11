#if __has_include(<wdm.h>)
#define KERNEL_MODE
#endif

#ifdef KERNEL_MODE
#include <ntifs.h>
#include "../src/detours.h"
#else
#define WIN32_LEAN_AND_MEAN
#define UMDF_USING_NTSTATUS
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include "../Detours/src/detours.h"

#pragma comment(lib, "ntdll")
#endif
#include <stdlib.h>

#pragma warning(disable:4996)


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


#ifdef KERNEL_MODE
EXTERN_C struct _PEB32* NTAPI PsGetProcessWow64Process(
    _In_ PEPROCESS Process
);

EXTERN_C inline bool NTAPI PsIsWow64Process(PEPROCESS aProcess)
{
#ifdef _WIN64
    return !!PsGetProcessWow64Process(aProcess);
#else
    aProcess;
    return false;
#endif
}

#else
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

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), (LPWSTR)s }

EXTERN_C BOOLEAN NTAPI RtlIsNameInExpression(
    _In_ PUNICODE_STRING Expression,
    _In_ PUNICODE_STRING Name,
    _In_ BOOLEAN IgnoreCase,
    _In_opt_ PWCH UpcaseTable
);
#endif


namespace Hook
{
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

    enum : size_t {
        IdxOfZwOpenFile = 0u,
        IdxOfZwCreateFile
    };

#ifdef KERNEL_MODE
    volatile long _locks[2][256] = { { false },{ false } };
    inline volatile long& _lock(size_t idx) {
        return _locks[idx][KeGetCurrentProcessorNumber()];
    }
#else
    thread_local volatile long _locks[2] = { false };
    inline volatile long& _lock(size_t idx) {
        return _locks[idx];
    }
#endif

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
        if (!InterlockedCompareExchange(&_lock(IdxOfZwOpenFile), false, false))
        {
            auto guard = DetourLockGuard(_lock(IdxOfZwOpenFile));

            LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DetoursX] " "ZwOpenFile(): %wZ\n",
                ObjectAttributes ? ObjectAttributes->ObjectName : nullptr);
        }

#ifndef KERNEL_MODE
        UNICODE_STRING Match = RTL_CONSTANT_STRING(L"*\\123.TXT");
        if (ObjectAttributes && RtlIsNameInExpression(&Match, ObjectAttributes->ObjectName, TRUE, NULL)) {

            return STATUS_ACCESS_DENIED;
        }
#endif
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
        if (!InterlockedCompareExchange(&_lock(IdxOfZwCreateFile), false, false))
        {
            auto guard = DetourLockGuard(_lock(IdxOfZwCreateFile));

            LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DetoursX] " "ZwCreateFile(): %wZ\n",
                ObjectAttributes ? ObjectAttributes->ObjectName : nullptr);
        }

#ifndef KERNEL_MODE
        UNICODE_STRING Match = RTL_CONSTANT_STRING(L"*\\123.TXT");
        if (ObjectAttributes && RtlIsNameInExpression(&Match, ObjectAttributes->ObjectName, TRUE, NULL)) {

            return STATUS_ACCESS_DENIED;
        }
#endif
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
// Note: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager#best
VOID CreateProcessCallback (
    _Inout_ PEPROCESS Process,
    _In_ HANDLE /*ProcessId*/,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE Handle = NULL;

    do 
    {
        if (CreateInfo && CreateInfo->FileOpenNameAvailable) {

            UNICODE_STRING Target = RTL_CONSTANT_STRING(L"*\\NOTEPAD.EXE");
            if (FsRtlIsNameInExpression(&Target, (PUNICODE_STRING)CreateInfo->ImageFileName, TRUE, NULL) == FALSE) {
                break;
            }

            Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS,
                *PsProcessType, KernelMode, &Handle);
            if (!NT_SUCCESS(Status)) {
                break;
            }

            struct WORK_ITEM : WORK_QUEUE_ITEM {
                KEVENT Wait;
                HANDLE Target;
                BOOLEAN IsWow64Target;
                PPS_CREATE_NOTIFY_INFO CreateInfo;
            } WorkItem;

            WorkItem.Target     = Handle;
            WorkItem.CreateInfo = CreateInfo;
            WorkItem.IsWow64Target = PsIsWow64Process(Process);

            KeInitializeEvent(&WorkItem.Wait, NotificationEvent, FALSE);
            ExInitializeWorkItem(&WorkItem, [](PVOID Context) {

                WORK_ITEM* WorkItem =(WORK_ITEM*) Context;

                LPCSTR Dlls[] = {
#ifdef _WIN64
                    "C:\\Unittest64.dll",
#else
                    "C:\\Unittest32.dll",
#endif
                };

                if (WorkItem->IsWow64Target) {
                    Dlls[0] = "C:\\Unittest32.dll";
                }

                if (DetourUpdateProcessWithDll(WorkItem->Target, Dlls, _countof(Dlls))) {
                    LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DetoursX] " __FUNCTION__ "() Update %s to %wZ\n",
                        Dlls[0], WorkItem->CreateInfo->ImageFileName);
                }

                KeSetEvent(&WorkItem->Wait, EVENT_INCREMENT, FALSE);

            }, &WorkItem);
            ExQueueWorkItem(&WorkItem, DelayedWorkQueue);

            KeWaitForSingleObject(&WorkItem.Wait, Executive, KernelMode, FALSE, NULL);
        }
    } while (false);

    if (Handle) {
        ObCloseHandle(Handle, KernelMode);
    }
}
#endif


#ifdef KERNEL_MODE
EXTERN_C VOID DriverUnload(PDRIVER_OBJECT)
#else
EXTERN_C VOID MainExit()
#endif
{
#ifdef KERNEL_MODE
    PsSetCreateProcessNotifyRoutineEx(CreateProcessCallback, true);
#endif

    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());

    DetourDetach((void**)&Hook::_ZwOpenFile, Hook::ZwOpenFile);
    DetourDetach((void**)&Hook::_ZwCreateFile, Hook::ZwCreateFile);

    DetourTransactionCommit();

    LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DetoursX] " __FUNCTION__ "(): Final.\n");
}


#ifdef KERNEL_MODE
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
#else
EXTERN_C int MainEntry()
#endif
{
#ifdef KERNEL_MODE
    PsSetCreateProcessNotifyRoutineEx(CreateProcessCallback, false);
    DriverObject->DriverUnload = DriverUnload;
#else
    DetourRestoreAfterWith();
#endif

    Hook::_ZwOpenFile   = ZwOpenFile;
    Hook::_ZwCreateFile = ZwCreateFile;

    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());

    DetourAttach((void**)&Hook::_ZwOpenFile, Hook::ZwOpenFile);
    DetourAttach((void**)&Hook::_ZwCreateFile, Hook::ZwCreateFile);

    DetourTransactionCommit();

    LOG(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DetoursX] " __FUNCTION__ "(): Begin.\n");
    return STATUS_SUCCESS;
}


#ifndef KERNEL_MODE
EXTERN_C BOOL WINAPI DllMain(_In_ void * /*DllHandle*/, _In_ unsigned Reason, _In_opt_ void * /*Reserved*/) {
    if (Reason == DLL_PROCESS_ATTACH) {
        MainEntry();
    }

    if (Reason == DLL_PROCESS_DETACH) {
        MainExit();
    }

    return TRUE;
}
#endif

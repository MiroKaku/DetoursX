// unnecessary, fix ReSharper's code analysis.
#pragma warning(suppress: 4117)
#define _KERNEL_MODE 1

#include <Veil.h>
#include <detours.h>

#define LOG(fmt, ...) DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DetoursX][%s():%u] " fmt "\n", __FUNCTION__, __LINE__, ## __VA_ARGS__)

namespace
{
    PDRIVER_OBJECT MainDriverObject = nullptr;
}

namespace Hook
{
    class DetourLockGuard
    {
        volatile long& mAtom;

    public:
        explicit DetourLockGuard(volatile long& atom) noexcept
            : mAtom(atom)
        {
            InterlockedCompareExchange(&mAtom, true, false);
        }
        ~DetourLockGuard()
        {
            InterlockedCompareExchange(&mAtom, false, true);
        }
    };

    enum : uint8_t {
        IdxOfMmIsAddressValid = 0u,
    };

    volatile long _locks[2][256] = { { false },{ false } };
    inline volatile long& _lock(size_t idx) {
        return _locks[idx][KeGetCurrentProcessorNumber()];
    }

    static auto _MmIsAddressValid = (decltype(::MmIsAddressValid)*)nullptr;
    BOOLEAN MmIsAddressValid(
        _In_ PVOID VirtualAddress
    )
    {
        if (!InterlockedCompareExchange(&_lock(IdxOfMmIsAddressValid), false, false))
        {
            auto guard = DetourLockGuard(_lock(IdxOfMmIsAddressValid));

            constexpr int max = 3;
            static int count = 0;

            if (count < max) {
                ++count;
                LOG("%p", VirtualAddress);
            }
        }

        return _MmIsAddressValid(VirtualAddress);
    }

    // Note: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager#best
    VOID CreateProcessCallback(
        _Inout_ PEPROCESS Process,
        _In_ HANDLE /*ProcessId*/,
        _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
    {
        do
        {
            if (!CreateInfo || !CreateInfo->FileOpenNameAvailable) {
                break;
            }

             UNICODE_STRING Target = RTL_CONSTANT_STRING(L"*\\NOTEPAD.EXE");
             if (FsRtlIsNameInExpression(&Target, (PUNICODE_STRING)CreateInfo->ImageFileName, TRUE, NULL) == FALSE) {
                 break;
             }

             HANDLE Handle = NULL;
             NTSTATUS Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS,
                 *PsProcessType, KernelMode, &Handle);
             if (!NT_SUCCESS(Status)) {
                 break;
             }

             PIO_WORKITEM WorkItem = IoAllocateWorkItem((PDEVICE_OBJECT)MainDriverObject);
             IoQueueWorkItemEx(WorkItem, [](
                 _In_ PVOID IoObject, _In_opt_ PVOID Handle, _In_ PIO_WORKITEM IoWorkItem)
             {
                 UNREFERENCED_PARAMETER(IoObject);

                 if (Handle) {
                     LPCSTR Dlls[] = {
                         "C:\\Detours.Test.dll",
                     };

                     if (DetourUpdateProcessWithDll(Handle, Dlls, _countof(Dlls))) {
                         for (const auto& Dll : Dlls) {
                             LOG("Import %s to NOTEPAD.EXE", Dll);
                         }
                     }

                     (void)ObCloseHandle(Handle, KernelMode);
                 }

                 if (IoWorkItem) {
                     IoFreeWorkItem(IoWorkItem);
                 }

             }, DelayedWorkQueue, Handle);
        } while (false);
    }
}

namespace Detours::Test
{
    EXTERN_C VOID DriverUnload(PDRIVER_OBJECT);

    EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
    {
        LOG("Enter");
        MainDriverObject = DriverObject;
        DriverObject->DriverUnload = DriverUnload;

        NTSTATUS Status = PsSetCreateProcessNotifyRoutineEx(Hook::CreateProcessCallback, false);
        if (!NT_SUCCESS(Status)) {
            LOG("PsSetCreateProcessNotifyRoutineEx failed: %08X", Status);
            return Status;
        }

        DetourTransactionBegin();
        DetourUpdateThread(ZwCurrentThread());
        {
            Hook::_MmIsAddressValid = MmIsAddressValid;
            DetourAttach((void**)&Hook::_MmIsAddressValid, Hook::MmIsAddressValid);
        }
        DetourTransactionCommit();

        MmIsAddressValid((PVOID)(LONG_PTR)0x1111222233334444);

        LOG("Exit");

        return STATUS_SUCCESS;
    }

    EXTERN_C VOID DriverUnload(PDRIVER_OBJECT)
    {
        LOG("Enter");

        (void)PsSetCreateProcessNotifyRoutineEx(Hook::CreateProcessCallback, true);

        DetourTransactionBegin();
        DetourUpdateThread(ZwCurrentThread());
        {
            DetourDetach((void**)&Hook::_MmIsAddressValid, Hook::MmIsAddressValid);
        }
        DetourTransactionCommit();

        LOG("Exit");
    }
    
}
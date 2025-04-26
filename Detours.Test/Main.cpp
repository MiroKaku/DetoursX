#include <Veil.h>
#include <detours.h>

void LogPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...);
#define LOG(fmt, ...) LogPrint("[DetoursX][%s():%u] " fmt "\n", __FUNCTION__, __LINE__, ## __VA_ARGS__)


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

    thread_local volatile long _locks[2] = { false };
    inline volatile long& _lock(size_t idx) {
        return _locks[idx];
    }

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
            LOG("%wZ", ObjectAttributes ? ObjectAttributes->ObjectName : nullptr);

            UNICODE_STRING Match = RTL_CONSTANT_STRING(L"*\\123.TXT");
            if (ObjectAttributes && RtlIsNameInExpression(&Match, ObjectAttributes->ObjectName, TRUE, NULL)) {
                return STATUS_ACCESS_DENIED;
            }
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
        if (!InterlockedCompareExchange(&_lock(IdxOfZwCreateFile), false, false))
        {
            auto guard = DetourLockGuard(_lock(IdxOfZwCreateFile));
            LOG("%wZ", ObjectAttributes ? ObjectAttributes->ObjectName : nullptr);

            UNICODE_STRING Match = RTL_CONSTANT_STRING(L"*\\123.TXT");
            if (ObjectAttributes && RtlIsNameInExpression(&Match, ObjectAttributes->ObjectName, TRUE, NULL)) {
                return STATUS_ACCESS_DENIED;
            }
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

namespace Detours::Test
{
    EXTERN_C LONG MainEntry()
    {
        LOG("Enter");

        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(ZwCurrentThread());
        {
            Hook::_ZwOpenFile = ::ZwOpenFile;
            Hook::_ZwCreateFile = ::ZwCreateFile;

            DetourAttach((void**)&Hook::_ZwOpenFile, Hook::ZwOpenFile);
            DetourAttach((void**)&Hook::_ZwCreateFile, Hook::ZwCreateFile);
        }
        DetourTransactionCommit();

        LOG("Exit");
        return STATUS_SUCCESS;
    }

    EXTERN_C VOID MainExit()
    {
        LOG("Enter");

        DetourTransactionBegin();
        DetourUpdateThread(ZwCurrentThread());
        {
            DetourDetach((void**)&Hook::_ZwOpenFile, Hook::ZwOpenFile);
            DetourDetach((void**)&Hook::_ZwCreateFile, Hook::ZwCreateFile);
        }
        DetourTransactionCommit();

        LOG("Exit");
    }

    EXTERN_C BOOL WINAPI DllMain(_In_ void* /*DllHandle*/, _In_ unsigned Reason, _In_opt_ void* /*Reserved*/) {
        if (Reason == DLL_PROCESS_ATTACH) {
            MainEntry();
        }

        if (Reason == DLL_PROCESS_DETACH) {
            MainExit();
        }

        return TRUE;
    }
}

void LogPrint(
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

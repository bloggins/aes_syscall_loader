#pragma once
#include <windows.h>

#ifndef _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#define _NTSTATUS_DEFINED
#endif

namespace syscall {

// Resolves system service numbers (SSNs) from a clean copy of ntdll.dll
// and builds direct syscall stubs. Must be called once before use.
bool Initialize();

NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                                 ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                 ULONG AllocationType, ULONG Protect);

NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                                PSIZE_T RegionSize, ULONG NewProtect,
                                PULONG OldProtect);

NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                              PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                              PSIZE_T NumberOfBytesWritten);

NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                          PVOID ObjectAttributes, HANDLE ProcessHandle,
                          PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
                          SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
                          PVOID AttributeList);

NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

NTSTATUS NtClose(HANDLE Handle);

NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
                             PSIZE_T RegionSize, ULONG FreeType);

}

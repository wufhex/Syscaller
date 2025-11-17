<div align="center">
	<br>
	<h1>Syscaller</h1>
	<p>
		<b>Header‑only C++ library for Native API syscall invocation on x64 Windows</b>
	</p>
	<br>
</div>

## Overview

Syscaller is a minimal, dependency‑free, CRT-less C++ library that dynamically resolves and executes Windows Native API system calls.
It works by parsing a system DLLs (e.g., ntdll.dll) to extract syscall IDs at runtime, then generating a small executable stub containing a raw syscall instruction.
This enables direct kernel invocation without going through high‑level user‑mode API wrappers (like kernel32.dll).

Because syscall numbers are resolved dynamically, Syscaller avoids the problem of hard‑coded syscall tables breaking across Windows updates.

Compatible with x64 Windows, using the kernel’s syscall calling convention (R10 for the first argument).

## Documentation

```cpp
/**
 * @brief Retrieves a system call from ntdll.dll.
 *
 * @param name (LPCSTR/const char*) The name of the system call.
 * @param type (type) The function signature/type of the system call.
 *
 * @return Pointer to the system call function cast to the specified type.
 */
auto pFn = MAKE_SYSCALL(name, type)
auto pFn = MAKE_SYSCALL("NtCreateFile", func_t)

/**
 * @brief Retrieves a system call from a specific dll.
 *
 * @param dll (LPCWSTR/const wchar_t*) -> Path or name of the dll containing the system call. (e.g. win32u.dll, ntdll.dll)
 * @param name (LPCSTR/const char*) -> The name of the system call.
 * @param type (type) The function signature/type of the system call.
 *
 * @return Pointer to the system call function cast to the specified type.
 */
auto pFn = MAKE_SYSCALLEX(dll, name, type)
auto pFn = MAKE_SYSCALLEX("win32u.dll", "NtUserWaitMessage", func_t)
```

## Quick Example

```cpp
#include "syscaller/syscaller.hpp"
#include <winternl.h>

typedef NTSTATUS(NTAPI* NtCreateFile_t)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);

int MainEntry() {
    HANDLE            fileHandle;
    IO_STATUS_BLOCK   ioStatusBlock;
    UNICODE_STRING    fileName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&fileName, L"\\??\\C:\\test.txt");
    InitializeObjectAttributes(
        &objAttr,
        &fileName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    auto pNtCreateFile = MAKE_SYSCALL("NtCreateFile", NtCreateFile_t);
    NTSTATUS status = pNtCreateFile(
        &fileHandle,
        FILE_GENERIC_READ,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (status == 0) {
        MessageBoxW(0, L"Opened Successfully!", L"Success", MB_OK);
        CloseHandle(fileHandle);
    }

    return 0;
}
```

## License

Syscaller is free for personal and commercial use under the MIT License.
You can use, modify, and integrate it into your engine or tools.
Forking and contribution is heavily encouraged!

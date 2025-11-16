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
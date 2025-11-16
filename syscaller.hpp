/**
 * @file syscaller.hpp
 * @brief Provides functionality for dynamic execution of Native API system calls.
 *
 * This library first fetches the syscall number for a target
 * Native API function by parsing core system DLLs.
 * It then generates and executes a dynamically patched assembly stub in memory
 * containing the corresponding 'syscall' instruction, 
 * effectively bypassing high-level API wrappers like those found in kernel32.dll.
 * 
 * The code is also designed to work without CRT or any default libraries (/NODEFAULTLIB compatible).
 * 
 * This implementation requires some high level Windows API functions for 
 * memory allocation, memory protection managing, and file reading.
 * And the utility from the C++ standard for std::forward. (DOES NOT depend on CRT)
 *
 * @note This implementation is specifically designed for x64 Windows
 * and follows the kernel syscall calling convention
 * (R10 for the first argument).
 *
 * @see SCCaller::GetSyscall, Syscall::Call, VirtualAlloc, VirtualProtect
 */

#pragma once
#include <Windows.h>
#include <utility>
#pragma comment(lib, "ntdll.lib")

#if !defined(_WIN64)
#error "Syscaller can only be compiled on Windows x64!"
#endif

namespace SCMemUtil {
#undef RtlCopyMemory
#undef RtlFillMemory

#pragma function(memcpy)
#pragma function(memset)

    EXTERN_C void __stdcall RtlCopyMemory(void* Destination, const void* Source, size_t Length);
    EXTERN_C void __stdcall RtlFillMemory(void* Destination, size_t Length, unsigned char Fill);

    HANDLE g_MemProgHeap = NULL;

    void* memcpy(void* dest, const void* src, size_t n) {
        RtlCopyMemory(dest, src, n);
        return dest;
    }

    void* memset(void* dest, int val, size_t n) {
        RtlFillMemory(dest, n, (unsigned char)val);
        return dest;
    }

    void* malloc(SIZE_T size) {
        if (!g_MemProgHeap) {
            g_MemProgHeap = GetProcessHeap();
        }
        return HeapAlloc(g_MemProgHeap, 0, size);
    }

    void free(void* memblock) {
        if (!g_MemProgHeap) {
            g_MemProgHeap = GetProcessHeap();
        }
        HeapFree(g_MemProgHeap, 0, memblock);
    }

    void* calloc(SIZE_T num, SIZE_T size) {
        if (num != 0 && size > SIZE_MAX / num) {
            return NULL;
        }

        SIZE_T totalSize = num * size;

        void* memblock = malloc(totalSize);
        if (!memblock) {
            return NULL;
        }

        SCMemUtil::memset(memblock, 0, totalSize);
        return memblock;
    }

    void* realloc(void* memblock, SIZE_T size) {
        if (!g_MemProgHeap) {
            g_MemProgHeap = GetProcessHeap();
        }

        if (!memblock) {
            return malloc(size);
        }

        if (size == 0) {
            if (memblock != NULL) {
                free(memblock);
            }
            return NULL;
        }

        return HeapReAlloc(
            g_MemProgHeap,
            0,
            memblock,
            size
        );
    }
}

namespace SCSafeStr {
    // Helper to get string length
    static size_t wlen(LPCWSTR s) {
        size_t len = 0;
        while (*s++) len++;
        return len;
    }

    // Helper to copy string
    static void wcopy(LPWSTR dst, LPCWSTR src, size_t n) {
        while (n-- && *src) {
            *dst++ = *src++;
        }
        *dst = 0;
    }

    // Helper to append string
    static void wappend(LPWSTR dst, LPCWSTR src, size_t n) {
        while (*dst) dst++;
        while (n-- && *src) {
            *dst++ = *src++;
        }
        *dst = 0;
    }

    static int strcmp(LPCSTR s1, LPCSTR s2) {
        while (*s1 && (*s1 == *s2)) {
            s1++;
            s2++;
        }
        return (int)(*s1 - *s2);
    }
}

namespace SCFile {
    BOOL ReadFileRaw(
        LPCWSTR filePath,
        UINT8** outBuffer,
        DWORD* outSize
    ) {
        if (!filePath || !outBuffer || !outSize) {
            return FALSE;
        }

        *outBuffer = NULL;
        *outSize = 0;

        DWORD pathSize = GetFullPathNameW(filePath, 0, NULL, NULL);
        if (pathSize == 0) {
            return FALSE;
        }

        LPWSTR fullPath = (LPWSTR)SCMemUtil::malloc(pathSize * sizeof(WCHAR));
        if (!fullPath) {
            return FALSE;
        }

        if (GetFullPathNameW(filePath, pathSize, fullPath, NULL) == 0) {
            SCMemUtil::free(fullPath);
            return FALSE;
        }

        HANDLE hFile = CreateFileW(
            fullPath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return FALSE;
        }

        SCMemUtil::free(fullPath);

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            return FALSE;
        }

        UINT8* buffer = (UINT8*)SCMemUtil::malloc(fileSize);
        if (!buffer) {
            CloseHandle(hFile);
            return FALSE;
        }

        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        if (!ok || bytesRead != fileSize) {
            SCMemUtil::free(buffer);
            return FALSE;
        }

        *outBuffer = buffer;
        *outSize = fileSize;
        return TRUE;
    }

    BOOL WriteFileRaw(
        LPCWSTR      filePath,
        const UINT8* buffer,
        DWORD        size
    ) {
        if (!filePath || !buffer || size == 0) {
            return FALSE;
        }

        DWORD pathSize = GetFullPathNameW(filePath, 0, NULL, NULL);
        if (pathSize == 0) {
            return FALSE;
        }

        LPWSTR fullPath = (LPWSTR)SCMemUtil::malloc(pathSize * sizeof(WCHAR));
        if (!fullPath) {
            return FALSE;
        }

        if (GetFullPathNameW(filePath, pathSize, fullPath, NULL) == 0) {
            SCMemUtil::free(fullPath);
            return FALSE;
        }

        HANDLE hFile = CreateFileW(
            fullPath,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        SCMemUtil::free(fullPath);

        if (hFile == INVALID_HANDLE_VALUE) {
            return FALSE;
        }

        DWORD bytesWritten = 0;
        BOOL ok = WriteFile(hFile, buffer, size, &bytesWritten, NULL);
        CloseHandle(hFile);

        return (ok && bytesWritten == size);
    }
}

namespace SCPE64 {
#define ALIGNUP(value, alignment) \
    ((((UINT_PTR)(value) + ((UINT_PTR)(alignment) - 1)) & ~((UINT_PTR)(alignment) - 1)))

    typedef struct PEFile64 {
        IMAGE_DOS_HEADER         dosHeader;
        IMAGE_NT_HEADERS64       ntHeaders64;
        IMAGE_SECTION_HEADER*    allSectionHeaders;
        UINT32                   numSectionHeaders;
    } PEFile64;

    typedef struct RVARange {
        DWORD start;
        DWORD end;
    } RVARange;

    typedef enum PEFileError {
        PEF_SUCCESS,
        PEF_INVALID_ARGUMENT,
        PEF_INVALID_DOS_MAGIC,
        PEF_INVALID_NT_MAGIC,
        PEF_INCORRECT_ARCH,
        PEF_NET_PE_UNSUPPORTED,
        PEF_NO_SECTION_FOUND,
        PEF_BUFFER_TOO_SMALL,
        PEF_MEM_ALLOC_FAILED
    } PEFileError;

    typedef enum PESectionError {
        PES_SUCCESS,
        PES_INVALID_PARAM,
        PES_INVALID_SECTION,
        PES_CONTENT_INVALID,
        PES_MEM_ALLOC_FAILED
    } PESectionError;

    typedef enum RVAError {
        RVA_SUCCESS,
        RVA_NO_EXPORT_DIRECTORY,
        RVA_INVALID_OFFSET,
        RVA_NOT_FOUND
    } RVAError;

    // Convert RVA -> file offset
    DWORD RVAToRawOffset(
        const PEFile64* parsedPE,
        UINT32          rva
    ) {
        for (UINT32 i = 0; i < parsedPE->numSectionHeaders; i++) {
            const IMAGE_SECTION_HEADER* sec = &parsedPE->allSectionHeaders[i];

            UINT32 secStart = sec->VirtualAddress;
            //UINT32 secEnd = secStart + max(sec->SizeOfRawData, sec->Misc.VirtualSize);
            UINT32 secEnd = secStart + sec->SizeOfRawData;

            if (rva >= secStart && rva < secEnd) {
                return sec->PointerToRawData + (rva - secStart);
            }
        }

        return 0xFFFFFFFF;
    }

    PEFileError ParsePEFile64(
        const UINT8* rawFile,
        SIZE_T       rawFileSize,
        PEFile64* outPEFile
    ) {
        // DOS Header
        if (rawFileSize < sizeof(IMAGE_DOS_HEADER)) {
            return PEF_INVALID_DOS_MAGIC;
        }

        const IMAGE_DOS_HEADER* pDosHeader = (const IMAGE_DOS_HEADER*)rawFile;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return PEF_INVALID_DOS_MAGIC;
        }

        // NT Headers
        if (rawFileSize < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
            return PEF_INVALID_NT_MAGIC;
        }

        const IMAGE_NT_HEADERS64* pNTHeaders64 = (const IMAGE_NT_HEADERS64*)(rawFile + pDosHeader->e_lfanew);
        if (pNTHeaders64->Signature != IMAGE_NT_SIGNATURE) {
            return PEF_INVALID_NT_MAGIC;
        }

        if (pNTHeaders64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            pNTHeaders64->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            return PEF_INCORRECT_ARCH;
        }

        if (pNTHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0) {
            return PEF_NET_PE_UNSUPPORTED;
        }

        if (pNTHeaders64->FileHeader.NumberOfSections == 0) {
            return PEF_NO_SECTION_FOUND;
        }

        // Copy headers
        outPEFile->dosHeader = *pDosHeader;
        outPEFile->ntHeaders64 = *pNTHeaders64;

        // Sections
        PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNTHeaders64);
        if (outPEFile->allSectionHeaders) {
            SCMemUtil::free(outPEFile->allSectionHeaders);
            outPEFile->allSectionHeaders = NULL;
            outPEFile->numSectionHeaders = 0;
        }

        // Get section count
        WORD numSections = pNTHeaders64->FileHeader.NumberOfSections;
        outPEFile->allSectionHeaders = (IMAGE_SECTION_HEADER*)SCMemUtil::calloc(
            numSections, sizeof(IMAGE_SECTION_HEADER)
        );

        if (!outPEFile->allSectionHeaders) {
            // Allocation failed — handle gracefully
            return PEF_MEM_ALLOC_FAILED;
        }

        outPEFile->numSectionHeaders = numSections;

        // Copy section headers from the PE image
        SCMemUtil::memcpy(
            outPEFile->allSectionHeaders,
            pFirstSection,
            numSections * sizeof(IMAGE_SECTION_HEADER)
        );

        return PEF_SUCCESS;
    }

    // Look up the RVA of an exported function by name
    RVAError FindExportRVA(
        UINT8* rawFile,
        SIZE_T          rawFileSize,
        const PEFile64* parsedPE,
        const char* exportName,
        DWORD* op_funcRVA
    ) {
        const IMAGE_OPTIONAL_HEADER64* opt = &parsedPE->ntHeaders64.OptionalHeader;
        DWORD exportRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRVA) {
            return RVA_NO_EXPORT_DIRECTORY;
        }

        UINT32 exportOff = RVAToRawOffset(parsedPE, exportRVA);
        if (exportOff + sizeof(IMAGE_EXPORT_DIRECTORY) > rawFileSize || exportOff == 0) {
            return RVA_INVALID_OFFSET;
        }

        const IMAGE_EXPORT_DIRECTORY* expDir = (const IMAGE_EXPORT_DIRECTORY*)(rawFile + exportOff);

        // Arrays of RVAs
        UINT32 namesRVA = expDir->AddressOfNames;
        UINT32 ordsRVA = expDir->AddressOfNameOrdinals;
        UINT32 funcsRVA = expDir->AddressOfFunctions;

        for (DWORD i = 0; i < expDir->NumberOfNames; ++i) {
            UINT32 nameRVA = *(const UINT32*)(
                rawFile + RVAToRawOffset(parsedPE, namesRVA + i * 4)
                );
            const char* name = (const char*)(
                rawFile + RVAToRawOffset(parsedPE, nameRVA)
                );

            if (SCSafeStr::strcmp(name, exportName) == 0) {
                UINT16 ord = *(const UINT16*)(
                    rawFile + RVAToRawOffset(parsedPE, ordsRVA + i * 2)
                    );
                UINT32 funcRVA = *(const UINT32*)(
                    rawFile + RVAToRawOffset(parsedPE, funcsRVA + ord * 4)
                    );
                *op_funcRVA = funcRVA;
                return RVA_SUCCESS;
            }
        }

        return RVA_NOT_FOUND;
    }

#undef ALIGNUP
}

namespace SCFetcher {
    typedef enum FetchError {
        SCFT_OK,                // Success
        SCFT_INVALID_PARAM,     // Invalid param passed
        SCFT_FILE_READ_ERROR,   // File read error
        SCFT_PARSE_ERROR,       // PE64 parsing error 
        SCFT_EXPORT_NOT_FOUND,  // Requested export not found
        SCFT_INVALID_OFFSET,    // Result RVA -> File offset conversion is invalid.
        SCFT_SYSCALL_NOT_FOUND  // Syscall id not found
    } FetchError;

    DWORD FollowJumpChains(
        UINT8* raw,
        SIZE_T rawSize,
        const SCPE64::PEFile64* pe,
        DWORD startRVA
    ) {
        DWORD currRVA = startRVA;
        const int maxDepth = 8;

        for (int depth = 0; depth < maxDepth; depth++) {
            DWORD off = SCPE64::RVAToRawOffset(pe, currRVA);
            if (off == 0xFFFFFFFF || off + 5 > rawSize) {
                break;
            }

            UINT8* p = raw + off;

            // ---------------------------------------------------------
            // 1) JMP rel32: E9 xx xx xx xx
            // ---------------------------------------------------------
            if (p[0] == 0xE9) {
                INT32 rel = *(INT32*)(p + 1);
                // RVA of next instruction + relative offset
                currRVA = currRVA + 5 + rel;
                continue; // Follow the jump
            }

            // If it's not a jump we recognize, we're done.
            break;
        }
        return currRVA;
    }

    bool ExtractSyscallIdFromStub(
        const UINT8* code,
        SIZE_T       maxLen,
        UINT32*      op_syscallId
    ) {
        // Scan the first few bytes of the stub
        for (SIZE_T i = 0; i + 10 < maxLen; i++) { 

            // On modern Windows, stubs often start with 'mov r10, rcx' (4C 8B D1)
            // The 'mov eax' (B8) might be at offset i=0 or i=3.
            // This loop handles both cases.

            // ============================================================
            // Standard Stub -> mov eax, imm32
            // Opcode: B8 xx xx xx xx
            // ============================================================
            if (code[i] == 0xB8) {
                // Found 'mov eax', read the immediate 32-bit value
                UINT32 imm = *(UINT32*)(code + i + 1);

                // Scan forward from here to find the 'syscall'
                // Opcode: 0F 05
                // We scan ~15 bytes forward
                for (SIZE_T j = i + 5; j < i + 20 && j + 1 < maxLen; j++) {
                    if (code[j] == 0x0F && code[j + 1] == 0x05) {
                        *op_syscallId = imm;
                        return true;
                    }
                }

                // If we found 'mov eax' but it was NOT followed by 'syscall',
                // then this is not the stub we're looking for.
                // We can stop scanning this function.
                return false;
            }
        }

        return false;
    }

    FetchError GetSyscall(
        LPCWSTR dll,
        LPCSTR  exportName,
        UINT32* op_syscallId
    ) {
        if (!dll || !exportName || !op_syscallId) {
            return SCFT_INVALID_PARAM;
        }

        UINT8* fileBuf = nullptr;
        DWORD fileSize = 0;
        if (!SCFile::ReadFileRaw(dll, &fileBuf, &fileSize)) {
            return SCFT_FILE_READ_ERROR;
        }

        SCPE64::PEFile64 pe;
        SCMemUtil::memset(&pe, 0, sizeof(SCPE64::PEFile64));
        pe.allSectionHeaders = nullptr;

        if (SCPE64::ParsePEFile64(fileBuf, fileSize, &pe) != SCPE64::PEF_SUCCESS) {
            SCMemUtil::free(fileBuf);
            return SCFT_PARSE_ERROR;
        }

        DWORD funcRVA = 0;
        if (SCPE64::FindExportRVA(fileBuf, fileSize, &pe, exportName, &funcRVA) != SCPE64::RVA_SUCCESS) {
            SCMemUtil::free(pe.allSectionHeaders);
            SCMemUtil::free(fileBuf);
            return SCFT_EXPORT_NOT_FOUND;
        }

        funcRVA = FollowJumpChains(fileBuf, fileSize, &pe, funcRVA);

        DWORD offset = SCPE64::RVAToRawOffset(&pe, funcRVA);
        if (offset == 0xFFFFFFFF || offset >= fileSize) {
            SCMemUtil::free(pe.allSectionHeaders);
            SCMemUtil::free(fileBuf);
            return SCFT_INVALID_OFFSET;
        }

        UINT32 syscallId = 0;
        bool ok = ExtractSyscallIdFromStub(
            fileBuf + offset,
            64, 
            &syscallId
        );

        SCMemUtil::free(pe.allSectionHeaders);
        SCMemUtil::free(fileBuf);

        if (!ok) {
            return SCFT_SYSCALL_NOT_FOUND;
        }

        *op_syscallId = syscallId;
        return SCFT_OK;
    }
}

namespace SCCaller {
    typedef enum CallerError {
        SCCL_OK,
        SCCL_ALLOC_FAIL,
        SCCL_PROTECT_UPDATE_FAIL
    } CallerError;

    // 4C 8B D1         - mov r10, rcx        
    // B8 DE C0 AD DE   - mov eax, 0xAAAAAAAA (placeholder)
    // 0F 05            - syscall
    // C3               - ret
    const int g_SyscallIdOffset = 4;
    unsigned char g_SyscallStubBytes[] = {
        // Microsoft x64 C/C++ (1st arg in rcx) ->
        // NT syscall calling convention (1st arg in r10)
        // R10 holds the original RCX when entering kernel mode.
        0x4C, 0x8B, 0xD1, 
        0xB8, 0xAA, 0xAA, 0xAA, 0xAA,
        0x0F, 0x05,
        0xC3
    };

    void* g_ExecutableStub = nullptr;

    CallerError Init() {
        if (g_ExecutableStub) {
            return SCCL_OK;
        }

        g_ExecutableStub = VirtualAlloc(
            NULL,
            sizeof(g_SyscallStubBytes),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!g_ExecutableStub) {
            return SCCL_ALLOC_FAIL;
        }

        SCMemUtil::memcpy(g_ExecutableStub, g_SyscallStubBytes, sizeof(g_SyscallStubBytes));

        DWORD oldProtect = 0;
        if (!VirtualProtect(
            g_ExecutableStub, 
            sizeof(g_SyscallStubBytes), 
            PAGE_EXECUTE_READ, 
            &oldProtect)
        ) {
            return SCCL_PROTECT_UPDATE_FAIL;
        }

        return SCCL_OK;
    }

    void Shutdown() {
        if (g_ExecutableStub) {
            VirtualFree(g_ExecutableStub, 0, MEM_RELEASE);
            g_ExecutableStub = nullptr;
        }
    }

    template <typename T>
    T MakeSyscallPtr(UINT32 syscallId) {
        if (!g_ExecutableStub) {
            return nullptr;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(
            g_ExecutableStub,
            sizeof(g_SyscallStubBytes),
            PAGE_EXECUTE_READWRITE,
            &oldProtect)
        ) {
            return nullptr;
        }

        unsigned char* pStub = (unsigned char*)g_ExecutableStub;
        *(DWORD*)(pStub + g_SyscallIdOffset) = syscallId;

        if (!VirtualProtect(
            g_ExecutableStub,
            sizeof(g_SyscallStubBytes),
            PAGE_EXECUTE_READ,
            &oldProtect)
        ) {
            return nullptr;
        }

        return (T)g_ExecutableStub;
    }
}

class Syscall {
public:
    template<typename Fn, typename... Args>
    static auto Call(LPCSTR name, Args&&... args) {
        return Syscall::Get<Fn>(name)(std::forward<Args>(args)...);
    }

    template<typename Fn>
    static Fn Get(LPCWSTR path, LPCSTR name) {
        static Fn fn = nullptr;
        if (!fn) {
            LPCWSTR actPath = path ? path : L"ntdll.dll";
            fn = Syscall::Resolve<Fn>(actPath, name);
        }
        return fn;
    }

private:
    template<typename T>
    static T Resolve(LPCWSTR dll, LPCSTR name) {
        UINT32 id = 0;

        WCHAR fullDllPath[MAX_PATH];
        if (!ResolveDllPath(
            dll,
            fullDllPath,
            MAX_PATH
        )) {
            return nullptr;
        }

        if (SCFetcher::GetSyscall(fullDllPath, name, &id) != SCFetcher::SCFT_OK) {
            return nullptr;
        }

        SCCaller::Init();
        return SCCaller::MakeSyscallPtr<T>(id);
    }

    static BOOL ResolveDllPath(
        LPCWSTR name,
        LPWSTR  outBuf,
        DWORD   outBufSize  // in wchar_t count
    ) {
        // If name already contains '\' or ':', treat as full path
        for (LPCWSTR p = name; *p; p++) {
            if (*p == L'\\' || *p == L':') {
                size_t len = SCSafeStr::wlen(name);
                if (len + 1 > outBufSize) {
                    return FALSE;
                }
                SCSafeStr::wcopy(outBuf, name, outBufSize);
                return TRUE;
            }
        }

        // Get system directory
        WCHAR sysDir[MAX_PATH];
        UINT len = GetSystemDirectoryW(sysDir, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            return FALSE;
        }

        size_t sysLen  = SCSafeStr::wlen(sysDir);
        size_t nameLen = SCSafeStr::wlen(name);

        // Check buffer
        if (sysLen + 1 + nameLen + 1 > outBufSize) {
            return FALSE;
        }

        // Build full path
        SCSafeStr::wcopy(outBuf, sysDir, outBufSize);
        SCSafeStr::wappend(outBuf, L"\\", outBufSize);
        SCSafeStr::wappend(outBuf, name, outBufSize);
        
        return TRUE;
    }
};

/**
 * @brief Retrieves a system call from ntdll.dll.
 *
 * @param name The name of the system call.
 * @param type The function signature/type of the system call.
 *
 * @return Pointer to the system call function cast to the specified type.
 */
#define MAKE_SYSCALL(name, type)        Syscall::Get<type>(nullptr, name)

 /**
  * @brief Retrieves a system call from a specific dll.
  *
  * @param dll  Path or name of the dll containing the system call. (e.g. win32u.dll, ntdll.dll)
  * @param name The name of the system call.
  * @param type The function signature/type of the system call.
  *
  * @return Pointer to the system call function cast to the specified type.
  */
#define MAKE_SYSCALLEX(dll, name, type) Syscall::Get<type>(dll, name)

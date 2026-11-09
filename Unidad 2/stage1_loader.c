/**
 * Lab 1: stage1_loader.c
 * Simulación de loader PE de 64 bits con Dynamic API Resolution (MITRE T1027.007).
 * Utiliza ROR13 hashing para localizar e invocar VirtualAlloc sin usar la IAT.
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Definición de prototipo de VirtualAlloc
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

// Algoritmo de hashing ROR13 para cadenas ASCII y Unicode
DWORD Ror13HashAscii(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << (32 - 13));
        hash += (DWORD)*str;
        str++;
    }
    return hash;
}

DWORD Ror13HashWide(const wchar_t* wstr) {
    DWORD hash = 0;
    while (*wstr) {
        wchar_t c = *wstr;
        if (c >= L'A' && c <= L'Z') c += 32; // Normalización lowercase
        hash = (hash >> 13) | (hash << (32 - 13));
        hash += (DWORD)c;
        wstr++;
    }
    return hash;
}

// 1. Obtener la dirección base de un módulo desde el PEB
HMODULE GetLoadedModuleBase(DWORD moduleHash) {
    PPEB pPeb = (PPEB)__readgsqword(0x60); // TEB->PEB en x64
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pCurr = pHead->Flink;

    while (pCurr != pHead) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pCurr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pEntry->BaseDllName.Buffer != NULL) {
            DWORD h = Ror13HashWide(pEntry->BaseDllName.Buffer);
            if (h == moduleHash) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        pCurr = pCurr->Flink;
    }
    return NULL;
}

// 2. Resolver una función exportada buscando por su hash ROR13
FARPROC ResolveExportByHash(HMODULE hMod, DWORD exportHash) {
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHdrs = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHdr->e_lfanew);
    DWORD exportRva = ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRva == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exportRva);
    DWORD* pNames = (DWORD*)((BYTE*)hMod + expDir->AddressOfNames);
    WORD* pOrds = (WORD*)((BYTE*)hMod + expDir->AddressOfNameOrdinals);
    DWORD* pFuncs = (DWORD*)((BYTE*)hMod + expDir->AddressOfFunctions);

    for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
        char* funcName = (char*)((BYTE*)hMod + pNames[i]);
        if (Ror13HashAscii(funcName) == exportHash) {
            WORD ord = pOrds[i];
            DWORD funcRva = pFuncs[ord];
            return (FARPROC)((BYTE*)hMod + funcRva);
        }
    }
    return NULL;
}

int main() {
    printf("[*] Iniciando Stage 1 Loader (Dynamic API Resolution)\n");

    // Hashes precalculados con ROR13:
    // "kernel32.dll" (lowercase) -> 0x6e2bca17
    // "VirtualAlloc" -> 0x91afca54
    DWORD hashKernel32 = 0x6e2bca17;
    DWORD hashVirtualAlloc = 0x91afca54;

    HMODULE hKernel32 = GetLoadedModuleBase(hashKernel32);
    if (!hKernel32) {
        printf("[-] No se pudo localizar kernel32.dll via PEB.\n");
        return 1;
    }
    printf("[+] kernel32.dll localizada en: 0x%p\n", (void*)hKernel32);

    fnVirtualAlloc myVirtualAlloc = (fnVirtualAlloc)ResolveExportByHash(hKernel32, hashVirtualAlloc);
    if (!myVirtualAlloc) {
        printf("[-] No se pudo resolver VirtualAlloc por API Hashing.\n");
        return 1;
    }
    printf("[+] VirtualAlloc resuelta exitosamente: 0x%p\n", (void*)myVirtualAlloc);

    // Asignación de memoria en runtime sin IAT estática
    LPVOID pMem = myVirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Memoria virtual asignada en: 0x%p\n", pMem);
    printf("[+] Evasión de IAT completada.\n");

    return 0;
}

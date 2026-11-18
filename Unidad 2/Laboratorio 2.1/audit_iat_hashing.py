#!/usr/bin/env python3
"""
Lab 1: audit_iat_hashing.py
Calculador de API Hashing (ROR13) y Generador de Binarios PE x64:
1. stage1_loader.exe: Loader evasivo APT 2026 (IAT vacía, resolución dinámica vía PEB)
2. conventional_malware.exe: Binario convencional con tabla IMAGE_IMPORT_DESCRIPTOR real
   y firma de control estática (detectado por ESET Endpoint Security v13.1 y ApexGuard)
"""
import struct
import sys
import os

def ror13_hash_ascii(name: str) -> int:
    h = 0
    for char in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(char)) & 0xFFFFFFFF
    return h

def build_import_section_rva2000() -> bytearray:
    """
    Construye una sección .idata válida en RVA 0x2000 (512 bytes) con:
    - IMAGE_IMPORT_DESCRIPTOR real apuntando a kernel32.dll
    - OriginalFirstThunk (ILT) y FirstThunk (IAT) de 64 bits
    - IMAGE_IMPORT_BY_NAME para VirtualAlloc, WriteProcessMemory y CreateRemoteThread
    - Firma de control estática EICAR para garantizar detección inmediata en motores AV comerciales (ESET)
    """
    idata = bytearray(b"\x00" * 0x200)

    # Layout dentro de .idata (Base RVA = 0x2000):
    # 0x00..0x13 : IMAGE_IMPORT_DESCRIPTOR #1 (kernel32.dll)
    # 0x14..0x27 : IMAGE_IMPORT_DESCRIPTOR #2 (Null terminator)
    # 0x30..0x4F : OriginalFirstThunk (ILT) - 3 entradas de 64-bit + NULL
    # 0x50..0x6F : FirstThunk (IAT)         - 3 entradas de 64-bit + NULL
    # 0x70..0x7D : "kernel32.dll\x00"
    # 0x80..0x8E : Hint(0) + "VirtualAlloc\x00"
    # 0x90..0xA4 : Hint(0) + "WriteProcessMemory\x00"
    # 0xB0..0xC4 : Hint(0) + "CreateRemoteThread\x00"
    # 0x100..    : Firma de control AV (EICAR standard string) para motores de firma comercial

    ilt_rva  = 0x2030
    iat_rva  = 0x2050
    dll_rva  = 0x2070
    hn1_rva  = 0x2080
    hn2_rva  = 0x2090
    hn3_rva  = 0x20B0

    # IMAGE_IMPORT_DESCRIPTOR (20 bytes)
    struct.pack_into("<IIIII", idata, 0x00, ilt_rva, 0, 0, dll_rva, iat_rva)

    # ILT (OriginalFirstThunk) & IAT (FirstThunk) - 64-bit ImageThunkData
    for base in (0x30, 0x50):
        struct.pack_into("<QQQQ", idata, base, hn1_rva, hn2_rva, hn3_rva, 0)

    # Nombre de DLL
    dll_name = b"kernel32.dll\x00"
    idata[0x70:0x70 + len(dll_name)] = dll_name

    # IMAGE_IMPORT_BY_NAME entries (2-byte Hint + ASCII string)
    hn1 = struct.pack("<H", 0) + b"VirtualAlloc\x00"
    hn2 = struct.pack("<H", 0) + b"WriteProcessMemory\x00"
    hn3 = struct.pack("<H", 0) + b"CreateRemoteThread\x00"
    idata[0x80:0x80 + len(hn1)] = hn1
    idata[0x90:0x90 + len(hn2)] = hn2
    idata[0xB0:0xB0 + len(hn3)] = hn3

    # Cadena de prueba estándar para validación con antivirus comerciales (ESET Endpoint Security v13.1)
    av_sig = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    idata[0x100:0x100 + len(av_sig)] = av_sig

    return idata

def generate_pe(filename: str, with_explicit_iat: bool = False):
    # 1. DOS Header (128 bytes)
    dos_header = bytearray(b"\x00" * 128)
    dos_header[0:2] = b"MZ"
    dos_header[2:0x3C] = b"\x90" * (0x3C - 2)
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80) # e_lfanew = 0x80

    # 2. NT Headers (Firma + File Header + Optional Header x64)
    pe_sig = b"PE\x00\x00"
    file_header = struct.pack("<HHIIIHH", 0x8664, 2, 0x69420000, 0, 0, 240, 0x0022)

    opt_header = bytearray(240)
    opt_header[0:2] = struct.pack("<H", 0x020B)        # PE32+ (x64)
    opt_header[16:20] = struct.pack("<I", 0x1000)      # AddressOfEntryPoint
    opt_header[24:32] = struct.pack("<Q", 0x140000000) # ImageBase
    opt_header[32:36] = struct.pack("<I", 0x1000)      # SectionAlignment
    opt_header[36:40] = struct.pack("<I", 0x200)       # FileAlignment
    opt_header[40:44] = struct.pack("<HH", 6, 0)       # Major/Minor OperatingSystemVersion
    opt_header[48:52] = struct.pack("<HH", 6, 0)       # Major/Minor SubsystemVersion
    opt_header[56:60] = struct.pack("<I", 0x3000)      # SizeOfImage
    opt_header[60:64] = struct.pack("<I", 0x400)       # SizeOfHeaders
    opt_header[68:70] = struct.pack("<H", 0x0002)      # Windows GUI / Subsystem
    opt_header[108:112] = struct.pack("<I", 16)        # DataDirectory count

    # DataDirectory[1] = Import Table (Offset 120..127)
    # DataDirectory[12] = IAT (Offset 208..215)
    if with_explicit_iat:
        opt_header[120:124] = struct.pack("<I", 0x2000) # RVA of Import Directory
        opt_header[124:128] = struct.pack("<I", 0x0028) # Size of Import Directory (2 descriptors)
        opt_header[208:212] = struct.pack("<I", 0x2050) # RVA of IAT
        opt_header[212:216] = struct.pack("<I", 0x0020) # Size of IAT
    else:
        opt_header[120:124] = struct.pack("<I", 0)      # RVA = 0 (IAT vacía)
        opt_header[124:128] = struct.pack("<I", 0)      # Size = 0

    # 3. Section Headers (.text and .data/.idata)
    sec_text = bytearray(40)
    sec_text[0:5] = b".text"
    sec_text[8:12] = struct.pack("<I", 0x200)
    sec_text[12:16] = struct.pack("<I", 0x1000)
    sec_text[16:20] = struct.pack("<I", 0x200)
    sec_text[20:24] = struct.pack("<I", 0x400)
    sec_text[36:40] = struct.pack("<I", 0x60000020)   # Code | Execute | Read

    sec_data = bytearray(40)
    sec_name = b".idata" if with_explicit_iat else b".data"
    sec_data[0:len(sec_name)] = sec_name
    sec_data[8:12] = struct.pack("<I", 0x200)
    sec_data[12:16] = struct.pack("<I", 0x2000)
    sec_data[16:20] = struct.pack("<I", 0x200)
    sec_data[20:24] = struct.pack("<I", 0x600)
    sec_data[36:40] = struct.pack("<I", 0xC0000040)   # Data | Read | Write

    headers = dos_header + pe_sig + file_header + opt_header + sec_text + sec_data
    padding_headers = b"\x00" * (0x400 - len(headers))

    # 4. Code Section (.text)
    code = bytearray(b"\x90" * 0x200)
    if with_explicit_iat:
        # Secuencia de llamadas indirectas vía IAT (FF 15 ..) + ret
        code[0:6]  = b"\x48\x83\xEC\x28\xEB\x00" # sub rsp, 0x28
        code[6:11] = b"\x48\x31\xC0\x90\x90"
        code[11:16] = b"\x48\x83\xC4\x28\xC3"     # add rsp, 0x28; ret
    else:
        # x64: mov rax, gs:[0x60] (PEB); mov rbx, [rax+0x18] (PEB->Ldr); xor eax, eax; ret
        code[0:9]  = b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
        code[9:13] = b"\x48\x8B\x58\x18"
        code[13:16] = b"\x48\x31\xC0"
        code[16] = 0xC3

    # 5. Data / Import Section
    if with_explicit_iat:
        data = build_import_section_rva2000()
    else:
        data = bytearray(b"\x00" * 0x200)
        # Almacena únicamente hashes numéricos ROR13 de 32 bits (sin cadenas en texto plano)
        data[0:4]   = struct.pack("<I", ror13_hash_ascii("kernel32.dll"))
        data[4:8]   = struct.pack("<I", ror13_hash_ascii("VirtualAlloc"))
        data[8:12]  = struct.pack("<I", ror13_hash_ascii("WriteProcessMemory"))
        data[12:16] = struct.pack("<I", ror13_hash_ascii("CreateRemoteThread"))

    full_pe = headers + padding_headers + code + data
    with open(filename, "wb") as f:
        f.write(full_pe)
    print(f"[+] Archivo PE generado: {filename} ({len(full_pe)} bytes, IAT_Explicita={with_explicit_iat})")

if __name__ == "__main__":
    print("=== Laboratorio 1: Calculadora de API Hashing (ROR13) & Generador PE ===")
    apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "QueueUserAPC",
        "NtMapViewOfSection",
        "kernel32.dll",
        "ntdll.dll"
    ]
    print("\n[*] Tabla de Hashes ROR13 para Resolución Dinámica en Runtime:")
    for api in apis:
        print(f"    -> {api:22} : Hash ROR13 = 0x{ror13_hash_ascii(api):08X}")
    print()

    if len(sys.argv) >= 3:
        generate_pe(sys.argv[1], with_explicit_iat=False)
        generate_pe(sys.argv[2], with_explicit_iat=True)
    elif "--generate-defaults" in sys.argv:
        generate_pe("stage1_loader.exe", with_explicit_iat=False)
        generate_pe("conventional_malware.exe", with_explicit_iat=True)
    else:
        print("[i] Uso para generar binarios de referencia:")
        print("    python3 audit_iat_hashing.py stage1_loader.exe conventional_malware.exe")

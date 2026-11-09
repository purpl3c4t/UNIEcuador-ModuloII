#!/usr/bin/env python3
"""
Lab 1: audit_iat_hashing.py
Auditor y generador de hashes ROR13 para funciones de Windows API.
Genera además un binario PE simulado (stage1_loader.exe) para el pipeline de los laboratorios.
"""
import struct
import sys

def ror13_hash_ascii(name: str) -> int:
    h = 0
    for char in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(char)) & 0xFFFFFFFF
    return h

def generate_mock_pe(filename: str = "stage1_loader.exe"):
    """
    Construye un ejecutable PE de 64 bits sintético y válido estructuralmente
    con una IAT completamente vacía y código x86_64 ejecutable.
    """
    # 1. DOS Header (64 bytes)
    # e_magic: MZ (0x5A4D)
    # e_lfanew en offset 0x3C apuntando a 0x80 (128)
    dos_header = bytearray(b"\x00" * 128)
    dos_header[0:2] = b"MZ"
    # Llenamos la zona intermedia con bytes del DOS stub tradicional
    dos_header[2:0x3C] = b"\x90" * (0x3C - 2)
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    # 2. NT Headers (Signature + File Header + Optional Header) en 0x80
    pe_sig = b"PE\x00\x00"
    
    # File Header: Machine=x64 (0x8664), NumberOfSections=2, SizeOfOptionalHeader=240, Characteristics=0x0022 (EXE)
    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,      # Machine (AMD64)
        2,           # NumberOfSections
        0x65432100,  # TimeDateStamp
        0,           # PointerToSymbolTable
        0,           # NumberOfSymbols
        240,         # SizeOfOptionalHeader
        0x0022       # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    # Optional Header (PE32+ / x64, 240 bytes)
    opt_header = bytearray(240)
    opt_header[0:2] = struct.pack("<H", 0x020B)  # Magic: PE32+
    opt_header[2] = 14                           # MajorLinkerVersion
    opt_header[16:20] = struct.pack("<I", 0x1000) # AddressOfEntryPoint (RVA)
    opt_header[24:32] = struct.pack("<Q", 0x140000000) # ImageBase
    opt_header[32:36] = struct.pack("<I", 0x1000) # SectionAlignment
    opt_header[36:40] = struct.pack("<I", 0x200)  # FileAlignment
    opt_header[56:60] = struct.pack("<I", 0x3000) # SizeOfImage
    opt_header[60:64] = struct.pack("<I", 0x400)  # SizeOfHeaders
    opt_header[68:70] = struct.pack("<H", 0x0003) # Subsystem: Windows CUI
    opt_header[70:72] = struct.pack("<H", 0x8160) # DllCharacteristics: DYNAMIC_BASE | NX_COMPAT
    opt_header[108:112] = struct.pack("<I", 16)   # NumberOfRvaAndSizes

    # NOTA CRÍTICA DE EVASIÓN:
    # La Data Directory[1] es IMAGE_DIRECTORY_ENTRY_IMPORT.
    # Se deja deliberadamente en 0 (RVA=0, Size=0) para simular la evasión total de IAT.
    
    # 3. Section Headers (2 secciones: .text y .data, 40 bytes cada una)
    # Sección 1: .text (Executable Code)
    sec_text = bytearray(40)
    sec_text[0:5] = b".text"
    sec_text[8:12] = struct.pack("<I", 0x200)   # VirtualSize
    sec_text[12:16] = struct.pack("<I", 0x1000) # VirtualAddress
    sec_text[16:20] = struct.pack("<I", 0x200)  # SizeOfRawData
    sec_text[20:24] = struct.pack("<I", 0x400)  # PointerToRawData
    sec_text[36:40] = struct.pack("<I", 0x60000020) # Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ

    # Sección 2: .data (Variables / Payload buffer)
    sec_data = bytearray(40)
    sec_data[0:5] = b".data"
    sec_data[8:12] = struct.pack("<I", 0x200)   # VirtualSize
    sec_data[12:16] = struct.pack("<I", 0x2000) # VirtualAddress
    sec_data[16:20] = struct.pack("<I", 0x200)  # SizeOfRawData
    sec_data[20:24] = struct.pack("<I", 0x600)  # PointerToRawData
    sec_data[36:40] = struct.pack("<I", 0xC0000040) # Characteristics: CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE

    # Relleno hasta el final del encabezado (Offset 0x400)
    headers = dos_header + pe_sig + file_header + opt_header + sec_text + sec_data
    padding_headers = b"\x00" * (0x400 - len(headers))

    # 4. Contenido de .text (Offset 0x400 a 0x600):
    # Simula código x86_64: Lectura de GS:[0x60] para PEB y llamada de hashing
    code = bytearray(b"\x90" * 0x200)
    # mov rax, qword ptr gs:[0x60]  -> 65 48 8B 04 25 60 00 00 00
    code[0:9] = b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
    # mov rbx, [rax + 0x18] (PEB->Ldr) -> 48 8B 58 18
    code[9:13] = b"\x48\x8B\x58\x18"
    # ret -> C3
    code[13] = 0xC3

    # 5. Contenido de .data (Offset 0x600 a 0x800):
    # Hashes almacenados en crudo
    data = bytearray(b"\x00" * 0x200)
    # Escribimos los hashes ROR13 de kernel32.dll y VirtualAlloc
    data[0:4] = struct.pack("<I", ror13_hash_ascii("kernel32.dll"))
    data[4:8] = struct.pack("<I", ror13_hash_ascii("VirtualAlloc"))

    full_pe = headers + padding_headers + code + data
    with open(filename, "wb") as f:
        f.write(full_pe)
    print(f"[+] Archivo PE generado exitosamente: {filename} ({len(full_pe)} bytes)")

if __name__ == "__main__":
    print("=== Laboratorio 1: Verificador de API Hashing & Generador PE ===")
    apis = ["VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory", "kernel32.dll"]
    for api in apis:
        h = ror13_hash_ascii(api)
        print(f"[*] API / Modulo: {api:20} -> Hash ROR13: 0x{h:08X}")
    
    target = sys.argv[1] if len(sys.argv) > 1 else "stage1_loader.exe"
    generate_mock_pe(target)

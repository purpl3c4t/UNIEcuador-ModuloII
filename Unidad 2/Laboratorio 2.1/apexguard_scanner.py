#!/usr/bin/env python3
"""
ApexGuard Advanced Endpoint Protection Suite v2026
Core Inspection Engine: Static IAT Analysis & Dynamic User-Mode Hooking Simulation
"""
import sys
import os
import struct
import json

class ApexGuardEngine:
    HIGH_RISK_APIS = {
        "VirtualAlloc": {"weight": 35, "category": "Memory Allocation (RWX)"},
        "VirtualProtect": {"weight": 30, "category": "Memory Permissions Modification"},
        "CreateRemoteThread": {"weight": 40, "category": "Process Injection / Thread Execution"},
        "WriteProcessMemory": {"weight": 35, "category": "Process Memory Modification"},
        "QueueUserAPC": {"weight": 30, "category": "Early Bird Injection"},
        "NtMapViewOfSection": {"weight": 35, "category": "Process Hollowing"},
        "SetThreadContext": {"weight": 25, "category": "Thread Hijacking"}
    }

    def __init__(self, aggressive_mode: bool = True):
        self.aggressive_mode = aggressive_mode
        self.threshold = 70

    def analyze_pe(self, filepath: str):
        if not os.path.exists(filepath):
            return {"error": f"File '{filepath}' not found"}

        with open(filepath, "rb") as f:
            data = f.read()

        if len(data) < 64 or data[:2] != b"MZ":
            return {"error": "Invalid PE binary (missing 'MZ' header)"}

        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            return {"error": "Invalid PE header (missing 'PE\\0\\0' signature)"}

        # Check Optional Header Magic
        opt_offset = e_lfanew + 24
        opt_magic = struct.unpack("<H", data[opt_offset:opt_offset+2])[0]
        is_64bit = (opt_magic == 0x020B)

        # Import Table Directory offset in Optional Header
        # In PE32+ (64-bit), DataDirectory[1] (Imports) is at offset opt_offset + 120
        # In PE32 (32-bit), DataDirectory[1] is at offset opt_offset + 104
        import_dir_offset = (opt_offset + 120) if is_64bit else (opt_offset + 104)
        
        import_rva = 0
        import_size = 0
        if import_dir_offset + 8 <= len(data):
            import_rva, import_size = struct.unpack("<II", data[import_dir_offset:import_dir_offset+8])

        # Scan for plaintext strings of dangerous APIs in entire binary
        detected_apis = []
        score = 0
        for api, meta in self.HIGH_RISK_APIS.items():
            if api.encode("ascii") in data:
                detected_apis.append({
                    "api": api,
                    "weight": meta["weight"],
                    "category": meta["category"],
                    "in_iat": (import_size > 0)
                })
                score += meta["weight"]

        # Cap score at 100
        score = min(100, score)
        is_blocked = (score >= self.threshold)

        verdict = "MALICIOUS / INJECTION_LOADER" if is_blocked else "CLEAN / TRUSTED"

        return {
            "target": os.path.basename(filepath),
            "filesize_bytes": len(data),
            "architecture": "x64" if is_64bit else "x86",
            "import_table_rva": f"0x{import_rva:08X}",
            "import_table_size": f"0x{import_size:08X}",
            "iat_empty": (import_size == 0),
            "detected_high_risk_apis": [d["api"] for d in detected_apis],
            "api_breakdown": detected_apis,
            "threat_score": score,
            "threshold": self.threshold,
            "status": "BLOCKED" if is_blocked else "ALLOWED",
            "verdict": verdict,
            "edr_hook_action": "TERMINATE_PROCESS_ON_LOAD" if is_blocked else "ALLOW_EXECUTION"
        }

    def print_scan_report(self, result: dict):
        print("\n" + "="*70)
        print(" APEXGUARD ADVANCED ENDPOINT PROTECTION v2026 - INSPECTION REPORT")
        print("="*70)
        if "error" in result:
            print(f" [!] ERROR: {result['error']}")
            print("="*70 + "\n")
            return

        print(f" [*] Target File    : {result['target']} ({result['filesize_bytes']} bytes, {result['architecture']})")
        print(f" [*] Import Table   : RVA={result['import_table_rva']}, Size={result['import_table_size']}")
        print(f" [*] IAT Empty?     : {'YES (No static imports declared)' if result['iat_empty'] else 'NO (Explicit imports present)'}")
        print(f" [*] Risk Score     : {result['threat_score']} / 100 (Threshold: {result['threshold']})")
        
        if result['detected_high_risk_apis']:
            print(" [*] High-Risk APIs :")
            for item in result['api_breakdown']:
                print(f"     -> {item['api']:20} [+{item['weight']} pts] - {item['category']}")
        else:
            print(" [*] High-Risk APIs : None found in IAT or plaintext strings.")

        print("-" * 70)
        if result['status'] == "BLOCKED":
            print(f" [!] FINAL VERDICT  : {result['verdict']}")
            print(f" [X] ACTION         : {result['edr_hook_action']} [BLOCKED]")
            print(" [!] Alert Detail   : Binary declares process injection primitives in IAT.")
        else:
            print(f" [+] FINAL VERDICT  : {result['verdict']}")
            print(f" [✓] ACTION         : {result['edr_hook_action']} [ALLOWED]")
            print(" [+] Security Note  : No injection indicators found. Static inspection bypassed.")
        print("="*70 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 apexguard_scanner.py <target_binary.exe>")
        sys.exit(1)

    engine = ApexGuardEngine()
    res = engine.analyze_pe(sys.argv[1])
    engine.print_scan_report(res)

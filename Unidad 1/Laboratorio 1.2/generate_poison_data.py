import numpy as np
import pandas as pd
import os

def generate_poisoning_streams():
    np.random.seed(101)
    n_days = 28 # 4 semanas completas
    samples_per_day = 300
    
    records = []
    # Línea base normal: 100 pps, varianza controlada
    for day in range(1, n_days + 1):
        week = (day - 1) // 7 + 1
        # Tráfico benigno diario
        benign_pps = np.random.normal(loc=100.0, scale=12.0, size=samples_per_day).clip(60, 140)
        
        # Inyección de chaff (Sapo Hervido): Semana 1 (0%), Semana 2 (4%), Semana 3 (10%), Semana 4 (18%)
        rates = {1: 0.0, 2: 0.04, 3: 0.10, 4: 0.18}
        chaff_rate = rates[week]
        n_chaff = int(samples_per_day * chaff_rate)
        
        chaff_pps = []
        if n_chaff > 0:
            # Los paquetes de chaff se introducen justo por encima del tráfico normal pero sin disparar alarmas inmediatas
            chaff_pps = np.random.normal(loc=145.0 + (week * 8), scale=15.0, size=n_chaff).clip(120, 220)
            
        daily_traffic = np.concatenate([benign_pps, chaff_pps])
        np.random.shuffle(daily_traffic)
        
        for val in daily_traffic:
            records.append({
                'day': day,
                'week': week,
                'packets_per_sec': round(val, 2),
                'is_chaff': 1 if val > 140 else 0
            })
            
    df = pd.DataFrame(records)
    out_path = '/workspace/scratch/laboratorios_ueba/lab2_baseline_poisoning/data/network_traffic_stream.csv'
    df.to_csv(out_path, index=False)
    print(f"Lab 2: Stream de tráfico con inyección temporal guardado en {out_path}")

if __name__ == '__main__':
    generate_poisoning_streams()

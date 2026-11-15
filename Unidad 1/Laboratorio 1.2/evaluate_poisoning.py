import numpy as np
import pandas as pd
import os

def calculate_classical_stats(data):
    mean = np.mean(data)
    std = np.std(data)
    threshold = mean + 3.0 * std
    return mean, std, threshold

def calculate_robust_stats(data):
    median = np.median(data)
    # MAD: Median Absolute Deviation
    mad = np.median(np.abs(data - median))
    # Factor consistente para distribución normal: 1.4826
    scaled_mad = 1.4826 * mad
    threshold = median + 3.0 * scaled_mad
    return median, mad, threshold

def evaluate_baseline_drift():
    data_path = os.path.dirname(__file__) + '/data/network_traffic_stream.csv'
    if not os.path.exists(data_path):
        from generate_poison_data import generate_poisoning_streams
        generate_poisoning_streams()
        
    df = pd.read_csv(data_path)
    
    print("================================================================================")
    print(" EVALUACIÓN COMPARATIVA: ESTIMADOR CLÁSICO (MEDIA/STD) VS ROBUSTO (MEDIANA/MAD)")
    print("================================================================================")
    
    # Semana 1: Baseline limpio de referencia
    s1_data = df[df['week'] == 1]['packets_per_sec'].values
    mean_s1, std_s1, thresh_classic_s1 = calculate_classical_stats(s1_data)
    med_s1, mad_s1, thresh_robust_s1 = calculate_robust_stats(s1_data)
    
    print(f"[SEMANA 1 - REFERENCIA LIMPIA]")
    print(f" -> Clásico: Media = {mean_s1:.2f}, Std = {std_s1:.2f} | Umbral Alerta = {thresh_classic_s1:.2f} pps")
    print(f" -> Robusto: Mediana = {med_s1:.2f}, MAD = {mad_s1:.2f} | Umbral Alerta = {thresh_robust_s1:.2f} pps\n")
    
    results = []
    for week in [1, 2, 3, 4]:
        week_data = df[df['week'] <= week]['packets_per_sec'].values
        m, s, t_c = calculate_classical_stats(week_data)
        med, mad, t_r = calculate_robust_stats(week_data)
        
        drift_classic = ((t_c - thresh_classic_s1) / thresh_classic_s1) * 100.0
        drift_robust = ((t_r - thresh_robust_s1) / thresh_robust_s1) * 100.0
        
        results.append({
            'Semana': week,
            'Media_Clasica': round(m, 2),
            'Std_Clasica': round(s, 2),
            'Umbral_Clasico': round(t_c, 2),
            'Drift_Clasico_%': round(drift_classic, 2),
            'Mediana_Robusta': round(med, 2),
            'MAD_Robusta': round(mad, 2),
            'Umbral_Robusto': round(t_r, 2),
            'Drift_Robusto_%': round(drift_robust, 2)
        })
        
        print(f"[SEMANA {week} ACUMULADA]")
        print(f"  [Clásico] Umbral = {t_c:.2f} pps (Desviación acumulada: +{drift_classic:.2f}%)")
        print(f"  [Robusto] Umbral = {t_r:.2f} pps (Desviación acumulada: +{drift_robust:.2f}%)")
        
    df_res = pd.DataFrame(results)
    out_eval = os.path.dirname(__file__) + '/data/poisoning_drift_summary.csv'
    df_res.to_csv(out_eval, index=False)
    
    # Simulación de un ataque de exfiltración masiva en la semana 4 (ej. 165 pps)
    attack_sample = 165.0
    print("\n--------------------------------------------------------------------------------")
    print(f"ESCENARIO DE PRUEBA: El atacante exfiltra a {attack_sample} pps en la Semana 4")
    print("--------------------------------------------------------------------------------")
    final_classic_threshold = results[-1]['Umbral_Clasico']
    final_robust_threshold = results[-1]['Umbral_Robusto']
    
    print(f" Umbral Final Clásico : {final_classic_threshold:.2f} pps -> {'[ALERTA DETECTADA]' if attack_sample > final_classic_threshold else '[BYPASS EXITOSO / CEGUERA CLÁSICA]'}")
    print(f" Umbral Final Robusto : {final_robust_threshold:.2f} pps -> {'[ALERTA DETECTADA / DEFENSA EXITOSA]' if attack_sample > final_robust_threshold else '[BYPASS]'}")
    print("================================================================================\n")

if __name__ == '__main__':
    evaluate_baseline_drift()

# Suite de Laboratorios Prácticos: Detección Basada en Comportamiento (UEBA) y Ciberdefensa Adversarial

Bienvenido al repositorio oficial de materiales prácticos para la suite de laboratorios de la primera unidad. Este repositorio contiene el código ejecutable, datasets sintéticos y guías paso a paso para desarrollar 4 laboratorios prácticos acumulativos (Con duración total estimada de 2 horas) y un Proyecto Integrador autónomo, este proyecto integrador se entrega como tarea el próximo fin de semana.

---

---

## 🚀 Requisitos y Configuración del Entorno

Los scripts están desarrollados en Python 3.10+ y utilizan bibliotecas estándares de ciencia de datos y ciberseguridad.

### Instalación de Dependencias
```bash
pip install torch numpy pandas scikit-learn networkx joblib
```

---

## ⏱️ Secuencia de Ejecución de los Laboratorios (2 Horas)

### Laboratorio 1: LOLBins y Deep Autoencoders (30 min)
* **Objetivo:** Comprender el colapso de contexto y entrenar un autoencoder no supervisado para detectar anomalías mediante el Error Cuadrático Medio (MSE).
* **Ejecución:**
  ```bash
  cd lab1_lotl_autoencoder
  python3 generate_data.py
  python3 train_autoencoder.py
  ```

### Laboratorio 2: Baseline Poisoning y Z-Score Robusto (30 min)
* **Objetivo:** Simular el ataque del sapo hervido para inflar la varianza clásica e implementar el estimador robusto basado en Mediana y MAD.
* **Ejecución:**
  ```bash
  cd ../lab2_baseline_poisoning
  python3 generate_poison_data.py
  python3 evaluate_poisoning.py
  ```

### Laboratorio 3: Zero-Packet Recon y Grafos Temporales (30 min)
* **Objetivo:** Modelar rutas de escalamiento de privilegios y evaluar técnicas de reconocimiento pasivo en memoria local con grafos dirigidos.
* **Ejecución:**
  ```bash
  cd ../lab3_zeropacket_graphs
  python3 create_topology.py
  python3 analyze_lateral_movement.py
  ```

### Laboratorio 4: Insider Threat y Puntuación Compuesta (30 min)
* **Objetivo:** Evaluar eventos forenses de cuentas autorizadas, detectar empaquetado (*staging*) y calcular el riesgo compuesto para revocar sesiones.
* **Ejecución:**
  ```bash
  cd ../lab4_insider_threat
  python3 composite_risk_engine.py
  ```

---

## 🏆 Proyecto Integrador Autónomo

El estudiante debe ejecutar y analizar el script unificado:
```bash
cd ../proyecto_integrador
python3 generate_enterprise_data.py
python3 unified_soc_pipeline.py
```
El reporte a entregar debe incluir:
1. Análisis de por qué el filtro robusto evitó la evasión del atacante.
2. Matriz de confusión obtenida por el pipeline.
3. Recomendaciones operativas para la integración de este modelo en un SIEM/SOAR empresarial.

# Laboratorio 4: Inteligencia de Amenazas y Contrainteligencia: Mitigación de Feed Poisoning y Ataques Self-DoS

## Objetivo de Aprendizaje:
Capacitar al estudiante en la identificación de vectores de contrainteligencia cibernética y contaminación deliberada de fuentes de inteligencia de amenazas (CTI Feed Poisoning), y en el diseño e implementación de una arquitectura de ingestión defensiva en tres capas (evaluación de confianza de la fuente, consenso multi-fuente y listas blancas de infraestructura crítica), previniendo con éxito incidentes de Denegación de Servicio Autoinfligida (*Self-Inflicted Denial of Service - Self-DoS*) y fatiga de alertas en el SOC.

---

## Contexto y Escenario Práctico
Los Centros de Operaciones de Seguridad (SOC) modernos y las plataformas SOAR configuran flujos automatizados para descargar Indicadores de Compromiso (IoCs) desde listas públicas, comunidades abiertas de intercambio (MISP) y foros de la Dark Web, inyectándolos directamente como reglas de bloqueo en firewalls perimetrales y agentes EDR. 

Los adversarios aprovechan esta automatización ciega para ejecutar operaciones de contrainteligencia: publican maliciosamente en fuentes abiertas direcciones IP indispensables (como servidores DNS públicos de Cloudflare `1.1.1.1` o Google `8.8.8.8`) y hashes de binarios legítimos esenciales de Windows (`ntdll.dll`), catalogándolos falsamente como servidores de comando y control (C2) o troyanos. Si la organización aplica estas reglas sin un filtro de validación cruzada, **la propia infraestructura defensiva colapsa la conectividad y operatividad de la empresa**. En este laboratorio,se implementa y audita el sanitizador perimetral en 3 capas que neutraliza estos ataques sin degradar la detección de amenazas reales.

---

## Recursos Involucrados:
* **Datos de Entrada:**
  * `data/poisoned_feed_sample.json` (Feed CTI crudo con 8 indicadores que contienen IoCs legítimos y muestras de envenenamiento).
  * `config.json` (Parámetros de consenso mínimo, listas blancas de protección y pesos de confianza).
* **Scripts de Procesamiento:**
  * `lab4_feed_poisoning/feed_sanitizer.py` (Motor de sanitización defensiva en 3 capas).
  * `lab4_feed_poisoning/simulate_poisoning.py` (Simulador de impacto operacional en el SOC: Ingesta Ingenua vs. Ingesta Sanitizada).
---

## Metodología Paso a Paso

### Paso 1: Ingesta y Preprocesamiento
1. Inspeccionar el feed de inteligencia crudo que simula una fuente agregada externa:
   ```bash
   head -n 35 data/poisoned_feed_sample.json
   ```
2. Observar la mezcla de indicadores:
   * Amenazas reales confirmadas por múltiples fuentes (`194.165.16.44`).
   * Reportes aislados de baja credibilidad en canales clandestinos (`185.220.101.5`).
   * Cargas de envenenamiento dirigidas contra DNS públicos (`1.1.1.1`, `8.8.8.8`) y binarios base del sistema operativo (`ntdll.dll`).
3. Revisar en `config.json` las políticas de seguridad:
   * Umbral mínimo de confianza de la fuente: $\ge 0.80$.
   * Consenso mínimo de fuentes independientes: $\ge 2$.
   * Lista de protección crítica (*Self-DoS Shield*): IPs de DNS esenciales y librerías del sistema.

### Paso 2: Exportación Estructurada:
1. Ejecutar el motor de sanitización en 3 capas:
   ```bash
   python3 lab4_feed_poisoning/feed_sanitizer.py
   ```
2. El script procesa secuencialmente cada indicador a través de los tres filtros:
   * **Capa 1 (Puntuación de Confianza):** Pondera la reputación histórica del emisor.
   * **Capa 2 (Consenso Multi-Fuente):** Exige que el indicador esté corroborado por al menos dos fuentes independientes antes de autorizar el bloqueo perimetral.
   * **Capa 3 (Escudo de Infraestructura Crítica):** Bloquea cualquier intento de inclusión en listas negras de activos protegidos.
3. El motor genera dos entregables JSON:
   * `sanitized_firewall_rules.json`: Contiene únicamente los 2 indicadores que superaron todos los filtros de validación.
   * `sanitizer_drop_audit.json`: Bitácora que documenta los 4 indicadores descartados y el motivo específico del rechazo.

### Paso 3: Simulación SOC y Demostración de Mitigación en Tres Capas
1. Ejecutar el simulador de impacto operativo:
   ```bash
   python3 lab4_feed_poisoning/simulate_poisoning.py
   ```
2. **Contraste de Escenarios en Consola:**
   * **Escenario 1 (Ingesta Ingenua):** Demostrar que el bloqueo ciego de las 8 reglas causa la caída total de la resolución DNS institucional y bloquea binarios del sistema operativo.
   * **Escenario 2 (Ingesta Sanitizada):** Demostrar que el sanitizador activa el escudo preventivo, descarta `185.220.101.5` por falta de consenso, neutraliza los 3 intentos de Self-DoS y autoriza el bloqueo efectivo de `194.165.16.44` y el hash malicioso real.

---

## Verificación

Para constatar la correcta ejecución del laboratorio:

1. **Verificar las reglas perimetrales legítimas aprobadas:**
   ```bash
   cat lab4_feed_poisoning/sanitized_firewall_rules.json
   ```
   *(Debe contener únicamente los 2 IoCs genuinos con consenso $\ge 2$ y confianza $\ge 0.85$).*

2. **Auditar los incidentes de contrainteligencia neutralizados:**
   ```bash
   cat lab4_feed_poisoning/sanitizer_drop_audit.json
   ```
   *(Debe reflejar el descarte de `1.1.1.1`, `8.8.8.8` y el hash de `ntdll.dll` bajo el motivo `CRITICAL_SELF_DOS_PREVENTED`, y de `185.220.101.5` bajo `INSUFFICIENT_CONSENSUS`).*

---

### Entregable Técnico Requerido
1. Archivo `lab4_feed_poisoning/sanitized_firewall_rules.json` con las reglas de bloqueo perimetral saneadas.
2. Archivo `lab4_feed_poisoning/sanitizer_drop_audit.json` con la bitácora forense de auditoría.
3. Analizar cómo la arquitectura de 3 capas previene ataques de Denegación de Servicio Autoinfligido.

## Tarea de la unidad

* **Modalidad:** Tarea autónoma / Proyecto de aplicación práctica (individual).
* **Entrega:** Repositorio de código o script ejecutable documentado con reporte técnico en formato Markdown.

### 1\. Descripción del Escenario Integral

Una organización del sector financiero ha migrado su infraestructura crítica a un entorno híbrido. Un grupo de amenaza avanzada (APT) ha obtenido credenciales estándar de un empleado de operaciones a través de ingeniería social. El adversario ejecutará el ataque completo a lo largo de las cuatro fases vistas en los laboratorios:

1. **Fase 1 (LotL):** Uso de `certutil.exe` para descargar un script ofuscado en Base64 en `%TEMP%`.
2. **Fase 2 (Poisoning):** Inyección paulatina de tráfico falso durante tres semanas para elevar la tolerancia de las alertas de volumen de la API interna.
3. **Fase 3 (Movimiento Lateral):** Reconocimiento pasivo local (`arp` y `netstat`) seguido de un salto lateral mediante *Pass-the-Hash* hacia el servidor de base de datos.
4. **Fase 4 (Exfiltración):** Empaquetado de registros bancarios con contraseña y transmisión fragmentada hacia un servicio de almacenamiento en la nube.

### 2\. Especificación Técnica de los Requerimientos del Proyecto

El estudiante debe integrar los cuatro módulos construidos en un **Pipeline de Monitoreo Continuo** (`unified_soc_pipeline.py`) que cumpla con los siguientes requisitos:

```
+-------------------------------------------------------------------------+
|                      PIPELINE UNIFICADO                                 |
+-------------------------------------------------------------------------+

  [Ingesta de Logs Forenses]
             |
             +---&gt; Módulo A: Detector Deep Autoencoder (PyTorch)
             |      Evalúa anomalía de invocación de proceso y argumentos.
             |
             +---&gt; Módulo B: Filtro Estadístico Robusto (Mediana + MAD)
             |      Evalúa anomalía de volumen descartando contaminación previa.
             |
             +---&gt; Módulo C: Analizador de Caminos en Grafo (NetworkX)
             |      Calcula el costo del camino hacia activos de Nivel Tier-0.
             |
             v
  [Motor de Fusión de Riesgo Compuesto]
             |
             +---&gt; Si Score &lt; 60: Normal (Registro pasivo)
             +---&gt; Si 60 &lt;= Score &lt; 85: Sospechoso (Exigir Step-Up MFA)
             +---&gt; Si Score &gt;= 85: Incidente Activo (Aislamiento + Revocación)

```

### 3\. Entregables

1. **Código Fuente Documentado (** **unified\_soc\_pipeline.py** **):** Script completo en Python 3 que procesa el dataset integrado de prueba y genera la traza forense de ejecución.
2. **Reporte Técnico de Arquitectura (** **informe\_analitico.md** **):**
  * Justificación de por qué el pipeline resistió el envenenamiento de datos del atacante en comparación con un SIEM de reglas clásicas.
  * Matriz de confusión final (Verdaderos Positivos, Falsos Positivos, Verdaderos Negativos y Falsos Negativos).
  * Plan de respuesta a incidentes detallando las llamadas API ejecutadas para aislar la identidad comprometida.

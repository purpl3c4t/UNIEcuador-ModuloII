## Laboratorio 1: Resolución Dinámica de APIs y Evasión de IAT (30 min)

### *Tema 2.1: Ciclo de vida y evolución ofensiva del Malware*
#### * **Objetivo:** Construir un loader funcional en C/C++ que oculte dependencias críticas de la *Import Address Table* (IAT) mediante la técnica MITRE ATT&amp;CK T1027.007[1].
#### * **Entorno:** Contenedor o VM con MinGW-w64 / MSVC y `pefile` en Python.
#### * **Flujo Práctico:**
  1. Compilar un binario simple que llama de forma estática a `VirtualAlloc` y `CreateThread`, inspeccionando su IAT con `dumpbin /imports` o `pefile` para verificar cómo se exponen sus capacidades al análisis estático[4][5].
  2. Implementar la navegación en bajo nivel del *Process Environment Block* (PEB) leyendo el registro de segmento `GS:[0x60]` (x64) para localizar la lista `InMemoryOrderModuleList` y recuperar la dirección base de `kernel32.dll` en memoria virtual[1].
  3. Codificar una rutina de *API Hashing* basada en el algoritmo ROR13 para iterar sobre la `IMAGE_EXPORT_DIRECTORY` y resolver en runtime la función de asignación de memoria sin dejar cadenas legibles[1][8].

* **Entregable de Entrada al Lab 2:** El archivo binario resultante (`stage1_loader.exe`), que presenta una IAT limpia/mínima y ejecuta su lógica asignando memoria de forma dinámica.

*  

# Laboratorio 2: Auditoría y Evasión Adversaria de Clasificadores Basados en IA

## Tema 2.2: Análisis Estático asistido por IA y Evasión de Análisis Estático

### Prerrequisito: Disponer de stage1_loader.exe generado en el Laboratorio 1

#### *1.Objetivo:* Auditar la robustez del modelo de aprendizaje profundo MalConv (entrenado sobre bytes crudos) e implementar un ataque adversario binario9more_horiz.

#### *Entorno:* Jupyter Notebook con PyTorch, MalConv preentrenado (arquitectura con embedding GLU y Global Max Pooling) y la librería captum11more_horiz.

#### *Flujo Práctico:* 

* Los estudiantes evalúan stage1_loader.exe en MalConv y constatan que el clasificador le asigna una probabilidad alta de malicia ($f(\mathbf{x}) \ge 0.5$) debido a las correlaciones globales de sus cabeceras1415.
* Aplican la técnica de explicabilidad Integrated Gradients para visualizar la matriz de atribución de características; identifican que los pesos decisorios se concentran en el encabezado PE y no en las instrucciones funcionales de la sección .text10more_horiz.
* Ejecutan un script en Python que calcula el gradiente del clasificador respecto a los 58 bytes editables del encabezado DOS (respetando estrictamente el número mágico MZ y el offset 0x3C que apunta a la cabecera PE)17more_horiz.
* Generan el binario perturbado (stage2_evasive.exe), verificando que preserva su funcionalidad intacta mientras la probabilidad predicha por MalConv cae drásticamente por debajo del umbral de detección1920.

#### *Entregable de Entrada al Lab 3:*

_El ejecutable stage2_evasive.exe, capaz de evadir el análisis estático de modelos de deep learning._

### Fundamento Técnico y Objetivo

El objetivo es auditar la arquitectura convolucional profunda **MalConv** (Raff et al.) utilizando **Integrated Gradients**. 
Se debe descubrir que el modelo concentra su atención en las cabeceras PE y no en el código de la sección `.text`. Posteriormente, aplicarán un ataque adversario que manipula únicamente los 58 bytes libres del *DOS Header* (Offsets `0x02` a `0x3B`), preservando el número mágico `MZ` y el puntero `e_lfanew` para evadir la detección sin romper la funcionalidad.
El script en `recursos/lab2_static_evasion/ `malconv_adversarial.py` `


### Paso a Paso de Ejecución (Lab 2)

1. Navega al directorio del laboratorio dentro de este folder de Github:

2. Ejecuta el script tomando como entrada el binario del Laboratorio 1:

```
python3 malconv_adversarial.py ../lab1_dynamic_api/stage1_loader.exe stage2_evasive.exe

```

3. **Verificación:** Observa cómo el mapa de relevancia confirma el sesgo de MalConv sobre los primeros 64 bytes y cómo se reduce la probabilidad de detección sin alterar la estructura válida del archivo PE.

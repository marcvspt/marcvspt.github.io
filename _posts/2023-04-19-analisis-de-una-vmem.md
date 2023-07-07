---
title: Análisis forense de una imagen VMEM
author: marcvs
date: 2023-04-19
categories: [Forense, Análisis]
tags: [forense, análisis, memoria, linux, windows]
pin: false
img_path: /assets/img/forense/vmem/
image:
    path: vmem.png
    alt: vmem
---

## ¿Qué es una VMEM?
**Imagen de memoria volátil (VMEM)** es una copia de la **memoria RAM** de un sistema informático en un momento determinado. La **RAM** es un tipo de memoria volátil, lo que significa que su contenido se borra cuando el sistema se apaga o reinicia. Por lo tanto, una imagen de memoria volátil se debe crear en tiempo real mientras el sistema informático está en funcionamiento para poder capturar el contenido de la memoria antes de que se borre.

## ¿Cómo obtengo la VMEM?
Las **VMEM** se pueden adquirir utilizando herramientas especializadas de adquisición de memoria. Estas herramientas crean una copia bit a bit de la **memoria RAM** del sistema y la almacenan en un archivo en disco.

La copia bit a bit, también conocida como una copia de sector a sector, es una copia exacta de un dispositivo o archivo que incluye todos los datos y metadatos, incluyendo cualquier espacio sin asignar o eliminado. En otras palabras, se trata de una copia exacta de todos los bits que componen el dispositivo o archivo original, en este caso la **memoria RAM** en su totalidad y no solo lo que está en uso.

### Sistemas Windows
Obtener con **DumpIt** (linea de comandos):
```powershell
DumpIt.exe -o <imagenvmem.raw/vmem>
```

Obtener con **FTK Imager**:
1. Abrir **FTK Imager** y seleccionar `File > Capture Memory`.
    ![ftk images capture memory](ftk1.png)
2. Elegir la ubicación de destino y nombre del archivo que se guardará.
    ![ftk imager file destination](ftk2.png)
3. Clic en "**Capture Memory**" y esperar a que termine.
    ![ftk imager dump memory](ftk3.png)

### Sistemas Linux
Obtener con **LiME**:
```bash
sudo insmod ./lime.ko "path=memory.lime format=lime"
```

Obtener con comando `dd` (no recomendado):

```bash
sudo dd if=/dev/mem of=/dev/sdb
```

## Análisis de la VMEM
Podemos usar la herramienta **Volatility**, tanto en su versión 2 como su versión 3. Para ver información general del sistema de imagen de una maquina **Linux** en la versión 3 podemos usar:
```bash
python3 vol.py -f ../memory.lime banners.Banners
```

Para ver lo mismo pero de maquina **Windows** con la versión 2:
```powershell
volatility.exe -f ./memory.raw imageinfo
```

Para la imagen **VMEM** que creamos anteriormente en windows con **FTK Imager**, podemos usar igual la versión 3:
![volatility 3 usage](volatility3.png)

### Ejemplo 1: Determinar perfil de una imagen Windows con volatility2
```powershell
volatility.exe -f ./memory.raw imageinfo
```

El comando o argumento `imageinfo` sirve para encontrar listar propiedades y atributos generales de la imagen, entre ellas los posibles perfiles o arquitecturas de la imagen:
![volatility 2 imageinfo output](volatility2-imageinfo.png)

### Ejemplo 2: Ver procesos ocultos de Windows con volatility2
```powershell
volatility.exe -f ./memory.raw --profile=Win7SP1x64 psxview
```

El comando o argumento `psxview` sirve para encontrar procesos ocultos del sistema de la imagen **VMEM**, si el proceso está en false para pslist y psscan, es el que está oculto:
![volatility 2 hide process psxview](volatility2-psxview.png)


## Herramientas
Descargar **DumpIt** (no hay una fuente oficial):
* [https://github.com/thimbleweed/All-In-USB/blob/master/utilities/DumpIt/DumpIt.exe](https://github.com/thimbleweed/All-In-USB/blob/master/utilities/DumpIt/DumpIt.exe)
* [https://www.downloadcrew.com/article/23854/dumpit](https://www.downloadcrew.com/article/23854/dumpit)

Descargar **FTK Imager**:
* [https://www.exterro.com/ftk-imager](https://www.exterro.com/ftk-imager)

Descargar **LiME**:
* [https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME)

Descargar **Volatility 2 y 3**:
* [https://www.volatilityfoundation.org/releases](https://www.volatilityfoundation.org/releases)

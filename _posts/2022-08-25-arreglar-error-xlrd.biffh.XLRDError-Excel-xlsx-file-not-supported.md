---
title: Windows Exploit Suggester (python2) - Arreglo de errores
author: marcvs
date: 2022-08-25
categories: [Errores, Bugs]
tags: [bugs, errores, python2, pip2, linux, windows]
pin: false
img_path: /assets/img/solutions/windows-exploit-suggester/
---

## ¿Qué es Windows Exploit Suggester?
Es una herramienta que compara los niveles de parches de un objetivo **Windows** con la base de datos de vulnerabilidades de **Microsoft** para detectar posibles parches faltantes en el objetivo. También notifica al usuario si hay exploits públicos y módulos **Metasploit** disponibles para los boletines que faltan.

Esta herramienta está desarrollada en **Python2** y se encuentra en el repositorio de **Github** de [AonCyberLabs](https://github.com/AonCyberLabs/Windows-Exploit-Suggester). Las dependencias, es decir, las librerías que utiliza esta herramienta son muy especificas en cuamto a su versión, sin embargo, el repositorio no lo especifica.

## Solución de errores
### Error 1 - Default python
**Python3** es la versión actual y cambiaron varias cosas de la versión 2, entre ellas el nombre de librerias y demás. Al estar desarrollada con **Python2**, al querer ejecutar el script haciendo `./windows-exploit-suggester.py` el detectará la versión instalada, sin embargo, si tanto **Python2** como **Python3** están disponibles, tomará la versión 3 para ejecutar el script por lo que nos dará un error.
![error python default](error-1.jpeg)

Esto es facil de arreglar definiendo bien el shebang, es decir, la primera linea que especifica el lenguaje del script `#!/usr/bin/env python`. Solo hay que agregar un `2` al `python`.
![fix python default](fix-1.jpeg)

### Error 2 - xlrd.biffh.XLRDError: Excel xlsx file; not supported
Tenemos que tener instalado pip2, podemos hacer lo siguiente.
```bash
sudo apt update
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
sudo python2 get-pip.py
```

Este error se ocasiona debido a la versión de la librería **xlrd**, si solo ejecutamos `pip2 install xlrd` se instalará la ultima versión de esta librería.
![error xlrd library](error-2.jpeg)

Sin embargo, la version **1.2.0** y anteriores, son compatibles con esta herramienta, por lo que es mejor ejecutar `pip2 install xlrd==1.2.0`.
![fix lxrd library](fix-2.jpeg)

### Alternativas
Existe una versión de **Python3** de esta herramienta en el repositorio de Github de [Pwnistry](https://github.com/Pwnistry/Windows-Exploit-Suggester-python3) y una de nueva generación también escrita **Python3** de [bitsadmin](https://github.com/bitsadmin/wesng) (recomendada para evitar estos problemas) se instala desde el código fuente o con `pip3 install wesng`.

## Referencias
* Blog hablando de [Windows Exploit Suggester](https://blog.gdssecurity.com/labs/2014/7/11/introducing-windows-exploit-suggester.html).
* [Repositorio de la herramienta python2](https://github.com/AonCyberLabs/Windows-Exploit-Suggester).
* [Repositorio de la herramienta python3](https://github.com/Pwnistry/Windows-Exploit-Suggester-python3).
* [Respositorio de la herramienta de nueva generación](https://github.com/bitsadmin/wesng).
* [Post original de la resolución del problema](https://stackoverflow.com/questions/65254535/xlrd-biffh-xlrderror-excel-xlsx-file-not-supported).
* [Issue donde se resuelve el problema](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/issues/50).

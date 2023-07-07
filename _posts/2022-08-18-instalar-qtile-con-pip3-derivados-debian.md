---
title: Qtile - Instalación con pip3 y Configuración
author: marcvs
date: 2022-08-18
categories: [Instalación, Configuración]
tags: [instalación, configuración, python3, pip3, debian, linux]
pin: false
img_path: /assets/img/configs/qtile/
image:
    path: customized.png
    alt: Qtile customized
---

## ¿Qué es Qtile?
Es un gestor de ventanas en mosaico (tiling window) completo y maleable, escrito y configurado en **Python**, que aprovecha toda la potencia y flexibilidad que ofrece este lenguaje para adaptarlo las necesidades del usuario.

Es simple, pequeño y extensible. Se pueden programar y configurar diseños, widgets y comandos incorporados propios.

## Instalación
Es verdad que en la página oficial de [Qtile](http://docs.qtile.org/en/stable/manual/install/index.html), se muestra como instalar este gestor en diferentes distribuciones, sin embargo, en sistemás como **Kali** o **Parrot**, no se encuentra este paquete en el repositorio, apesar de estar basados en **Debian**.

Además, es poco clara forma de instalarlo con `pip3`, ya que esto se debe hacer como superusuario (root).
```bash
sudo apt update
sudo apt install python3 python3-pip xserver-xorg xinit libpangocairo-1.0-0
sudo python3 -m pip install --upgrade pip
sudo pip3 install xcffib qtile psutil cairocffi
```

La documentación, muestra como instalar este gestor con pip desde los repositorios de **Python PyPI** y desde el código fuente en **GitHub**, sin embargo, no basta con esto ya que no se crea un `qtile.desktop` en `/usr/share/xsessions`. Esto lo podemos hace manual mente creando el archivo.
```conf
[Desktop Entry]
Name=Qtile
Comment=Qtile Session
Exec=qtile start
Type=Application
Keywords=wm;tiling
```

O descargarlo desde el repositorio oficial de [Qtile en Github](https://github.com/qtile/qtile/blob/master/resources/qtile.desktop).
```bash
cd /usr/share/xsessions
sudo wget https://raw.githubusercontent.com/qtile/qtile/master/resources/qtile.desktop
```

Reinciamos el sistema, seleccionamos como gestor de ventanas **Qtile** y listo.
![Qtile installed](instaled.png)

## Personalización
Yo tengo modificado los dotfiles de **Qtile** de [Antonio Sarosi](https://antoniosarosi.com/), ya que tiene muy buenos aspectos, colores y demás. Para más información de configuración visitar su [repositorio](https://github.com/antoniosarosi/dotfiles/blob/master/.config/qtile/README.es.md).
![Qtile customized](customized.png)


## Referencias
* Documentación oficial de [Qtile](http://docs.qtile.org/en/stable/).

## Apoyo
* Apóya con una estrella al repositorio de [Qtile en GitHub](https://github.com/qtile/qtile/).
* Apóya con una estrella al repositorio de **dotfiles** de [Antonio Sarosi](https://github.com/antoniosarosi/dotfiles).

---
title: Instalar LibreWolf en ParrotOS y derivados de Debian
author: marcvs
date: 2023-05-03
categories: [Instalación, Configuración]
tags: [instalación, configuración, web, debian, linux]
pin: false
img_path: /assets/img/configs/librewolf/
image:
    path: librewolf.png
    alt: librewolf
---

## ¿Qué es librewolf?
Es un navegador web de código abierto y privado que se basa en el proyecto **Firefox**. Su objetivo es proporcionar una experiencia de navegación en línea segura y privada sin comprometer la usabilidad y la funcionalidad.

El código fuente completo del navegador **LibreWolf** está disponible públicamente, lo que significa que cualquier persona puede revisarlo y hacer contribuciones para mejorarlo.

### ¿Por qué debería de usarlo?

LibreWolf se centra en la privacidad y la seguridad al bloquear el seguimiento en línea, la recolección de datos y las cookies de terceros. También cuenta con características adicionales para proteger su privacidad, como la navegación en modo privado y el uso de DNS seguros.

Dentro de las opiniones de usuarios que lo usan (como yo), **LibreWolf** se siente más rápido que **Firefox**, aunque en la teoría ambos consumen los mismos recursos.

## Instalación mediante repositorio oficial
En **ParrotOS** como en **Kali Linux**, así como en otras distrubuciones basadas en Debian, no se encuentra **LibreWolf** en los repositorios default del sistema cuando se instala.
![librewolf repository not found debian](not-found.png)

### Metodo 1
En el la página web de este **Browser** podemos ver apartados que hacen referencia a la instalación en distrubiciones basadas **Debian** y **Ubuntu**, pero el problema es que el método oficial tiene un problema a la hora de identificar el **codename** de **Parrot** y **Kali**, poniendo como defecto uno de **Ubuntu**, que aunque este basado en **Debian**, tiene algunos problemas con este.
```bash
sudo apt update && sudo apt install -y wget gnupg lsb-release apt-transport-https ca-certificates

distro=$(if echo " una vanessa focal jammy bullseye vera uma" | grep -q " $(lsb_release -sc) "; then echo $(lsb_release -sc); else echo focal; fi)

wget -O- https://deb.librewolf.net/keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/librewolf.gpg

sudo tee /etc/apt/sources.list.d/librewolf.sources << EOF > /dev/null
Types: deb
URIs: https://deb.librewolf.net
Suites: $distro
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/librewolf.gpg
EOF

sudo apt update
sudo apt install librewolf -y
```

#### Solución al problema con el codename
La linea donde hace detección del **codename** no detecta el repositorio de nuestra la distribución, en este caso `ara` ya que usó **ParrotOS**, que necesita el `/etc/apt/sources.list.d/librewolf.sources` especifiamente en la variable `$distro` que aparece en el apartado `Suites`.
```bash
distro=$(if echo " una vanessa focal jammy bullseye vera uma" | grep -q " $(lsb_release -sc) "; then echo $(lsb_release -sc); else echo focal; fi)
```

La sálida de este comando va a hacer el valor de la variable `$distro` sea igual a **focal**, un **codename** de una versión de **Ubuntu**, que aunque sea basado en **Debian**, es una versión modificada de este, por lo que si queremos que funcione nuestro **LibreWolf** lo mejor es usar el **codename** de la última versión de **Debian**, en este caso `bullseye`.
```bash
sudo apt update && sudo apt install -y wget gnupg lsb-release apt-transport-https ca-certificates

wget -O- https://deb.librewolf.net/keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/librewolf.gpg

sudo tee /etc/apt/sources.list.d/librewolf.sources << EOF > /dev/null
Types: deb
URIs: https://deb.librewolf.net
Suites: bullseye
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/librewolf.gpg
EOF

sudo apt update
sudo apt install librewolf -y
```

Ya no es necesaria la variable `$distro` porque estamos hardcodeando el valor del codename en el apartado `Suites`.
![librewolf repository found debian](search-found.png)

Si tenemos dudas del **codename**, podemos entrar a la URL de el apartado [*URIs*](https://deb.librewolf.net/dists/).
![codename librewolf repository](url-dist.png)

### Metodo 2
También es posible instalar el **.deb** descargandolo de la páguna oficial de [**OpenSuse**](https://download.opensuse.org/repositories/home:/bgstack15:/aftermozilla/Debian_Unstable/amd64/), sin embargo, las actualizaciones no serán efectuadas al hacer `sudo apt -y uptade && sudo apt -y full-upgrade` ya que fue instalado manualmente y el repositorio no está sincronizado en las listas de `apt`.

### LibreWolf instalado
![librewolf installed](installed.png)

## Referencias
* Página oficial del proyecto [LibreWolf](https://librewolf.net/#what-is-librewolf).
* Código fuente [GitLab](https://gitlab.com/librewolf-community/browser).
* Instalación en distribuciones basada en [Debian](https://librewolf.net/installation/debian/).

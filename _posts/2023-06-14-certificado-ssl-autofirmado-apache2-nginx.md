---
title: Certificado SSL autofirmado Apache2 y Nginx
author: marcvs
date: 2023-06-14
categories: [Instalación, Configuración]
tags: [instalación, configuración, http, web, debian, linux]
pin: false
img_path: /assets/img/configs/certssl/
image:
    path: certssl.jpg
    alt: certificado ssl
---

## ¿Qué es SSL?
Capa de Sockets Seguros o Secure Sockets Layer (**SSL**), es un protocolo de seguridad que crea un enlace cifrado entre un servidor y un cliente. El **SSL** se usa para proteger la privacidad, la autenticación y la integridad de los datos que se transmiten por Internet. El **SSL** también se conoce como Seguridad de capa de transporte o Transport Layer Security (**TLS**), que es una versión actualizada y más segura del protocolo.

### ¿Cómo funciona?
La apliación más común de este protocolo es en la comunicación Web entre un servidor y un cliente **HTTP** como un navegador, e.j: firefox, edge, chrome, etc.,:
1. Un navegador o servidor intenta conectarse a un sitio web (es decir, un servidor web) protegido mediante **certificados SSL**.
2. El navegador o servidor solicita que el servidor web se identifique.
3. En respuesta el servidor web envía al navegador o servidor una copia de su **certificado SSL**.
4. El navegador o servidor evalúa si el **certificado SSL** es confiable. En caso afirmativo, envía una señal al servidor web.
5. A continuación, el servidor web devuelve un reconocimiento firmado digitalmente para iniciar una sesión cifrada mediante **SSL**.
6. Los datos cifrados se comparten entre el navegador o servidor y el servidor web.

Los sitios web que usan **SSL** tienen la sigla **HTTPS** en su **URL** en lugar de **HTTP**. Esto indica que la conexión es segura y que los datos están protegidos. También se muestra un ícono de candado en la barra de dirección **URL**.

### Certificados SSL
Un **certificado SSL** es un certificado digital que autentica la identidad de un servidor y habilita una conexión cifrada. El certificado contiene información sobre la identidad del servidor, el algoritmo de cifrado que usa y la autoridad que lo emitió.

Para ver los detalles de un certificado **SSL**, puedes hacer clic en el símbolo de candado ubicado en la barra del navegador. Estos son algunos de los detalles que generalmente se incluyen en los certificados **SSL**:
* El nombre de dominio asociado al certificado emitido
* A qué persona, organización o dispositivo se emitió
* Qué autoridad de certificación lo emitió
* La firma digital de la autoridad de certificación
* Subdominios asociados
* Fecha de emisión del certificado
* La fecha de vencimiento del certificado
* La clave pública (no se revela la clave privada)

#### Tipos
Existen diferentes tipos de certificados **SSL** con diferentes niveles de validación. Estos son los seis tipos principales:
* Certificados de validación extendida (**EV SSL**): son los certificados **SSL** que ofrecen el mayor nivel de confianza y seguridad.
* Certificados validados por la organización (**OV SSL**): son los certificados **SSL** que ofrecen un nivel intermedio de confianza y seguridad.
* Certificados validados por el dominio (**DV SSL**): son los certificados **SSL** que ofrecen el nivel más básico de confianza y seguridad.
* Certificados SSL **comodín**: son los certificados **SSL** que permiten proteger un dominio principal y todos sus subdominios con un solo certificado.
* Certificados SSL de varios dominios (**MDC**): son los certificados **SSL** que permiten proteger varios dominios diferentes con un solo certificado.
* Certificados de comunicaciones unificadas (**UCC**): son los certificados **SSL** que permiten proteger varios dominios y subdominios con un solo certificado.

#### ¿Cómo obtengo un certificado?
Los certificados **SSL** se pueden obtener directamente de una Autoridad de Certificación o Certificate Authority (**CA**). Las CA emiten millones de certificados SSL cada año. Cumplen una función fundamental en el funcionamiento de Internet y en la manera en que se garantizan las interacciones transparentes y de confianza en línea.

El costo de un certificado SSL puede ir desde un certificado gratuito a uno que cuesta cientos de dólares, lo que dependerá del nivel de seguridad que requieras. Una vez que decidas el tipo de certificado que necesitas, puedes buscar emisores de certificados que ofrezcan certificados del nivel que necesitas.

Existen proyectos como [Let's Encrypt](https://letsencrypt.org/es/) que emiten certificados gratuitos. El objetivo de Let’s Encrypt y el protocolo ACME es hacer posible configurar un servidor HTTPS y permitir que este genere automáticamente un certificado válido para navegadores, sin ninguna intervención humana. Esto se logra ejecutando un agente de administración de certificados en el servidor web.

Otro método son los [certificados autofirmados](https://www.entrust.com/es/resources/faq/what-is-a-self-signed-certificate), sin embargo, estos al ser emitidos por una persona, organización o entidad no oficial se reconocen como inseguros, por lo que los navegadores preguntarán siempre antes de acceder a los sitios con certificado autofirmados.

## Certfificado autofirmado Apache2
Debemos configurar un dominio `.local` o con un `TLD`, no registrado, en el `/etc/hosts` para que apunte a la IP de nuestro servidor, para este ejemplo usaremos `example-domain.local` con subdominios `www.example-domain.local`, `db.example-domain.local` y `docker.example-domain.local`.
```conf
127.0.0.1	localhost
127.0.1.1	debian

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

192.168.100.86  example-domain.local www.example-domain.local db.example-domain.local
```
Otra opción es agregar las entradas DNS en el router de nuestra para que el dominio y los subdominos apunten a la IP de nuestra máquina.

Descargamos Apache2 y OpenSSL.
```bash
sudo apt update
sudo apt install openssl apache2
```

Creamos los certificados.
```bash
sudo openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout /etc/ssl/private/example-domain.local.key -out /etc/ssl/certs/example-domain.local.crt -subj "/CN=example-domain.local" -addext "subjectAltName = DNS:example-domain.local, DNS:www.example-domain.local, DNS:db.example.local"
```

Configuramos los parámetros **SSL**.
```bash
sudo nano /etc/apache2/conf-available/ssl-params.conf
```
CONTENIDO
```conf
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
# Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
# Requires Apache >= 2.4
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Requires Apache >= 2.4.11
SSLSessionTickets Off
```

Configuramos el servicio web **HTTPS** para usar nuestro dominio.
```bash
sudo nano /etc/apache2/sites-available/default-ssl.conf
```
CONTENIDO
```conf
<IfModule mod_ssl.c>
	<VirtualHost _default_:443>
		ServerAdmin webmaster@localhost
		ServerName example-domain.local

		DocumentRoot /var/www/html

		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined

		SSLEngine on

		SSLCertificateFile      /etc/ssl/certs/example-domain.local.crt
		SSLCertificateKeyFile /etc/ssl/private/example-domain.local.key

		<FilesMatch "\.(cgi|shtml|phtml|php)$">
			SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
			SSLOptions +StdEnvVars
		</Directory>
	</VirtualHost>
</IfModule>
```

Modificamos el archivo del host para redirigir tráfico hacia **HTTPS**.
```bash
sudo nano /etc/apache2/sites-available/000-default.conf
```
CONTENIDO
```conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost

	DocumentRoot /var/www/html
	Redirect permanent "/" "https://example-domain.local/"

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

Habilitar módulos y la configuración SSL.
```bash
sudo a2enmod ssl
sudo a2enmod headers
sudo a2enconf ssl-params
```

Habilitar nuestro host SSL.
```bash
sudo a2ensite default-ssl
```

Verificar configuración antes de reiniciar.
```bash
sudo apache2ctl configtest
###OUTPUT CORRECT
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.1.1. Set the 'ServerName' directive globally to suppress this message
Syntax OK
```

Reinciamos el servidor.
```bash
sudo service apache2 restart
sudo systemctl restart apache2 #Mismo anterior
```

Advertencia de certificado autofirmado.
![Apache2 advertencia certssl autofirmado](advertencia certssl apache2.png)

Página web con **SSL**.
![Apache2 web con ssl](webssl apache2.png)

Redirección de la **IP**.
![Apache2 redireccion ip a dominio ssl](redireccion ip apache2.png)

### Virtual Hosting
Si queremos hacer virtual hosting podemos crear otro archivo de servicio web apache2.
```bash
sudo nano /etc/apache2/sites-available/db.example-domain.local.conf
```
CONTENIDO
```conf
<VirtualHost *:80>
	ServerName db.example-domain.local
	Redirect permanent "/" "https://db.example-domain.local/"
</VirtualHost>

<VirtualHost *:443>
	ServerName db.example-domain.local
	DocumentRoot /var/www/db/html

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	SSLEngine on
	SSLCertificateFile /etc/ssl/certs/example-domain.local.crt
	SSLCertificateKeyFile /etc/ssl/private/example-domain.local.key

	<FilesMatch "\.(cgi|shtml|phtml|php)$">
		SSLOptions +StdEnvVars
	</FilesMatch>
	<Directory /var/www/db/html>
		SSLOptions +StdEnvVars
		Options -Indexes +FollowSymLinks +MultiViews
		AllowOverride All
		Require all granted
	</Directory>
</VirtualHost>
```

Habilitar nuestro host virtual.
```bash
sudo a2ensite db.example-domain.local.conf
```

Verificar configuración antes de reiniciar.
```bash
sudo apache2ctl configtest
###OUTPUT CORRECT
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.1.1. Set the 'ServerName' directive globally to suppress this message
Syntax OK
```

Reinciamos el servidor.
```bash
sudo service apache2 restart
sudo systemctl restart apache2 #Mismo anterior
```

Ambos servicios coexistiendo en el mismo servidor.
![Apache2 subdominio virtualhosting](virtualhost subdomain apache2.png)

### Dominio principal canónico para SEO
Configuramos el servicio web HTTPS para usar nuestro dominio.
```bash
sudo nano /etc/apache2/sites-available/default-ssl.conf
```
CONTENIDO
```conf
<IfModule mod_ssl.c>
	<VirtualHost _default_:443>
		ServerAdmin webmaster@localhost
		ServerName example-domain.local

		DocumentRoot /var/www/html

		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined

		SSLEngine on

		SSLCertificateFile      /etc/ssl/certs/example-domain.local.crt
		SSLCertificateKeyFile /etc/ssl/private/example-domain.local.key

		<FilesMatch "\.(cgi|shtml|phtml|php)$">
			SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
			SSLOptions +StdEnvVars
		</Directory>

		RewriteEngine On
		RewriteCond %{HTTP_HOST} !^www\. [NC]
		RewriteRule ^(.*)$ https://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
	</VirtualHost>
</IfModule>
```

Debemos habilitar los rewrites con.
```bash
sudo a2enmod rewrite
```

Modificamos el archivo del host para redirigir tráfico hacia HTTPS.
```bash
sudo nano /etc/apache2/sites-available/000-default.conf
```
CONTENIDO
```conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost

	DocumentRoot /var/www/html
	Redirect permanent "/" "https://www.example-domain.local/"

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

Habilitar nuestro host SSL.
```bash
sudo a2ensite default-ssl
```

Verificar configuración antes de reiniciar.
```bash
sudo apache2ctl configtest
###OUTPUT CORRECT
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.1.1. Set the 'ServerName' directive globally to suppress this message
Syntax OK
```

Reinciamos el servidor.
```bash
sudo service apache2 restart
sudo systemctl restart apache2 #Mismo anterior
```

Redireccionamiento visto con las cabeceras de una petición hecha con `curl`.
![Apache2 redireccion dominio raiz a www](redireccion www apache2.png)

## Certfificado autofirmado Nginx
Debemos configurar un dominio `.local` o con un `TLD`, no registrado, en el `/etc/hosts` para que apunte a la IP de nuestro servidor, para este ejemplo usaremos `example-domain.local` con subdominios `www.example-domain.local`, `db.example-domain.local` y `docker.example-domain.local`.
```conf
127.0.0.1	localhost
127.0.1.1	debian

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

192.168.100.86  example-domain.local www.example-domain.local db.example-domain.local docker.example-domain.local
```
Otra opción es agregar las entradas DNS en el router de nuestra para que el dominio y los subdominos apunten a la IP de nuestra máquina.

Descargamos Nginx y OpenSSL.
```bash
sudo apt update
sudo apt install openssl nginx
```

Creamos los certificados.
```bash
sudo openssl req -x509 -nodes -days 730 -newkey rsa:2048 -keyout /etc/ssl/private/example-domain.local.key -out /etc/ssl/certs/example-domain.local.crt -subj "/CN=example-domain.local" -addext "subjectAltName = DNS:example-domain.local, DNS:www.example-domain.local, DNS:db.example.local, DNS:docker.example-domain.local"
```

Configuramos los parámetros SSL.
```bash
sudo nano /etc/nginx/snippets/example-domain.local.conf
```
CONTENIDO
```conf
ssl_certificate /etc/ssl/certs/example-domain.local.crt;
ssl_certificate_key /etc/ssl/private/example-domain.local.key;

ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling off;
ssl_stapling_verify off;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";

ssl_ecdh_curve secp384r1;
```

Configuramos el servicio web para usar HTTPS.
```bash
sudo nano /etc/nginx/sites-available/default
```
CONTENIDO
```nginx
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	server_name example-domain.local;
	return 301 https://$server_name$request_uri;
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;
	server_name example-domain.local;

	include snippets/example-domain.local.conf;

	location / {
		root /var/www/html;
		index index.html index.htm index.nginx-debian.html;
		try_files $uri $uri/ =404;
	}
}
```

Verificar configuración antes de reiniciar.
```bash
sudo nginx -t
###OUTPUT CORRECT
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

Reiniciamos el servidor.
```bash
sudo service nginx restart
sudo systemctl restart nginx #Mismo anterior
```

Advertencia de certificado autofirmado.
![Nginx advertencia certssl autofirmado](advertencia certssl nginx.png)

Página web con **SSL**.
![Nginx web con ssl](webssl nginx.png)

Redirección de la **IP**.
![Nginx redireccion ip a dominio ssl](redireccion ip nginx.png)

### VirtualHosting
Si queremos hacer virtual hosting podemos crear otro archivo de servicio web nginx.
```bash
sudo nano /etc/nginx/sites-available/db.example-domain.local
```
CONTENIDO
```nginx
server {
	listen 80;
	listen [::]:80;
	server_name db.example-domain.local;
	return 301 https://$server_name$request_uri;
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;
	server_name db.example-domain.local;

	include snippets/example-domain.local.conf;

	location / {
		root /var/www/db/html;
		index index.html index.htm index.nginx-debian.html;
		try_files $uri $uri/ =404;
	}
}
```
Debemos crear un enlace simbolico de `sites-available` a `sites-enabled`.
```bash
sudo ln -s /etc/nginx/sites-available/db.example-domain.local /etc/nginx/sites-enabled/db.example-domain.local
```

Verificar configuración antes de reiniciar.
```bash
sudo nginx -t
###OUTPUT CORRECT
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

Reiniciamos el servidor.
```bash
sudo service nginx restart
sudo systemctl restart nginx #Mismo anterior
```

Ambos servicios coexistiendo en el mismo servidor.
![Nginx subdominio virtualhosting](virtualhost subdomain nginx.png)

### Reverse Proxy
Si queremos hacer un reverse proxy podemos crear otro archivo de servicio web nginx.
```bash
sudo nano /etc/nginx/sites-available/docker.example-domain.local
```
CONTENIDO
```nginx
server {
	listen 80;
	listen [::]:80;
	server_name docker.example-domain.local;
	return 301 https://$server_name$request_uri;
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;
	include snippets/example-domain.local.conf;

	server_name docker.example-domain.local;
	location / {
		proxy_pass http://127.0.0.1:8000;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_set_header X-Forwarded-Host $host;
		proxy_set_header X-Forwarded-Port $server_port;
		proxy_set_header X-Forwarded-Server $host;
	}
}
```
Debemos crear un enlace simbolico de `sites-available` a `sites-enabled`.
```bash
sudo ln -s /etc/nginx/sites-available/docker.example-domain.local /etc/nginx/sites-enabled/docker.example-domain.local
```

Servicio web en DockVerificar configuración antes de reiniciar.
```bash
sudo nginx -t
###OUTPUT CORRECT
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

Reiniciamos el servidor.
```bash
sudo service nginx restart
sudo systemctl restart nginx #Mismo anterior
```

Servicio web en **Docker**.
![Servicio web flask python docker](web docker.png)

Servicio web en **Docker** a través de **Nginx**.
![Web flask docker proxy Nginx](revproxy nginx.png)

### Dominio principal canónico para SEO
Podemos usar la configuración de dominio canónico para mejorar el **SEO**.
```bash
sudo nano /etc/nginx/sites-available/default
```
CONTENIDO
```nginx
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	server_name example-domain.local;
	return 301 $scheme://www.example-domain.local$request_uri;
}

server {
	listen 80;
	listen [::]:80;
	server_name www.example-domain.local;
	return 301 https://$server_name$request_uri;
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;
	server_name example-domain.local;

	include snippets/example-domain.local.conf;

	return 301 $scheme://www.example-domain.local$request_uri;
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;
	server_name www.example-domain.local;

	include snippets/example-domain.local.conf;

	location / {
		root /var/www/html;
		index index.html index.htm index.nginx-debian.html;
		try_files $uri $uri/ =404;
	}
}
```

Servicio web en DockVerificar configuración antes de reiniciar.
```bash
sudo nginx -t
###OUTPUT CORRECT
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

Reiniciamos el servidor.
```bash
sudo service nginx restart
sudo systemctl restart nginx #Mismo anterior
```

Redireccionamiento visto con las cabeceras de una petición hecha con `curl`.
![Nginx redireccion dominio raiz a www](redireccion www nginx.png)

## Certificado oficial en un servidor con contenedores
Tengo un repositorio de [GitHub](https://github.com/marcvspt/revproxy-docker) de sobre como desplegar un sistema multiweb con **Docker** y **SSL** usando **Certbot** todo sobre contenedores, desde el **Reverse Proxy**, los servicios web hasta el **Certbot**.

## Referencias
* [¿Qué es un certificado SSL?](https://latam.kaspersky.com/resource-center/definitions/what-is-a-ssl-certificate)
* [¿Qué es un certificado autofirmado?](https://www.entrust.com/es/resources/faq/what-is-a-self-signed-certificate)
* [Let's Encrypt](https://letsencrypt.org/es/)
* [¿Cómo crear un certificado SSL autofirmado para Apache2?](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-18-04-es)
* [¿Cómo crear un certificado SSL autofirmado para Nginx?](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-in-ubuntu-16-04)
* [HTTPS en Nginx](https://techexpert.tips/es/nginx-es/habilitar-https-en-nginx/)
* [HTTP en Nginx certbot Docker](https://mindsers.blog/post/https-using-nginx-certbot-docker/)
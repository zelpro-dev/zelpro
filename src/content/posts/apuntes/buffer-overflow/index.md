---
title: Buffer Overflow
published: 2025-09-06
tags: []
category: Apuntes
---

## ¿Qué es un Buffer?

Un `buffer` es una zona de memoria reservada para almacenar datos temporales. Un ejemplo puede ser un **array** de `char` de tamaño fijo que guarda una cadena de texto. El problema surge cuando el programa no valida la **longitud** de los datos que se copian en el buffer.

## ¿De dónde viene el overflow?

Cuando se dan estas situaciones el exceso de datos se **derraman** hacia direcciones de memoria adyacentes, sobrescribiendo variables, punteros o incluso la `dirección de retorno` de una función. Con esto lo que podemos llegar a conseguir es **ejecutar comandos**.

### Stack (o pila)

Al llamar una función, se crea un **Stack Frame** con:

- Variables locales.
- Dirección de retorno (a dónde volver al acabar la función).
- Registros guardados.

Si el buffer está en la pila y se desborda, los datos pueden sobrescribir la `dirección de retorno`.

- Esto permite que, al terminar la función, el programa salte a una dirección elegida por el atacante.

##  Protecciones modernas contra Buffer Overflow

### 1. Stack Canaries
- **Qué es**: valor aleatorio en el stack antes del return address.  
- **Protección**: detecta sobrescritura antes de retornar.  
- **Identificación**:  
  - Compilación: `-fstack-protector`  
  - Binario: `readelf -s ./binario | grep __stack_chk_fail`

---

### 2. DEP / NX Bit (Data Execution Prevention / No-eXecute)
- **Qué es**: marca stack/heap como no ejecutables.  
- **Protección**: evita ejecutar shellcode en datos.  
- **Identificación**:  
  - Linux: `readelf -l ./binario | grep GNU_STACK`  
    - `RWE` → ejecutable  
    - `RW` → protegido  
  - Windows: `dumpbin` o `PEiD` → `NX compatible`

---

### 3. ASLR (Address Space Layout Randomization)
- **Qué es**: aleatoriza direcciones de memoria.  
- **Protección**: dificulta conocer saltos exactos.  
- **Identificación**:  
  - `cat /proc/sys/kernel/randomize_va_space`  
    - `0` → off  
    - `1` → parcial  
    - `2` → completo  
  - `checksec ./binario` → muestra `PIE`

---

### 4. RELRO (Relocation Read-Only)
- **Qué es**: protege la GOT contra sobrescrituras.  
- **Protección**: GOT parcial o completamente de solo lectura.  
- **Identificación**:  
  - `checksec ./binario`  
    - Partial RELRO  
    - Full RELRO  

---

### 5. Fortificación de librerías (FORTIFY_SOURCE)
- **Qué es**: reemplazo seguro de funciones inseguras (`strcpy`, `sprintf`).  
- **Protección**: validación de longitudes.  
- **Identificación**:  
  - `strings ./binario | grep _chk`  

---

### 6. PIE (Position Independent Executable)
- **Qué es**: ejecutable relocatable.  
- **Protección**: direcciones cambian en cada ejecución (con ASLR).  
- **Identificación**:  
  - `readelf -h ./binario | grep Type`  
    - `DYN` → PIE  
    - `EXEC` → no PIE  
  - `checksec ./binario`  

---

### 7. SafeSEH / SEHOP (Windows)
- **Qué es**: protecciones contra explotación de SEH.  
- **Protección**: evita manipulación de la tabla SEH.  
- **Identificación**:  
  - `dumpbin /headers ./binario.exe | findstr "SafeSEH"`  
  - Herramientas: CFF Explorer  

---

### 8. CFG (Control Flow Guard – Windows)
- **Qué es**: valida saltos indirectos.  
- **Protección**: bloquea ROP y llamadas ilegítimas.  
- **Identificación**:  
  - `dumpbin /loadconfig ./binario.exe` → buscar `Control Flow Guard`  

---

### 9. Shadow Stack / CET (Intel Control-Flow Enforcement Technology)
- **Qué es**: shadow stack protegido por hardware.  
- **Protección**: impide sobrescritura del return address.  
- **Identificación**:  
  - Linux: `dmesg | grep CET` o `cat /proc/cpuinfo`  
  - Windows: Configuración de seguridad → *Hardware-enforced Stack Protection*  

---

### 10. Stack Clash Protections
- **Qué es**: protección contra colisiones de stack y heap.  
- **Protección**: inserta guard pages en memoria.  
- **Identificación**:  
  - Revisar kernel → viene activado en Linux modernos.  

---

## Cómo atacar un Buffer Overflow

### 1. Overwrite de dirección de retorno
- **Idea**: sobrescribir la dirección de retorno de una función en el stack.  
- **Objetivo**: redirigir la ejecución hacia una dirección controlada.  
- **Clásico**: apuntar al buffer donde está el shellcode.  

---

### 2. Shellcode Injection
- **Idea**: inyectar código máquina (payload) dentro del buffer.  
- **Ejemplo**: un shellcode que abre una shell (`/bin/sh`).  
- **Problema moderno**: NX/DEP bloquea ejecución en stack/heap.  

---

### 3. NOP Sled
- **Idea**: rellenar el buffer con muchas instrucciones NOP (`0x90`).  
- **Ventaja**: el return address no necesita apuntar con exactitud, basta caer dentro del sled.  
- **Ejecución**: el flujo “resbala” hasta llegar al shellcode.  

---

### 4. Return-to-libc
- **Idea**: en vez de inyectar código, usar funciones ya existentes en libc.  
- **Ejemplo**: sobrescribir return address con `system()`, pasando `/bin/sh` como argumento.  
- **Ventaja**: evita restricciones de NX/DEP.  

---

### 5. ROP (Return Oriented Programming)
- **Idea**: encadenar pequeños fragmentos de código existentes en memoria (gadgets).  
- **Cada gadget**: termina en `ret`.  
- **Ventaja**: construir un "programa" sin necesidad de inyectar código.  
- **Uso común**: saltarse DEP y ASLR (en combinación con info leaks).  

---

### 6. Jump-Oriented Programming (JOP)
- **Idea**: variante de ROP que usa gadgets terminados en `jmp` en lugar de `ret`.  
- **Ventaja**: evade mitigaciones contra ROP.  

---

### 7. Heap Spraying
- **Idea**: llenar el heap con patrones repetidos (NOPs + shellcode).  
- **Uso**: técnicas web/exploits de navegadores.  
- **Ventaja**: aumenta probabilidad de ejecución en una dirección controlada.  

---

### 8. Off-by-One Exploit
- **Idea**: overflow pequeño (1 byte extra).  
- **Efecto**: modificar un byte crítico (ej. el byte menos significativo del return address).  
- **Uso**: ataques sutiles y difíciles de detectar.  

---

### 9. Format String Exploit
- **Relacionado**: no es exactamente un overflow, pero sí un bug de memoria.  
- **Idea**: usar especificadores de formato `%x`, `%n` para leer/escribir memoria arbitraria.  
- **Uso**: puede derivar en control de ejecución.  

---

### 10. Bypass de protecciones modernas
- **Contra ASLR**: usar *info leaks* para conocer direcciones reales.  
- **Contra NX/DEP**: usar ROP o Return-to-libc.  
- **Contra Canarios**: intentar *brute force* del valor o usar bugs de lectura para filtrarlo.  

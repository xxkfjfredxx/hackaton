# 🔐 TLS/SSL Auditor

> **Hackathon · Reto 2: Sistema de Análisis de Configuración TLS y Riesgo de Exposición en Servicios Web**

Herramienta de ciberseguridad que analiza la configuración TLS/SSL de servidores web para detectar vulnerabilidades, evaluar el nivel de riesgo y generar recomendaciones claras orientadas tanto al equipo técnico como al cliente final.

## 📸 Vista previa

![Dashboard principal — comparación de múltiples servidores](images/preview%20(2).png)

![Dashboard detalle — protocolos, cipher suites y certificado](images/preview%20(4).png)

---

## ¿Para qué sirve?

Cuando un servidor web usa HTTPS, necesita configurar correctamente los protocolos y algoritmos de cifrado (TLS/SSL). Una mala configuración puede permitir que atacantes:

- **Descifren el tráfico** de los usuarios (robo de contraseñas, sesiones, datos personales).
- **Suplanten la identidad** del servidor (ataques Man-in-the-Middle).
- **Aprovechen vulnerabilidades conocidas** como POODLE, FREAK o Heartbleed.

Este sistema escanea uno o más servidores y reporta exactamente qué está mal, qué nivel de riesgo representa y qué acción concreta tomar para solucionarlo.

---

## ¿Qué hace?

| Análisis | Qué detecta |
|---|---|
| **Protocolos TLS/SSL** | SSL 2.0, SSL 3.0, TLS 1.0 y 1.1 obsoletos habilitados |
| **Cipher Suites** | Algoritmos débiles: RC4, DES, 3DES, NULL, EXPORT, MD5 |
| **Puntuación de cifrado** | Score 0-10 por cipher suite con desglose por componente (KEX, Auth, Cipher, Hash) |
| **Certificado digital** | Fecha de vencimiento, confiabilidad (CA reconocida vs. autofirmado) |
| **Vulnerabilidades** | POODLE, FREAK, cipher NULL/ANON |
| **Comparativa** | Matriz de diferencias cuando se escanean múltiples servidores |

---

## Estructura del proyecto

```
hackaton/
├── dashboard.py      ← Interfaz web interactiva (Streamlit) — usar esto
├── tlsauditor.py     ← Motor de análisis + herramienta de línea de comandos
└── README.md
```

**`tlsauditor.py`** contiene toda la lógica de análisis:
- Validación de entradas (IPs, dominios, puertos)
- Sistema de puntuación de cipher suites (0-10 con 4 pesos ponderados)
- Motor de recomendaciones con nivel de severidad (CRÍTICO/ALTO/MEDIO)
- Comparativa entre múltiples servidores

**`dashboard.py`** es la interfaz web que llama a `tlsauditor.py` y muestra los resultados de forma visual.

---

## Instalación

### Requisitos previos

- Python 3.11 o superior
- pip

### 1. Instalar dependencias

```bash
pip install sslyze cryptography streamlit pandas
```

| Librería | Para qué sirve |
|---|---|
| `sslyze` | Motor que ejecuta el escaneo TLS contra el servidor |
| `cryptography` | Lectura y análisis de certificados digitales |
| `streamlit` | Interfaz web del dashboard |
| `pandas` | Tablas de datos en el dashboard |

---

## Cómo ejecutarlo

### Opción A — Dashboard web (recomendado)

```bash
streamlit run dashboard.py
```

![Interfaz del dashboard con resultados de escaneo](images/preview%20(3).png)

Se abre automáticamente el navegador en `http://localhost:8501`.

**Pasos en la interfaz:**
1. En el panel izquierdo, escribe los dominios o IPs a analizar (uno por línea o separados por comas).
2. Activa "Escanear todos los puertos críticos" si quieres revisar más allá del puerto 443.
3. Haz clic en **🔍 Iniciar Escaneo**.
4. Los resultados aparecen organizados en secciones:
   - **Recomendaciones de Seguridad** — hallazgos ordenados por criticidad
   - **Comparación de Servidores** — matriz de diferencias (si se escanean ≥ 2 servidores)
   - **Información Detallada** — protocolos, cipher suites y certificado servidor por servidor

### Opción B — Línea de comandos

```bash
# Un solo servidor (puerto 443 por defecto)
python tlsauditor.py google.com

# Múltiples servidores
python tlsauditor.py google.com cloudflare.com github.com

# Puerto personalizado
python tlsauditor.py api.miservidor.com:8443

# Escanear catálogo completo de puertos
python tlsauditor.py google.com --all-ports
```

---

## Formatos de entrada aceptados

```
google.com
example.com:8443
192.168.1.10
192.168.1.10:443
```

---

## Qué detecta — tabla de hallazgos

| Hallazgo | Severidad | Descripción |
|---|---|---|
| SSL 2.0 habilitado | 🔴 CRÍTICO | Protocolo roto hace décadas — tráfico legible por atacantes |
| SSL 3.0 habilitado | 🔴 CRÍTICO | Vulnerable a POODLE (CVE-2014-3566) — descifra cookies de sesión |
| TLS 1.0 / 1.1 habilitado | 🟠 ALTO | Retirados oficialmente en 2021 (RFC 8996) — degradación de protocolo |
| Sin TLS 1.2 ni 1.3 | 🔴 CRÍTICO | Sin cifrado moderno — todo el tráfico interceptable |
| TLS 1.3 no habilitado | 🟡 MEDIO | Se pierde la versión más rápida y segura disponible |
| Cipher NULL o ANON | 🔴 CRÍTICO | Conexiones sin cifrado o sin autenticación |
| Cipher EXPORT (40-bit) | 🔴 CRÍTICO | Vulnerable a FREAK (CVE-2015-0204) |
| RC4 / DES / 3DES / MD5 | 🟠 ALTO | Algoritmos rotos o con ataques conocidos |
| Certificado vencido | 🔴 CRÍTICO | Navegadores rechazan la conexión con error grave |
| Certificado próximo a vencer | 🟠 ALTO/🔴 CRÍTICO | <30 días → alto, <7 días → crítico |
| Certificado no confiable | 🔴 CRÍTICO | Autofirmado o CA no reconocida — advertencias en el navegador |

---

## Sistema de puntuación de cipher suites

![Desglose detallado de componentes por cipher suite](images/preview%20(1).png)

Cada cipher suite recibe un **score de 0 a 10** calculado con 4 componentes ponderados según criterios de seguridad modernos:

| Componente | Peso | Ejemplos |
|---|---|---|
| Cifrado simétrico + modo | 40% | AES-256-GCM=10, ChaCha20=10, 3DES=2, NULL=0 |
| Intercambio de claves (KEX) | 35% | ECDHE=10, DHE=9, RSA=3, EXPORT=0 |
| Autenticación | 15% | ECDSA=10, RSA=7, ANON=0 |
| Hash / MAC | 10% | SHA-256=10, SHA-1=4, MD5=0 |

**Etiquetas de resultado:**

| Score | Etiqueta |
|---|---|
| 9.0 – 10.0 | ✅ FUERTE |
| 7.0 – 8.9  | 🟢 BUENO |
| 5.0 – 6.9  | 🟡 ACEPTABLE |
| 3.0 – 4.9  | 🟠 DÉBIL |
| 0.0 – 2.9  | 🔴 CRÍTICO |

---

## Catálogo de puertos auditados

Con la opción `--all-ports` (dashboard) o `--all-ports` (CLI), se escanean **33 puertos** en tres perfiles:

| Perfil | Puertos representativos |
|---|---|
| **LEGACY** | 443, 21 (FTP), 995 (POP3S), 993 (IMAPS), 465 (SMTPS), 5900 (VNC), 3306 (MySQL)… |
| **STANDARD** | 5432 (PostgreSQL), 2376 (Docker), 6443 (Kubernetes), 8883 (MQTT), 5061 (SIP-TLS)… |
| **MODERN** | 8500 (Consul), 2379 (etcd), 9443, 9092 (Kafka), 5000, 8000, 3000… |

---

## Ejemplos de entrada y salida

### Ejemplo 1 — Servidor moderno y bien configurado

**Entrada:**
```bash
python tlsauditor.py cloudflare.com
```

**Salida:**
```
=> Iniciando escaneo de 1 endpoint(s) ...

=======================================================
  Resultados para cloudflare.com:443
=======================================================

  -- Soporte de Protocolos --
  SSL 2.0: no soportado
  SSL 3.0: no soportado
  TLS 1.0: no soportado
  TLS 1.1: no soportado
  TLS 1.2: SOPORTADO  (3 cipher suite(s))
      * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    [9.4/10 - FUERTE]
      * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    [9.0/10 - FUERTE]
        ↳ KEX: ECDHE=10  |  Auth: ECDSA=10  |  Cipher: AES_128_GCM=9  |  Hash: SHA256=10
      * TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  [9.8/10 - FUERTE]
  TLS 1.3: SOPORTADO  (3 cipher suite(s))

  -- Información del Certificado --
  Sujeto       : CN=cloudflare.com
  Emisor       : CN=Google Trust Services, O=Google Trust Services, C=US
  Tipo de clave: ECPublicKey
  Válido desde : 2025-01-10 08:00:00+00:00
  Válido hasta : 2025-04-10 07:59:59+00:00
  Vencimiento  : Vence en 89 días — OK
  Confiable    : Sí

  ── ANÁLISIS DE RIESGOS Y RECOMENDACIONES ──
  [OK] Sin hallazgos de seguridad — la configuración es correcta.
```

---

### Ejemplo 2 — Servidor con protocolos obsoletos

**Entrada:**
```bash
python tlsauditor.py servidor-legacy.empresa.com
```

**Salida:**
```
=> Iniciando escaneo de 1 endpoint(s) ...

=======================================================
  Resultados para servidor-legacy.empresa.com:443
=======================================================

  -- Soporte de Protocolos --
  SSL 2.0: no soportado
  SSL 3.0: no soportado
  TLS 1.0: SOPORTADO  (5 cipher suite(s))
      * TLS_RSA_WITH_AES_256_CBC_SHA      [4.9/10 - DÉBIL]   [DÉBIL]
      * TLS_RSA_WITH_3DES_EDE_CBC_SHA     [3.3/10 - DÉBIL]   [DÉBIL]
  TLS 1.1: SOPORTADO  (5 cipher suite(s))
  TLS 1.2: SOPORTADO  (11 cipher suite(s))
  TLS 1.3: no soportado

  -- Información del Certificado --
  Vencimiento  : Vence en 18 días — URGENTE
  Confiable    : Sí

  ────────────────────────────────────────────────────────────
  ANÁLISIS DE RIESGOS Y RECOMENDACIONES
  ────────────────────────────────────────────────────────────

  🟠 [ALTO] Protocolo(s) Obsoleto(s): TLS 1.0, TLS 1.1
     Riesgo : TLS 1.0 y TLS 1.1 fueron retirados en 2021 (RFC 8996).
              Exponen a ataques de degradación de protocolo.
     Acción : Deshabilitar TLS 1.0 y TLS 1.1. Solo habilitar TLS 1.2 y TLS 1.3.

  🟠 [ALTO] Certificado Vence en 18 Día(s)
     Riesgo : El certificado expirará en 18 días. Los usuarios verán
              errores de seguridad si no se renueva a tiempo.
     Acción : Renovar antes de que expire. Considerar Let's Encrypt
              para renovación automática.

  🟡 [MEDIO] TLS 1.3 No Habilitado
     Riesgo : El servidor no ofrece TLS 1.3, la versión más rápida y segura.
     Acción : Habilitar TLS 1.3 — mejora velocidad y seguridad simultáneamente.
```

---

### Ejemplo 3 — Múltiples servidores con comparativa

**Entrada:**
```bash
python tlsauditor.py google.com 1.1.1.1 8.8.8.8
```

**Salida:**
```
=> Iniciando escaneo de 3 endpoint(s) ...

[... resultados individuales de cada servidor ...]

========================================================================
  INFORME DE COMPARACIÓN DE SERVIDORES
========================================================================

-- Matriz de soporte de protocolos --

  Protocolo       google.com:443    1.1.1.1:443    8.8.8.8:443
  ──────────────────────────────────────────────────────────────
  SSL 2.0                     NO             NO             NO
  SSL 3.0                     NO             NO             NO
  TLS 1.0              SÍ(5)             NO             NO    ⚠ DISCREPANCIA
  TLS 1.1              SÍ(5)             NO             NO    ⚠ DISCREPANCIA
  TLS 1.2             SÍ(11)          SÍ(5)          SÍ(3)
  TLS 1.3              SÍ(3)          SÍ(3)          SÍ(3)

-- Diferencias de cipher suites --

  TLS 1.0:
    Solo en google.com:443 (5):
      + TLS_RSA_WITH_AES_256_CBC_SHA            [4.9/10 - DÉBIL]
      + TLS_RSA_WITH_3DES_EDE_CBC_SHA           [3.3/10 - DÉBIL]

-- Tipos de clave de certificado --

  google.com:443       ECPublicKey
  1.1.1.1:443          ECPublicKey
  8.8.8.8:443          ECPublicKey

  ✔ Todos los servidores usan el mismo tipo de clave de certificado.
```

---

### Ejemplo 4 — IP con puerto personalizado

**Entrada:**
```bash
python tlsauditor.py 192.168.1.100:8443
```

**Salida:**
```
=> Iniciando escaneo de 1 endpoint(s) ...

=======================================================
  Resultados para 192.168.1.100:8443
=======================================================

  -- Soporte de Protocolos --
  TLS 1.2: SOPORTADO  (2 cipher suite(s))
  TLS 1.3: no soportado

  -- Información del Certificado --
  Sujeto       : CN=mi-servidor-interno
  Confiable    : No (autofirmado o CA desconocida)
  Vencimiento  : Vence en 365 días — OK

  ────────────────────────────────────────────────────────────
  ANÁLISIS DE RIESGOS Y RECOMENDACIONES
  ────────────────────────────────────────────────────────────

  🔴 [CRÍTICO] Certificado No Confiable (Autofirmado)
     Riesgo : No emitido por una CA reconocida. Los navegadores muestran
              advertencias que alejan a los usuarios.
     Acción : Obtener certificado de una CA reconocida. Let's Encrypt es gratuito.

  🟡 [MEDIO] TLS 1.3 No Habilitado
     Riesgo : El servidor no ofrece TLS 1.3, la versión más rápida y segura.
     Acción : Habilitar TLS 1.3 en el servidor.
```

---

### Ejemplo 5 — Objetivo inválido o sin conectividad

**Entrada:**
```bash
python tlsauditor.py 999.999.999.999 hostname-invalido
```

**Salida:**
```
Advertencia: formato de objetivo incorrecto '999.999.999.999', saltando.
Advertencia: formato de objetivo incorrecto 'hostname-invalido', saltando.
No hay objetivos válidos para escanear.
```

---

### Entradas aceptadas en el dashboard

| Formato de entrada | Válido | Descripción |
|---|---|---|
| `google.com` | ✅ | Dominio estándar, escanea puerto 443 |
| `api.servidor.com:8443` | ✅ | Dominio con puerto personalizado |
| `192.168.1.10` | ✅ | IP directa, puerto 443 |
| `192.168.1.10:443` | ✅ | IP con puerto explícito |
| `localhost` | ✅ | Servidor local |
| `999.999.999.999` | ❌ | IP inválida — ignorada |
| `servidor` (sin punto) | ❌ | Hostname sin TLD — ignorado |

---

## Notas importantes

- **Solo uso defensivo**: esta herramienta diagnostica configuraciones inseguras, no explota vulnerabilidades.
- **Sin dependencias externas de red**: todo el análisis se hace conectando directamente al servidor objetivo.
- El escaneo puede tardar de **segundos a minutos** dependiendo del número de servidores y puertos.
- Ambos archivos (`dashboard.py` y `tlsauditor.py`) deben estar en la **misma carpeta**.


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

## Ejemplo de salida en terminal

```
=> Iniciando escaneo de 1 endpoint(s) ...

=======================================================
  Resultados para google.com:443
=======================================================

  -- Soporte de Protocolos --
  SSL 2.0: no soportado
  SSL 3.0: no soportado
  TLS 1.0: no soportado
  TLS 1.1: no soportado
  TLS 1.2: SOPORTADO  (5 cipher suite(s))
      * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    [9.4/10 - FUERTE]
      * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256       [8.6/10 - BUENO]
  TLS 1.3: SOPORTADO  (3 cipher suite(s))

  -- Información del Certificado --
  Sujeto      : CN=*.google.com
  Confiable   : Sí
  Vencimiento : Vence en 72 días — OK

  ── ANÁLISIS DE RIESGOS Y RECOMENDACIONES ──

  🟡 [MEDIO] TLS 1.3 No Habilitado
     Riesgo : El servidor no ofrece TLS 1.3...
     Acción : Habilitar TLS 1.3 en el servidor.
```

---

## Notas importantes

- **Solo uso defensivo**: esta herramienta diagnostica configuraciones inseguras, no explota vulnerabilidades.
- **Sin dependencias externas de red**: todo el análisis se hace conectando directamente al servidor objetivo.
- El escaneo puede tardar de **segundos a minutos** dependiendo del número de servidores y puertos.
- Ambos archivos (`dashboard.py` y `tlsauditor.py`) deben estar en la **misma carpeta**.

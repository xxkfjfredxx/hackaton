# TLS Auditor — Sistema de Análisis de Configuración TLS

> **Hackathon · Reto 2: Sistema de Análisis de Configuración TLS y Riesgo de Exposición en Servicios Web**

Sistema modular de auditoría TLS/SSL que analiza servidores web, identifica configuraciones inseguras, clasifica hallazgos por criticidad y genera reportes accionables.

---

## Estructura del proyecto

```
hackaton/
├── run_audit.py              ← Orquestador principal (punto de entrada)
├── targets.txt               ← Ejemplo de archivo de targets
├── scanner/
│   ├── 01_validator.py       ← Validación y normalización de entradas
│   ├── 02_tls_scanner.py     ← Motor TLS (sslyze + ssl nativo fallback)
│   ├── 03_nmap_scanner.py    ← Escaneo de puertos y vulnerabilidades (Nmap NSE)
│   ├── 04_crypto_analyzer.py ← Análisis criptográfico (librería cryptography)
│   ├── 05_risk_evaluator.py  ← Motor de riesgo y recomendaciones
│   └── 06_reporter.py        ← Generador de reportes (JSON, CSV, HTML, TXT)
└── reports/                  ← Reportes generados automáticamente
```

---

## Instalación de dependencias

```bash
pip install sslyze cryptography pdfplumber
```

> **Nmap** (opcional pero recomendado):  
> Descargar desde https://nmap.org/download.html e instalar.  
> Debe estar en el PATH del sistema.

---

## Uso

### Auditar dominios directamente

```bash
# Un solo objetivo
python run_audit.py google.com

# Múltiples objetivos
python run_audit.py google.com cloudflare.com github.com

# Con puerto personalizado
python run_audit.py api.myserver.com:8443
```

### Desde archivo de targets

```bash
python run_audit.py --file targets.txt
```

Formato del archivo `targets.txt`:
```
# Comentarios con #
google.com
cloudflare.com:443
github.com
192.168.1.1:8443
```

### Opciones de reporte

```bash
# Generar solo HTML
python run_audit.py google.com --format html

# Generar JSON y CSV
python run_audit.py google.com --format json csv

# Todos los formatos (default)
python run_audit.py google.com --format all

# Directorio de salida personalizado
python run_audit.py google.com --out ./mis_reportes/
```

### Omitir Nmap (más rápido si Nmap no está instalado)

```bash
python run_audit.py google.com --skip-nmap
```

---

## Módulos (scripts independientes)

Cada módulo puede ejecutarse de forma standalone para tests:

```bash
# Validar targets
python scanner/01_validator.py google.com bad_target 999.999.999.999

# Escaneo TLS
python scanner/02_tls_scanner.py google.com github.com --json

# Escaneo Nmap NSE
python scanner/03_nmap_scanner.py google.com --quick

# Análisis criptográfico
python scanner/04_crypto_analyzer.py github.com

# Evaluación de riesgo (requiere JSON previo)
python scanner/05_risk_evaluator.py --input audit_data.json

# Generar reportes desde JSON
python scanner/06_reporter.py --input audit_data.json --format html
```

---

## Qué detecta el sistema

| Hallazgo | Severidad | Módulo |
|---|---|---|
| SSL 2.0 / SSL 3.0 habilitado | CRITICAL | 02 |
| TLS 1.0 habilitado | HIGH | 02 |
| TLS 1.1 habilitado | MEDIUM | 02 |
| TLS 1.3 ausente | MEDIUM | 02 |
| Cipher suites débiles (RC4, 3DES, NULL, EXPORT) | HIGH | 02 |
| Certificado expirado | CRITICAL | 02, 04 |
| Certificado por expirar (<30 días) | HIGH/MEDIUM | 02, 04 |
| Certificado no confiable (autofirmado) | CRITICAL | 02 |
| Clave pública débil (RSA<2048, EC<256) | HIGH | 04 |
| Algoritmo de firma SHA1/MD5 | HIGH | 04 |
| Certificado de larga duración (>825 días) | LOW | 04 |
| Heartbleed (CVE-2014-0160) | CRITICAL | 03 |
| POODLE (CVE-2014-3566) | HIGH | 03 |
| LOGJAM / DH débil (CVE-2015-4000) | HIGH | 03 |
| Grade de cifrado F/E por ssl-enum-ciphers | HIGH | 03 |
| Headers HTTP de seguridad ausentes (HSTS, CSP, etc.) | MEDIUM/LOW | 03 |

---

## Formatos de reporte

| Formato | Descripción |
|---|---|
| **HTML** | Reporte visual auto-contenido, ideal para presentación |
| **JSON** | Datos estructurados para integración con GUI futura |
| **CSV** | Vista tabular para análisis en Excel / pandas |
| **TXT** | Salida de consola estructurada para logs |

---

## Integración con GUI (futura)

La GUI debe llamar la función `run_audit()` de `run_audit.py`:

```python
from run_audit import run_audit

result = run_audit(
    raw_targets=["google.com", "github.com"],
    formats=["html", "json"],
    skip_nmap=False,
    output_dir="reports/",
    quiet=True,          # suprimir stdout
)

# Acceder a resultados
for ev in result["evaluations"]:
    print(ev["host"], ev["risk_level"], ev["risk_score"])

# Ruta del reporte HTML generado
html_path = result["reports"].get("html")
```

---

## Ejemplo de salida

```
Servidor  : google.com:443
Riesgo    : CRITICAL (100/100)
Hallazgos : 6 total
  * [HIGH] TLS 1.0 habilitado (protocolo obsoleto)
    Rec: Deshabilitar TLS 1.0. Deprecado por RFC 8996.
  * [HIGH] Cipher suites débiles en TLS 1.0
    Rec: Deshabilitar RC4, 3DES, DES, NULL, EXPORT o MD5.
  * [HIGH] Cipher suites débiles en TLS 1.1
  * [HIGH] Cipher suites débiles en TLS 1.2 (3DES)
  * [MEDIUM] TLS 1.3 no habilitado
  * [MEDIUM] No habilitado TLS 1.1 → debería deshabilitarse

Servidor  : github.com:443
Riesgo    : LOW (10/100)
Hallazgos : 1 total
  * [MEDIUM] TLS 1.3 no habilitado
```

---

## Dependencias

| Librería | Versión | Uso |
|---|---|---|
| `sslyze` | ≥5.x | Motor principal de análisis TLS |
| `cryptography` | ≥42.x | Análisis criptográfico de certificados |
| `nmap` | ≥7.x | Escaneo de puertos y vulnerabilidades NSE |

---

## Restricciones del reto

- **Enfoque defensivo**: el sistema diagnostica configuraciones inseguras, no explota vulnerabilidades.
- **Sin dependencias de red externas**: todo el análisis es directo contra el servidor objetivo.
- **Reproducible**: cada ejecución genera un reporte con timestamp único.

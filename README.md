# 🔐 TLS Auditor — Sistema de Análisis de Configuración TLS

> **Hackathon · Reto 2: Sistema de Análisis de Configuración TLS y Riesgo de Exposición en Servicios Web**

Sistema modular de auditoría TLS/SSL que analiza servidores web, identifica configuraciones inseguras, clasifica hallazgos por nivel de criticidad y genera reportes orientados al cliente final (no técnico) y al equipo técnico.

---

## Estructura del proyecto

```
hackaton/
├── app.py                    ← Dashboard web (Streamlit) — punto de entrada principal
├── run_audit.py              ← Orquestador CLI para uso desde terminal
├── targets.txt               ← Ejemplo de archivo de targets
├── scanner/
│   ├── 01_validator.py       ← Validación y normalización de entradas
│   ├── 02_tls_scanner.py     ← Motor TLS (sslyze + ssl nativo como fallback)
│   ├── 03_nmap_scanner.py    ← Escaneo de puertos y vulnerabilidades (Nmap NSE)
│   ├── 04_crypto_analyzer.py ← Análisis criptográfico del certificado
│   ├── 05_risk_evaluator.py  ← Motor de riesgo, scoring y hallazgos
│   └── 06_reporter.py        ← Generación de reportes (JSON, CSV, HTML, TXT)
└── reports/                  ← Reportes generados automáticamente (con timestamp)
```

---

## Instalación

```bash
pip install streamlit sslyze cryptography plotly
```

> **Nmap** (opcional pero recomendado para detectar Heartbleed, POODLE, LOGJAM):
> Descargar desde https://nmap.org/download.html e instalar.
> Debe estar disponible en el PATH del sistema.

---

## Uso

### Dashboard web (recomendado)

```bash
streamlit run app.py
```

Abre el navegador en `http://localhost:8501`. Desde la interfaz puedes:

- Ingresar dominios o IPs separados por comas o saltos de línea
- Activar **Modo Rápido** (sin Nmap) para resultados en segundos
- Activar **Escanear todos los puertos** para revisar los 33 puertos del catálogo
- Ver el dashboard interactivo con score, hallazgos y comparativa entre servidores
- Revisar el **Informe de Riesgos** orientado al cliente final (sin jerga técnica)

### CLI desde terminal

```bash
# Un solo objetivo
python run_audit.py google.com

# Múltiples objetivos
python run_audit.py google.com cloudflare.com github.com

# Desde archivo
python run_audit.py --file targets.txt

# Con puerto personalizado
python run_audit.py api.myserver.com:8443

# Omitir Nmap (más rápido)
python run_audit.py google.com --skip-nmap

# Elegir formato de reporte
python run_audit.py google.com --format html json
python run_audit.py google.com --format all --out ./mis_reportes/
```

Formato de `targets.txt`:
```
# Comentarios con #
google.com
cloudflare.com:443
github.com
192.168.1.1:8443
```

---

## Módulos del scanner (uso standalone para tests)

Cada módulo puede ejecutarse de forma independiente desde la terminal:

```bash
# 01 · Validar objetivos
python scanner/01_validator.py google.com bad_target 999.999.999.999

# 02 · Escaneo TLS (protocolos + certificados)
python scanner/02_tls_scanner.py google.com github.com --json

# 03 · Escaneo Nmap NSE (puertos + vulnerabilidades)
python scanner/03_nmap_scanner.py google.com --quick

# 04 · Análisis criptográfico del certificado
python scanner/04_crypto_analyzer.py github.com

# 05 · Evaluación de riesgo (requiere JSON de escaneo previo)
python scanner/05_risk_evaluator.py --input scan_results.json

# 06 · Generación de reporte desde JSON
python scanner/06_reporter.py --input audit_data.json --format html
```

---

## Arquitectura y flujo de datos

```
Entrada (hosts/IPs)
        │
        ▼
01_validator.py
  · Valida formato (dominio / IP / host:puerto)
  · Resuelve DNS
  · Elimina duplicados
        │
        ▼ (paralelo, ThreadPoolExecutor)
┌───────────────────────────────────────┐
│  02_tls_scanner.py                    │
│  · Protocolos TLS/SSL habilitados     │
│  · Cipher suites (débiles/fuertes)    │
│  · Estado del certificado             │
│  Backend: sslyze → ssl nativo         │
├───────────────────────────────────────┤
│  03_nmap_scanner.py  (opcional)       │
│  · Detección Heartbleed / POODLE      │
│  · Grade de ciphers (ssl-enum-ciphers)│
│  · Headers HTTP de seguridad          │
├───────────────────────────────────────┤
│  04_crypto_analyzer.py                │
│  · Fuerza de clave pública (RSA/EC)   │
│  · Algoritmo de firma (SHA1 = débil)  │
│  · SANs, fingerprints, tipo cert DV/EV│
└───────────────────────────────────────┘
        │
        ▼
05_risk_evaluator.py
  · Score de riesgo acumulado (0-100)
  · Nivel global: CRITICAL / HIGH / MEDIUM / LOW / OK
  · Lista de hallazgos ordenados por severidad
  · Comparativa entre servidores
        │
        ▼
06_reporter.py
  · JSON  → datos estructurados
  · CSV   → análisis en Excel / pandas
  · HTML  → reporte visual auto-contenido
  · TXT   → log estructurado
        │
        ▼
app.py (Dashboard Streamlit)
  · Métricas en tiempo real
  · Gauge de riesgo por servidor
  · Informe para cliente final (lenguaje no técnico)
  · Log de ejecución en vivo
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
| Certificado próximo a expirar (<30 días) | HIGH/MEDIUM | 02, 04 |
| Certificado no confiable (autofirmado) | CRITICAL | 02 |
| Clave pública débil (RSA<2048, EC<256) | HIGH | 04 |
| Algoritmo de firma SHA1/MD5 | HIGH | 04 |
| Certificado de larga duración (>825 días) | LOW | 04 |
| Heartbleed (CVE-2014-0160) | CRITICAL | 03 |
| POODLE (CVE-2014-3566) | HIGH | 03 |
| LOGJAM / DH débil (CVE-2015-4000) | HIGH | 03 |
| Grade de cifrado F/E por ssl-enum-ciphers | HIGH | 03 |
| Headers HTTP de seguridad ausentes (HSTS, CSP…) | MEDIUM/LOW | 03 |

---

## Catálogo de puertos auditados

El sistema revisa hasta **33 puertos** agrupados en tres perfiles:

| Perfil | Descripción |
|---|---|
| **LEGACY** | FTP, SMTP, POP3, IMAP, VNC, MySQL, Redis… — detecta TLS obsoleto |
| **STANDARD** | PostgreSQL, Docker, LDAP, SMTP-TLS, K8s… — estándar TLS 1.2 |
| **MODERN** | APIs, servicios cloud, Kafka, Consul… — TLS 1.3 preferido |

---

## Formatos de reporte

| Formato | Descripción |
|---|---|
| **HTML** | Reporte visual auto-contenido, ideal para presentar al cliente |
| **JSON** | Datos estructurados para integración con otras herramientas |
| **CSV** | Vista tabular para análisis en Excel / pandas |
| **TXT** | Log estructurado para pipelines y auditorías automatizadas |

Los reportes se guardan en `reports/` con nombre `tls_audit_YYYYMMDD_HHMMSS.<formato>`.

---

## Dependencias

| Librería | Uso |
|---|---|
| `streamlit` | Dashboard web interactivo |
| `plotly` | Gauge de riesgo y gráficos |
| `sslyze` ≥5.x | Motor principal de análisis TLS |
| `cryptography` ≥42.x | Análisis criptográfico de certificados |
| `nmap` ≥7.x (externo) | Escaneo NSE — Heartbleed, POODLE, LOGJAM |

---

## Integración programática

Para llamar el motor desde otro script Python:

```python
# Llamar el orquestador directamente
import importlib.util, pathlib

ROOT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("risk", ROOT / "scanner/05_risk_evaluator.py")
mod_risk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod_risk)

evaluation = mod_risk.evaluate_host("google.com", 443, tls_result, nmap_result, crypto_result)
print(evaluation["risk_level"], evaluation["risk_score"])
```

O usando `run_audit.py`:

```python
# run_audit expone run_audit() como función pública
from run_audit import run_audit

result = run_audit(
    raw_targets=["google.com", "github.com"],
    formats=["html", "json"],
    skip_nmap=True,
    output_dir="reports/",
)

for ev in result["evaluations"]:
    print(f"{ev['host']} → {ev['risk_level']} ({ev['risk_score']}/100)")

html_path = result["reports"].get("html")
```

---

## Notas de diseño

- **Enfoque defensivo**: el sistema diagnostica configuraciones inseguras, no las explota.
- **Sin dependencias de red externas**: todo el análisis es directo contra el servidor objetivo.
- **Paralelo por defecto**: el dashboard usa `ThreadPoolExecutor` con pre-scan TCP para descartar puertos cerrados antes de lanzar los análisis pesados.
- **Dos audiencias**: los hallazgos técnicos (módulos 02-05) son complementados por el informe de cliente final del dashboard (riesgo + impacto de negocio + qué pedirle al desarrollador).
- **Reproducible**: cada ejecución genera un reporte con timestamp único en `reports/`.

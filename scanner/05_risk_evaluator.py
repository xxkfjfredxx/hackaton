"""
05_risk_evaluator.py
--------------------
Motor de evaluación de riesgo y generación de recomendaciones.

Recibe los resultados de los módulos 02, 03 y 04 y produce:
  - Puntuación de riesgo (0-100, mayor = más crítico)
  - Nivel de severidad: CRITICAL / HIGH / MEDIUM / LOW / INFO
  - Lista de hallazgos clasificados
  - Recomendaciones específicas y accionables
  - Comparativa entre múltiples servidores

Uso standalone:
    # Normalmente es llamado por run_audit.py, pero puede recibir JSON:
    python 05_risk_evaluator.py --input scan_results.json
    python 05_risk_evaluator.py --input scan_results.json --json
"""

import json
import argparse
from typing import Any


# ──────────────────────────────────────────────
#  Definición de reglas de riesgo
# ──────────────────────────────────────────────
# Cada regla: (id, severidad, score, titulo, descripcion, recomendacion)
SEVERITY_SCORES = {
    "CRITICAL": 30,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       5,
    "INFO":      1,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _finding(fid: str, severity: str, title: str,
             description: str, recommendation: str) -> dict:
    return {
        "id":             fid,
        "severity":       severity,
        "score":          SEVERITY_SCORES[severity],
        "title":          title,
        "description":    description,
        "recommendation": recommendation,
    }


# ──────────────────────────────────────────────
#  Evaluadores por módulo
# ──────────────────────────────────────────────
def _eval_tls_protocols(tls_result: dict) -> list[dict]:
    """Evalúa protocolos TLS/SSL del módulo 02."""
    findings = []
    protocols = tls_result.get("protocols", {})

    obsolete_enabled = []
    secure_enabled   = []

    proto_severity = {
        "SSL 2.0": "CRITICAL",
        "SSL 3.0": "CRITICAL",
        "TLS 1.0": "HIGH",
        "TLS 1.1": "MEDIUM",
        "TLS 1.2": None,
        "TLS 1.3": None,
    }

    for proto, data in protocols.items():
        supported = data.get("supported")
        if supported is True:
            sev = proto_severity.get(proto)
            if sev:
                obsolete_enabled.append((proto, sev))
            else:
                secure_enabled.append(proto)

    for proto, sev in obsolete_enabled:
        recommendations = {
            "SSL 2.0": "Deshabilitar inmediatamente SSL 2.0. Está criptográficamente roto desde 1995.",
            "SSL 3.0": "Deshabilitar SSL 3.0. Vulnerable a POODLE (CVE-2014-3566).",
            "TLS 1.0": "Deshabilitar TLS 1.0. Deprecado por RFC 8996. Incompatible con PCI DSS 3.2+.",
            "TLS 1.1": "Deshabilitar TLS 1.1. Deprecado por RFC 8996. No tiene soporte de AEAD.",
        }
        findings.append(_finding(
            fid=f"PROTO_{proto.replace(' ', '_').replace('.', '')}",
            severity=sev,
            title=f"{proto} habilitado (protocolo obsoleto)",
            description=f"El servidor acepta conexiones {proto}, un protocolo criptográfico "
                        f"considerado inseguro u obsoleto según estándares actuales.",
            recommendation=recommendations.get(proto, f"Deshabilitar {proto}"),
        ))

    if not any(p == "TLS 1.3" for p in secure_enabled):
        findings.append(_finding(
            fid="PROTO_TLS13_MISSING",
            severity="MEDIUM",
            title="TLS 1.3 no habilitado",
            description="El servidor no ofrece TLS 1.3, el protocolo más moderno y seguro disponible.",
            recommendation="Habilitar TLS 1.3. Ofrece mejor rendimiento (0-RTT) y seguridad mejorada.",
        ))

    if not secure_enabled:
        findings.append(_finding(
            fid="PROTO_NO_SECURE",
            severity="CRITICAL",
            title="Sin protocolos seguros habilitados",
            description="El servidor no ofrece ninguna versión moderna de TLS (1.2 o 1.3).",
            recommendation="Habilitar TLS 1.2 y TLS 1.3 inmediatamente.",
        ))

    # Evaluar cipher suites débiles
    for proto, data in protocols.items():
        weak = data.get("weak_ciphers", [])
        if weak:
            findings.append(_finding(
                fid=f"CIPHER_WEAK_{proto.replace(' ', '_').replace('.', '')}",
                severity="HIGH",
                title=f"Cipher suites débiles en {proto}",
                description=f"Se detectaron {len(weak)} cipher suite(s) con algoritmos inseguros: "
                            f"{', '.join(weak[:3])}{'...' if len(weak) > 3 else ''}",
                recommendation="Deshabilitar cipher suites con RC4, 3DES, DES, NULL, EXPORT o MD5. "
                               "Usar solo cipher suites AEAD (AES-GCM, ChaCha20-Poly1305).",
            ))

    return findings


def _eval_certificate(cert_data: list[dict] | dict) -> list[dict]:
    """Evalúa el estado del certificado del módulo 02 o 04."""
    findings = []

    # El módulo 02 devuelve lista, el 04 devuelve dict directo
    certs = cert_data if isinstance(cert_data, list) else [cert_data]

    for cert in certs:
        if not cert or "error" in cert:
            findings.append(_finding(
                fid="CERT_UNAVAILABLE",
                severity="HIGH",
                title="Certificado no disponible o inaccesible",
                description="No se pudo obtener el certificado del servidor.",
                recommendation="Verificar que el servidor tiene un certificado válido instalado.",
            ))
            continue

        # Estado de confianza
        if cert.get("trusted") is False:
            findings.append(_finding(
                fid="CERT_UNTRUSTED",
                severity="CRITICAL",
                title="Certificado no confiable",
                description="El certificado no es de confianza (autofirmado o CA no reconocida).",
                recommendation="Obtener un certificado de una CA reconocida (Let's Encrypt, DigiCert, etc.)",
            ))

        # Expirado
        if cert.get("expired"):
            findings.append(_finding(
                fid="CERT_EXPIRED",
                severity="CRITICAL",
                title="Certificado EXPIRADO",
                description=f"El certificado expiró. Los clientes rechazarán la conexión.",
                recommendation="Renovar el certificado inmediatamente.",
            ))
        else:
            days = cert.get("days_remaining")
            if days is not None:
                if days < 7:
                    sev, label = "CRITICAL", "menos de 7 días"
                elif days < 30:
                    sev, label = "HIGH", "menos de 30 días"
                elif days < 90:
                    sev, label = "MEDIUM", "menos de 90 días"
                else:
                    sev = label = None

                if sev:
                    findings.append(_finding(
                        fid="CERT_EXPIRING_SOON",
                        severity=sev,
                        title=f"Certificado próximo a expirar ({days} días)",
                        description=f"El certificado expirará en {days} días ({label}).",
                        recommendation="Renovar el certificado antes de que expire. "
                                       "Considerar automatización con Let's Encrypt / ACME.",
                    ))

    return findings


def _eval_crypto_analysis(crypto_result: dict) -> list[dict]:
    """Evalúa los resultados del módulo 04 (cryptography lib)."""
    findings = []

    if "error" in crypto_result:
        return findings  # sin datos = sin hallazgos del módulo

    # Clave pública débil
    pk = crypto_result.get("public_key", {})
    if pk.get("weak"):
        findings.append(_finding(
            fid="CRYPTO_WEAK_KEY",
            severity="HIGH",
            title=f"Clave pública débil ({pk.get('type')} {pk.get('bits', '?')} bits)",
            description=f"La clave pública {pk.get('type')} de {pk.get('bits', '?')} bits "
                        "no cumple los estándares mínimos actuales.",
            recommendation=pk.get("recommendation",
                                  "Renovar certificado con clave RSA ≥2048 o ECDSA ≥P-256."),
        ))

    # Algoritmo de firma débil
    sig = crypto_result.get("signature", {})
    if sig.get("weak"):
        findings.append(_finding(
            fid="CRYPTO_WEAK_SIGNATURE",
            severity="HIGH",
            title=f"Algoritmo de firma débil ({sig.get('algorithm')})",
            description=f"El certificado usa {sig.get('algorithm')} como algoritmo de firma, "
                        "considerado criptográficamente inseguro.",
            recommendation="Renovar el certificado con SHA-256 o SHA-384 como algoritmo de firma.",
        ))

    # Duración excesiva del certificado
    val = crypto_result.get("validity", {})
    if val.get("long_lived"):
        findings.append(_finding(
            fid="CERT_LONG_LIVED",
            severity="LOW",
            title="Certificado de larga duración (>825 días)",
            description=f"El certificado tiene una validez total de {val.get('total_days')} días, "
                        "superando el límite de 825 días establecido por CA/Browser Forum.",
            recommendation="Usar certificados de 90 días (Let's Encrypt) o máximo 1 año (398 días).",
        ))

    # Tipo de certificado
    cert_type = crypto_result.get("cert_type", "")
    if "DV" in cert_type:
        findings.append(_finding(
            fid="CERT_TYPE_DV",
            severity="INFO",
            title="Certificado DV (Domain Validation)",
            description="El certificado solo valida el dominio, no la identidad de la organización.",
            recommendation="Para servicios transaccionales o financieros, considerar certificado OV o EV.",
        ))

    return findings


def _eval_nmap_results(nmap_result: dict) -> list[dict]:
    """Evalúa los resultados del módulo 03 (nmap)."""
    findings = []

    if "error" in nmap_result:
        findings.append(_finding(
            fid="NMAP_UNAVAILABLE",
            severity="INFO",
            title="Nmap no disponible — análisis NSE omitido",
            description=nmap_result.get("error", "Nmap no ejecutado"),
            recommendation="Instalar Nmap para análisis de vulnerabilidades conocidas (Heartbleed, POODLE, etc.)",
        ))
        return findings

    # Vulnerabilidades detectadas por NSE
    for vuln in nmap_result.get("vulnerabilities", []):
        findings.append(_finding(
            fid=f"NSE_{vuln.get('id', 'UNKNOWN').replace('-', '_')}",
            severity=vuln.get("severity", "HIGH"),
            title=f"Vulnerabilidad: {vuln.get('name')} ({vuln.get('id')})",
            description=vuln.get("desc", "Vulnerabilidad detectada por Nmap NSE"),
            recommendation=f"Aplicar parche o actualización que corrija {vuln.get('id')}. "
                           "Revisar boletín de seguridad del proveedor.",
        ))

    # Cifrados con grade bajo (ssl-enum-ciphers)
    for proto, data in nmap_result.get("tls_ciphers_by_protocol", {}).items():
        grade = data.get("grade", "")
        if grade in ("F", "E", "D"):
            findings.append(_finding(
                fid=f"NMAP_CIPHER_GRADE_{proto.replace(' ', '_')}_{grade}",
                severity="HIGH" if grade == "F" else "MEDIUM",
                title=f"Grade de cifrado {grade} en {proto}",
                description=f"Nmap ssl-enum-ciphers asignó grade '{grade}' a {proto}, "
                             "indicando cipher suites débiles o inseguros.",
                recommendation="Revisar y deshabilitar cipher suites con grade F o E.",
            ))

    # Headers de seguridad HTTP faltantes
    present_headers = set(nmap_result.get("security_headers", {}).keys())
    recommended_headers = {
        "Strict-Transport-Security": (
            "HIGH",
            "Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        ),
        "X-Frame-Options": (
            "MEDIUM",
            "Agregar: X-Frame-Options: DENY o SAMEORIGIN para prevenir clickjacking",
        ),
        "X-Content-Type-Options": (
            "LOW",
            "Agregar: X-Content-Type-Options: nosniff",
        ),
        "Content-Security-Policy": (
            "MEDIUM",
            "Implementar Content-Security-Policy para prevenir XSS",
        ),
    }
    for header, (sev, rec) in recommended_headers.items():
        if header not in present_headers:
            findings.append(_finding(
                fid=f"HEADER_MISSING_{header.replace('-', '_').upper()}",
                severity=sev,
                title=f"Header de seguridad ausente: {header}",
                description=f"El servidor no envía el header HTTP '{header}', "
                             "lo cual puede exponer a vulnerabilidades en el navegador.",
                recommendation=rec,
            ))

    return findings


# ──────────────────────────────────────────────
#  Evaluación consolidada
# ──────────────────────────────────────────────
def evaluate_host(
    host: str,
    port: int,
    tls_result: dict | None = None,
    nmap_result: dict | None = None,
    crypto_result: dict | None = None,
) -> dict[str, Any]:
    """
    Evalúa todos los hallazgos de un host y produce el informe de riesgo.
    """
    findings: list[dict] = []

    if tls_result:
        findings += _eval_tls_protocols(tls_result)
        certs = tls_result.get("certificates", [])
        if certs:
            findings += _eval_certificate(certs)

    if nmap_result:
        findings += _eval_nmap_results(nmap_result)

    if crypto_result:
        findings += _eval_crypto_analysis(crypto_result)
        # También certificado del módulo 04
        if "validity" in crypto_result:
            findings += _eval_certificate(crypto_result)

    # Deduplicar por ID
    seen_ids: set[str] = set()
    unique_findings: list[dict] = []
    for f in findings:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            unique_findings.append(f)

    # Ordenar por severidad
    findings_sorted = sorted(
        unique_findings,
        key=lambda f: SEVERITY_ORDER.index(f["severity"])
    )

    # Calcular score total (0-100)
    raw_score = sum(f["score"] for f in findings_sorted)
    score = min(100, raw_score)

    # Nivel de riesgo global
    if score >= 60 or any(f["severity"] == "CRITICAL" for f in findings_sorted):
        risk_level = "CRITICAL"
    elif score >= 40 or any(f["severity"] == "HIGH" for f in findings_sorted):
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    elif score >= 5:
        risk_level = "LOW"
    else:
        risk_level = "OK"

    # Conteo por severidad
    severity_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings_sorted:
        severity_counts[f["severity"]] += 1

    return {
        "host":            host,
        "port":            port,
        "risk_score":      score,
        "risk_level":      risk_level,
        "severity_counts": severity_counts,
        "total_findings":  len(findings_sorted),
        "findings":        findings_sorted,
    }


def compare_hosts(evaluations: list[dict]) -> dict[str, Any]:
    """Genera una vista comparativa entre múltiples servidores evaluados."""
    if not evaluations:
        return {}

    sorted_by_risk = sorted(evaluations, key=lambda e: e["risk_score"], reverse=True)

    return {
        "total_hosts": len(evaluations),
        "ranking": [
            {
                "rank": i + 1,
                "host": e["host"],
                "port": e["port"],
                "risk_score": e["risk_score"],
                "risk_level": e["risk_level"],
                "critical": e["severity_counts"].get("CRITICAL", 0),
                "high":     e["severity_counts"].get("HIGH", 0),
                "medium":   e["severity_counts"].get("MEDIUM", 0),
            }
            for i, e in enumerate(sorted_by_risk)
        ],
        "most_critical": sorted_by_risk[0]["host"] if sorted_by_risk else None,
        "safest":        sorted_by_risk[-1]["host"] if sorted_by_risk else None,
    }


# ──────────────────────────────────────────────
#  CLI standalone
# ──────────────────────────────────────────────
RISK_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "OK":       "✅",
    "INFO":     "ℹ️ ",
}


def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Motor de evaluación de riesgo — Módulo 05"
    )
    parser.add_argument('--input', '-i', required=True,
                        help='JSON con resultados de escaneo (producido por run_audit.py)')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    with open(args.input, 'r', encoding='utf-8') as f:
        data = json.load(f)

    evaluations = []
    for entry in data if isinstance(data, list) else [data]:
        ev = evaluate_host(
            host=entry.get("host", "?"),
            port=entry.get("port", 443),
            tls_result=entry.get("tls"),
            nmap_result=entry.get("nmap"),
            crypto_result=entry.get("crypto"),
        )
        evaluations.append(ev)

    comparison = compare_hosts(evaluations)

    if args.json:
        print(json.dumps({"evaluations": evaluations, "comparison": comparison},
                         indent=2, ensure_ascii=False))
        return

    print(f"\n{'='*60}")
    print("  REPORTE DE EVALUACIÓN DE RIESGO TLS")
    print(f"{'='*60}")

    for ev in evaluations:
        icon = RISK_ICONS.get(ev["risk_level"], "❓")
        print(f"\n  {icon} {ev['host']}:{ev['port']}")
        print(f"     Score de riesgo: {ev['risk_score']}/100  |  Nivel: {ev['risk_level']}")
        print(f"     Hallazgos: {ev['total_findings']} "
              f"(C:{ev['severity_counts']['CRITICAL']} "
              f"H:{ev['severity_counts']['HIGH']} "
              f"M:{ev['severity_counts']['MEDIUM']} "
              f"L:{ev['severity_counts']['LOW']})")

        for f in ev["findings"]:
            sev_icon = RISK_ICONS.get(f["severity"], "?")
            print(f"\n     {sev_icon} [{f['severity']}] {f['title']}")
            print(f"        Descripción   : {f['description']}")
            print(f"        Recomendación : {f['recommendation']}")

    if comparison.get("ranking"):
        print(f"\n{'='*60}")
        print("  RANKING COMPARATIVO DE EXPOSICIÓN")
        print(f"{'='*60}")
        for row in comparison["ranking"]:
            icon = RISK_ICONS.get(row["risk_level"], "")
            print(f"  #{row['rank']}  {icon} {row['host']}:{row['port']}"
                  f"  Score: {row['risk_score']}/100  [{row['risk_level']}]")


if __name__ == '__main__':
    _cli()

"""
TLS/SSL Auditor Dashboard — Streamlit UI
Run: streamlit run dashboard.py
"""
from tlsauditor import (
    score_cipher_suite,
    is_valid_target,
    SCAN_COMMANDS,
    PROTOCOL_ATTRS,
    WEAK_CIPHER_KEYWORDS,
    ALL_AUDIT_PORTS,
)
from sslyze import (
    Scanner,
    ScanCommand,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerScanStatusEnum,
    ScanCommandAttemptStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
import html
import csv
import io
import json
import datetime
import warnings
import sys
import os

import streamlit as st
import pandas as pd

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


# Make tlsauditor importable from the same folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="TLS/SSL Auditor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* ── Global ── */
  section[data-testid="stSidebar"] { background: #0d1117 !important; }
  .main .block-container { padding-top: 1.5rem; }

  /* ── Section header ── */
  .sec-header {
    font-size: 1.25rem; font-weight: 700; color: #e6edf3;
    border-bottom: 1px solid #21262d;
    padding-bottom: 8px; margin: 20px 0 14px;
    display: flex; align-items: center; gap: 8px;
  }

  /* ── Metric cards ── */
  .metric-grid { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 18px; }
  .metric-card {
    flex: 1; min-width: 110px;
    background: #161b22; border: 1px solid #21262d;
    border-radius: 10px; padding: 18px 12px; text-align: center;
  }
  .metric-val { font-size: 2.4rem; font-weight: 800; line-height: 1; }
  .metric-lbl { font-size: 0.72rem; letter-spacing: 1px; color: #8b949e; margin-top: 5px; }

  /* ── Severity cards ── */
  .sev-card {
    border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;
    border-left: 5px solid;
  }
  .sev-CRITICO { border-color: #FF4B4B; background: rgba(255,75,75,0.08); }
  .sev-ALTO    { border-color: #FF8C00; background: rgba(255,140,0,0.08); }
  .sev-MEDIO   { border-color: #FFD700; background: rgba(255,215,0,0.06); }
  .sev-BAJO    { border-color: #4A90D9; background: rgba(74,144,217,0.06); }

  /* ── Severity badge ── */
  .sev-badge {
    display: inline-block; font-size: 10px; font-weight: 800;
    letter-spacing: 0.8px; padding: 2px 8px; border-radius: 4px;
    margin-right: 8px; vertical-align: middle;
  }
  .badge-CRITICO { background: #FF4B4B; color: #fff; }
  .badge-ALTO    { background: #FF8C00; color: #fff; }
  .badge-MEDIO   { background: #FFD700; color: #111; }
  .badge-BAJO    { background: #4A90D9; color: #fff; }

  /* ── Score pill ── */
  .score-pill {
    display: inline-block; font-size: 11px; font-weight: 700;
    padding: 2px 9px; border-radius: 10px;
  }
  .pill-FUERTE    { background: #00C853; color: #000; }
  .pill-BUENO     { background: #64DD17; color: #000; }
  .pill-ACEPTABLE { background: #FFD740; color: #111; }
  .pill-DEBIL     { background: #FF6D00; color: #fff; }
  .pill-CRITICO   { background: #DD2C00; color: #fff; }

  /* ── Protocol status ── */
  .proto-row { margin: 4px 0; }
  .proto-yes { color: #3fb950; font-weight: 600; }
  .proto-no  { color: #484f58; }
  .proto-err { color: #f85149; }

  /* ── Cert field ── */
  .cert-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .cert-table td { padding: 5px 8px; border-bottom: 1px solid #21262d; vertical-align: top; }
  .cert-table td:first-child { color: #8b949e; white-space: nowrap; width: 38%; }
  .cert-ok   { color: #3fb950; font-weight: 600; }
  .cert-warn { color: #d29922; font-weight: 600; }
  .cert-bad  { color: #f85149; font-weight: 600; }

  /* ── Discrepancy row ── */
  .disc { color: #f0883e; font-weight: 700; font-size: 0.75rem; }
</style>
""", unsafe_allow_html=True)


# ── Findings helper (returns list, no printing) ────────────────────────────────
def get_findings(supported_protos, weak_ciphers_by_proto,
                 cert_trusted, cert_expired, cert_days,
                 has_tls12, has_tls13,
                 cert_key_type=None, cert_key_size=None):
    """Return list of (priority, severity, title, risk, action)."""
    findings = []
    OBSOLETE = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
    found_obsolete = [p for p in supported_protos if p in OBSOLETE]

    if "SSL 2.0" in found_obsolete:
        findings.append((1, "CRÍTICO", "SSL 2.0 Habilitado",
                         "SSL 2.0 fue roto hace décadas. Los atacantes pueden leer "
                         "el tráfico en texto plano.",
                         "Deshabilitar SSL 2.0 en la configuración del servidor de inmediato."))

    if "SSL 3.0" in found_obsolete:
        findings.append((1, "CRÍTICO", "SSL 3.0 Habilitado — vulnerable a POODLE",
                         "SSL 3.0 es explotable mediante POODLE (CVE-2014-3566). "
                         "Un atacante puede descifrar cookies de sesión.",
                         "Deshabilitar SSL 3.0 en el servidor."))

    if "TLS 1.0" in found_obsolete or "TLS 1.1" in found_obsolete:
        obs = ", ".join(
            p for p in ["TLS 1.0", "TLS 1.1"] if p in found_obsolete)
        findings.append((2, "ALTO", f"Protocolo(s) Obsoleto(s): {obs}",
                         f"{obs} fue retirado oficialmente en 2021 (RFC 8996). "
                         "Mantenerlo expone a ataques de degradación de protocolo.",
                         f"Deshabilitar {obs}. Solo habilitar TLS 1.2 y TLS 1.3."))

    if not has_tls13:
        findings.append((3, "MEDIO", "TLS 1.3 No Habilitado",
                         "El servidor no ofrece TLS 1.3, la versión más rápida y segura.",
                         "Habilitar TLS 1.3 — mejora velocidad y seguridad simultáneamente."))

    if not has_tls12 and not has_tls13:
        findings.append((1, "CRÍTICO", "Sin Versión TLS Segura Disponible",
                         "El servidor no ofrece ninguna versión segura de TLS. "
                         "Todo el tráfico puede ser interceptado.",
                         "Configurar TLS 1.2 y TLS 1.3 en el servidor urgentemente."))

    null_protos = [
        p for p, c in weak_ciphers_by_proto.items()
        if any("NULL" in x.upper() or "ANON" in x.upper() for x in c)
    ]
    if null_protos:
        findings.append((1, "CRÍTICO", "Cipher Suites NULL / Anónimos Detectados",
                         f"Acepta conexiones SIN cifrado (NULL) o sin autenticación (ANON) "
                         f"en: {', '.join(null_protos)}.",
                         "Eliminar todos los cipher suites NULL y ANON de la configuración TLS."))

    export_protos = [
        p for p, c in weak_ciphers_by_proto.items()
        if any("EXPORT" in x.upper() for x in c)
    ]
    if export_protos:
        findings.append((1, "CRÍTICO", "Cipher Suites EXPORT Detectados (riesgo FREAK)",
                         f"Cipher suites 40-bit encontrados en: {', '.join(export_protos)}. "
                         "Vulnerables al ataque FREAK (CVE-2015-0204).",
                         "Eliminar todos los cipher suites EXPORT del servidor."))

    weak_protos = [
        p for p, c in weak_ciphers_by_proto.items()
        if any(kw in x.upper() for x in c for kw in ["RC4", "DES", "3DES", "MD5"])
    ]
    if weak_protos:
        findings.append((2, "ALTO", "Algoritmos de Cifrado Débiles Detectados",
                         f"RC4, DES, 3DES o MD5 encontrados en: {', '.join(weak_protos)}.",
                         "Usar solo AES-GCM o ChaCha20-Poly1305 (algoritmos AEAD modernos)."))

    if cert_expired:
        findings.append((1, "CRÍTICO", "Certificado VENCIDO",
                         "El certificado expiró. Los navegadores muestran error grave.",
                         "Renovar el certificado de inmediato."))
    elif cert_days is not None and cert_days < 30:
        sev = "CRÍTICO" if cert_days < 7 else "ALTO"
        pri = 1 if cert_days < 7 else 2
        findings.append((pri, sev, f"Certificado Vence en {cert_days} Día(s)",
                         f"El certificado expirará en {cert_days} día(s). "
                         "Los usuarios verán errores si no se renueva a tiempo.",
                         "Renovar antes de que expire. Considerar Let's Encrypt para "
                         "renovación automática."))

    if not cert_trusted:
        findings.append((1, "CRÍTICO", "Certificado No Confiable (Autofirmado)",
                         "No emitido por una CA reconocida. Los navegadores muestran "
                         "advertencias que alejan a los usuarios.",
                         "Obtener certificado de una CA reconocida. Let's Encrypt es gratuito."))

    # ── Tamaño de clave RSA/DSA ──────────────────────────────────────────
    if cert_key_size is not None and cert_key_type in ("RSAPublicKey", "DSAPublicKey"):
        algo = "RSA" if cert_key_type == "RSAPublicKey" else "DSA"
        if cert_key_size < 2048:
            findings.append((
                1, "CRÍTICO",
                f"Clave {algo} Insuficiente — {cert_key_size} bits",
                f"Una clave {algo} de {cert_key_size} bits puede romperse con hardware moderno. "
                "NIST retiró {algo}-1024 en 2010 y ya no se considera seguro.",
                f"Reemplazar el certificado con clave {algo}-2048 mínimo, "
                "o mejor migrar a ECDSA P-256/P-384 (más rápido y seguro).",
            ))
        elif cert_key_size < 3072:
            findings.append((
                3, "MEDIO",
                f"Clave {algo} de {cert_key_size} bits — Considerar Actualización",
                f"Las recomendaciones actuales (NIST SP 800-57) sugieren {algo}-3072+ "
                "para certificados de larga duración. {algo}-2048 sigue siendo aceptable hoy.",
                f"Planificar migración a {algo}-3072 o, idealmente, a ECDSA P-256 "
                "que ofrece seguridad equivalente a RSA-3072 con clave 4x más pequeña.",
            ))

    findings.sort(key=lambda x: x[0])
    return findings


# ── Core scan function ─────────────────────────────────────────────────────────
def scan_servers(raw_targets: list[str], all_ports: bool = False) -> list[dict]:
    """Run sslyze scans and return a list of structured result dicts."""
    scan_requests = []

    for target in raw_targets:
        target = target.strip()
        if not target:
            continue

        if ":" in target:
            hostname, port_str = target.rsplit(":", 1)
            try:
                ports = [int(port_str)]
            except ValueError:
                continue
        else:
            hostname = target
            ports = ALL_AUDIT_PORTS if all_ports else [443]

        if not is_valid_target(hostname):
            continue

        for port in ports:
            try:
                scan_requests.append(
                    ServerScanRequest(
                        server_location=ServerNetworkLocation(
                            hostname=hostname, port=port),
                        scan_commands=SCAN_COMMANDS,
                    )
                )
            except ServerHostnameCouldNotBeResolved:
                pass
            except Exception:
                pass

    if not scan_requests:
        return []

    scanner = Scanner()
    scanner.queue_scans(scan_requests)

    results = []
    for result in scanner.get_results():
        loc = result.server_location
        data = {
            "hostname": loc.hostname,
            "port": loc.port,
            "key": f"{loc.hostname}:{loc.port}",
            "status": "ok",
            "error": None,
            "protocols": {},
            "certificate": None,
            "recommendations": [],
        }

        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            data["status"] = "error"
            data["error"] = str(result.connectivity_error_trace)
            results.append(data)
            continue

        scan = result.scan_result
        supported_protos: list[str] = []
        weak_ciphers_by_proto: dict[str, list[str]] = {}
        has_tls12 = has_tls13 = False

        for proto_name, proto_attr in PROTOCOL_ATTRS:
            attempt = getattr(scan, proto_attr)
            proto_data = {"supported": None,
                          "cipher_suites": [], "error": None}

            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                accepted = attempt.result.accepted_cipher_suites
                if accepted:
                    proto_data["supported"] = True
                    supported_protos.append(proto_name)
                    for s in accepted:
                        name = s.cipher_suite.name
                        score, label, components = score_cipher_suite(name)
                        is_weak = any(kw in name.upper()
                                      for kw in WEAK_CIPHER_KEYWORDS)
                        proto_data["cipher_suites"].append({
                            "name": name,
                            "score": score,
                            "label": label,
                            "components": components,
                            "is_weak": is_weak,
                        })
                    weak = [s["name"]
                            for s in proto_data["cipher_suites"] if s["is_weak"]]
                    if weak:
                        weak_ciphers_by_proto[proto_name] = weak
                    if proto_name == "TLS 1.2":
                        has_tls12 = True
                    if proto_name == "TLS 1.3":
                        has_tls13 = True
                else:
                    proto_data["supported"] = False
            elif attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                proto_data["error"] = str(attempt.error_reason)

            data["protocols"][proto_name] = proto_data

        # ── Certificate ──────────────────────────────────────────────────
        cert_attempt = scan.certificate_info
        cert_trusted = False
        cert_expired = False
        cert_days = None

        if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            deployments = cert_attempt.result.certificate_deployments
            if deployments:
                dep = deployments[0]
                leaf = dep.received_certificate_chain[0]
                now = datetime.datetime.now(datetime.timezone.utc)
                not_before = getattr(
                    leaf, "not_valid_before_utc", leaf.not_valid_before)
                not_after = getattr(
                    leaf, "not_valid_after_utc", leaf.not_valid_after)

                if not_after:
                    na = (not_after if not_after.tzinfo
                          else not_after.replace(tzinfo=datetime.timezone.utc))
                    days_remaining = (na - now).days
                    is_expired = days_remaining <= 0
                else:
                    days_remaining = None
                    is_expired = False

                cert_trusted = dep.verified_certificate_chain is not None
                cert_expired = is_expired
                cert_days = days_remaining

                data["certificate"] = {
                    "subject": leaf.subject.rfc4514_string(),
                    "issuer": leaf.issuer.rfc4514_string(),
                    "key_type": leaf.public_key().__class__.__name__,
                    "key_size": getattr(leaf.public_key(), "key_size", None),
                    "serial": str(leaf.serial_number),
                    "valid_from": str(not_before),
                    "valid_until": str(not_after),
                    "days_remaining": days_remaining,
                    "expired": is_expired,
                    "trusted": cert_trusted,
                }

        cert_key_size = data["certificate"]["key_size"] if data.get("certificate") else None
        cert_key_type_val = data["certificate"]["key_type"] if data.get("certificate") else None
        data["recommendations"] = get_findings(
            supported_protos, weak_ciphers_by_proto,
            cert_trusted, cert_expired, cert_days,
            has_tls12, has_tls13,
            cert_key_type=cert_key_type_val,
            cert_key_size=cert_key_size,
        )
        results.append(data)

    return results


# ── Export helpers ────────────────────────────────────────────────────────────
def _build_json(results: list) -> str:
    """Serializa los resultados completos a JSON con indentación."""
    timestamp = datetime.datetime.now().isoformat()
    payload = {
        "generated_at": timestamp,
        "total_servers": len(results),
        "servers": [
            {
                "host": r["hostname"],
                "port": r["port"],
                "status": r["status"],
                "error": r.get("error"),
                "protocols": {
                    proto: {
                        "supported": data.get("supported"),
                        "cipher_suites": [
                            {
                                "name": s["name"],
                                "score": s["score"],
                                "level": s["label"],
                                "is_weak": s["is_weak"],
                            }
                            for s in data.get("cipher_suites", [])
                        ],
                    }
                    for proto, data in r.get("protocols", {}).items()
                },
                "certificate": r.get("certificate"),
                "findings": [
                    {
                        "priority": f[0],
                        "severity": f[1],
                        "title": f[2],
                        "risk": f[3],
                        "action": f[4],
                    }
                    for f in r.get("recommendations", [])
                ],
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def _build_csv(results: list) -> str:
    """Genera un CSV plano: una fila por hallazgo por servidor."""
    output = io.StringIO()
    fieldnames = [
        "servidor", "puerto", "estado",
        "protocolo", "cipher_suite", "score", "nivel", "es_debil",
        "cert_sujeto", "cert_emisor", "cert_dias_restantes",
        "cert_expirado", "cert_confiable",
        "hallazgo_severidad", "hallazgo_titulo", "hallazgo_riesgo", "hallazgo_accion",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for r in results:
        base = {
            "servidor": r["hostname"],
            "puerto": r["port"],
            "estado": r["status"],
        }
        cert = r.get("certificate") or {}
        cert_fields = {
            "cert_sujeto": cert.get("subject", ""),
            "cert_emisor": cert.get("issuer", ""),
            "cert_dias_restantes": cert.get("days_remaining", ""),
            "cert_expirado": cert.get("expired", ""),
            "cert_confiable": cert.get("trusted", ""),
        }

        # Una fila por cipher suite
        for proto, data in r.get("protocols", {}).items():
            for s in data.get("cipher_suites", []):
                writer.writerow({
                    **base, **cert_fields,
                    "protocolo": proto,
                    "cipher_suite": s["name"],
                    "score": s["score"],
                    "nivel": s["label"],
                    "es_debil": s["is_weak"],
                })

        # Filas de hallazgos
        for f in r.get("recommendations", []):
            writer.writerow({
                **base, **cert_fields,
                "hallazgo_severidad": f[1],
                "hallazgo_titulo": f[2],
                "hallazgo_riesgo": f[3],
                "hallazgo_accion": f[4],
            })

        # Si no hay ni ciphers ni hallazgos, escribir al menos una fila con los datos base
        if not any(data.get("cipher_suites") for data in r.get("protocols", {}).values()) \
                and not r.get("recommendations"):
            writer.writerow({**base, **cert_fields})

    return output.getvalue()


def _build_html(results: list) -> str:
    """Genera un reporte HTML auto-contenido con diseño profesional."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ok = [r for r in results if r["status"] == "ok"]
    err = [r for r in results if r["status"] == "error"]

    SEV_COLOR = {"CRÍTICO": "#ef4444", "ALTO": "#f97316", "MEDIO": "#eab308", "BAJO": "#3b82f6"}
    SEV_BG    = {"CRÍTICO": "#fef2f2", "ALTO": "#fff7ed", "MEDIO": "#fefce8", "BAJO": "#eff6ff"}
    LEVEL_COLOR = {
        "FUERTE": "#16a34a", "BUENO": "#65a30d",
        "ACEPTABLE": "#ca8a04", "DÉBIL": "#ea580c", "CRÍTICO": "#dc2626",
    }

    def sev_badge(sev: str) -> str:
        c = SEV_COLOR.get(sev, "#6b7280")
        return (f'<span style="background:{c};color:#fff;font-size:10px;font-weight:800;'
                f'padding:2px 9px;border-radius:4px;letter-spacing:.6px">{sev}</span>')

    def level_pill(label: str, score: float) -> str:
        c = LEVEL_COLOR.get(label, "#6b7280")
        return (f'<span style="background:{c};color:#fff;font-size:10px;font-weight:700;'
                f'padding:2px 8px;border-radius:10px">{score:.1f} — {label}</span>')

    def proto_row(name: str, data: dict) -> str:
        sup = data.get("supported")
        n   = len(data.get("cipher_suites", []))
        if sup is True:
            icon, txt, c = "✅", f"SOPORTADO ({n} suites)", "#16a34a"
        elif sup is False:
            icon, txt, c = "—", "No soportado", "#9ca3af"
        else:
            icon, txt, c = "⚠", "Error de escaneo", "#ef4444"
        return (f'<tr><td style="padding:6px 12px;color:#374151;font-weight:600">{name}</td>'
                f'<td style="padding:6px 12px;color:{c}">{icon} {txt}</td></tr>')

    def cipher_rows(suites: list) -> str:
        rows = ""
        for s in suites:
            w_style = 'color:#dc2626;font-weight:700' if s["is_weak"] else 'color:#6b7280'
            bar_w   = int(s["score"] / 10 * 100)
            bar_c   = LEVEL_COLOR.get(s["label"], "#6b7280")
            rows += f"""
            <tr style="border-bottom:1px solid #f3f4f6">
              <td style="padding:6px 10px;font-size:12px;font-family:monospace">{s['name']}</td>
              <td style="padding:6px 10px">{level_pill(s['label'], s['score'])}</td>
              <td style="padding:6px 10px;width:120px">
                <div style="background:#e5e7eb;border-radius:4px;height:6px">
                  <div style="background:{bar_c};width:{bar_w}%;height:6px;border-radius:4px"></div>
                </div>
              </td>
              <td style="padding:6px 10px;font-size:11px;{w_style}">
                {'⚠ DÉBIL' if s['is_weak'] else ''}
              </td>
            </tr>"""
        return rows

    def cert_block(cert: dict | None) -> str:
        if not cert:
            return '<p style="color:#9ca3af">No se pudo obtener el certificado.</p>'
        days = cert.get("days_remaining")
        if cert.get("expired"):
            d_str, d_c = f"EXPIRADO hace {abs(days)} días", "#dc2626"
        elif days is not None and days < 7:
            d_str, d_c = f"Vence en {days} días — URGENTE 🚨", "#dc2626"
        elif days is not None and days < 30:
            d_str, d_c = f"Vence en {days} días — Próximo ⚠️", "#f97316"
        else:
            d_str, d_c = f"Vence en {days} días — OK ✅", "#16a34a"
        trusted_str = ('✅ Confiable' if cert.get("trusted")
                       else '❌ No confiable (autofirmado)')
        trusted_c = "#16a34a" if cert.get("trusted") else "#dc2626"

        key_size = cert.get("key_size")
        key_type_raw = cert.get("key_type", "")
        if key_size and key_type_raw in ("RSAPublicKey", "DSAPublicKey"):
            algo = "RSA" if "RSA" in key_type_raw else "DSA"
            if key_size < 2048:
                ks_str, ks_c = f"{algo} {key_size} bits — 🔴 INSUFICIENTE", "#dc2626"
            elif key_size < 3072:
                ks_str, ks_c = f"{algo} {key_size} bits — ⚠️ Aceptable", "#f97316"
            else:
                ks_str, ks_c = f"{algo} {key_size} bits — ✅ Fuerte", "#16a34a"
        else:
            ks_str = key_type_raw or "N/A"
            ks_c = "#374151"

        rows = [
            ("Sujeto",              cert.get("subject", "N/A"),  "#374151"),
            ("Emisor",              cert.get("issuer",  "N/A"),   "#374151"),
            ("Tipo / Tamaño clave", ks_str,                       ks_c),
            ("Válido desde",        cert.get("valid_from","N/A"),  "#374151"),
            ("Válido hasta",        cert.get("valid_until","N/A"), "#374151"),
            ("Vencimiento",          d_str,                        d_c),
            ("Confiabilidad",        trusted_str,                  trusted_c),
        ]
        html_rows = "".join(
            f'<tr><td style="padding:5px 10px;color:#6b7280;white-space:nowrap;'
            f'border-bottom:1px solid #f3f4f6;font-size:12px">{k}</td>'
            f'<td style="padding:5px 10px;color:{c};font-size:12px;'
            f'border-bottom:1px solid #f3f4f6">{v}</td></tr>'
            for k, v, c in rows
        )
        return f'<table style="width:100%;border-collapse:collapse">{html_rows}</table>'

    def finding_cards(findings: list) -> str:
        if not findings:
            return ('<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;'
                    'padding:14px 18px;color:#15803d;font-weight:600">✅ Sin hallazgos — '
                    'configuración correcta</div>')
        cards = ""
        for f in findings:
            sev  = f[1]; title = f[2]; risk = f[3]; action = f[4]
            bg   = SEV_BG.get(sev, "#f9fafb")
            bc   = SEV_COLOR.get(sev, "#6b7280")
            cards += f"""
            <div style="background:{bg};border-left:4px solid {bc};border-radius:6px;
                        padding:12px 16px;margin-bottom:8px">
              <div>{sev_badge(sev)} &nbsp;<strong>{html.escape(title)}</strong></div>
              <div style="margin-top:6px;font-size:13px;color:#374151">
                <b>Riesgo:</b> {html.escape(risk)}
              </div>
              <div style="margin-top:4px;font-size:13px;color:#1d4ed8">
                <b>Acción:</b> {html.escape(action)}
              </div>
            </div>"""
        return cards

    # ── Server sections ───────────────────────────────────────────────
    server_sections = ""
    for r in ok:
        protocols_html = "".join(
            proto_row(pn, r["protocols"].get(pn, {}))
            for pn, _ in PROTOCOL_ATTRS
        )
        all_ciphers = ""
        for pn, _ in PROTOCOL_ATTRS:
            suites = r["protocols"].get(pn, {}).get("cipher_suites", [])
            if suites:
                all_ciphers += (
                    f'<tr><td colspan="4" style="padding:8px 10px;background:#f9fafb;'
                    f'font-weight:700;font-size:12px;color:#374151">{pn}</td></tr>'
                    + cipher_rows(suites)
                )

        findings = r.get("recommendations", [])
        n_crit   = sum(1 for f in findings if f[1] == "CRÍTICO")
        badge_txt = (f'<span style="background:#ef4444;color:#fff;padding:3px 10px;'
                     f'border-radius:6px;font-size:12px;font-weight:700">'
                     f'🔴 {n_crit} CRÍTICO(S)</span>' if n_crit else
                     f'<span style="background:#16a34a;color:#fff;padding:3px 10px;'
                     f'border-radius:6px;font-size:12px;font-weight:700">✅ OK</span>')

        server_sections += f"""
        <div style="border:1px solid #e5e7eb;border-radius:12px;margin-bottom:32px;
                    overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.06)">
          <!-- Server header -->
          <div style="background:#1e293b;padding:18px 24px;display:flex;
                      justify-content:space-between;align-items:center">
            <div style="color:#f1f5f9;font-size:18px;font-weight:700">
              🖥️ {r['hostname']}:{r['port']}
            </div>
            {badge_txt}
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:0">
            <!-- Protocols -->
            <div style="padding:20px 24px;border-right:1px solid #f3f4f6">
              <h3 style="margin:0 0 12px;color:#0f172a;font-size:14px">
                🔐 Protocolos TLS/SSL
              </h3>
              <table style="width:100%;border-collapse:collapse;font-size:13px">
                {protocols_html}
              </table>
            </div>
            <!-- Certificate -->
            <div style="padding:20px 24px">
              <h3 style="margin:0 0 12px;color:#0f172a;font-size:14px">
                📜 Certificado
              </h3>
              {cert_block(r.get("certificate"))}
            </div>
          </div>

          <!-- Cipher suites -->
          <div style="padding:20px 24px;border-top:1px solid #f3f4f6">
            <h3 style="margin:0 0 12px;color:#0f172a;font-size:14px">
              🔑 Cipher Suites
            </h3>
            <table style="width:100%;border-collapse:collapse;font-size:12px">
              <thead>
                <tr style="background:#f8fafc">
                  <th style="padding:7px 10px;text-align:left;color:#6b7280">Cipher Suite</th>
                  <th style="padding:7px 10px;text-align:left;color:#6b7280">Nivel</th>
                  <th style="padding:7px 10px;color:#6b7280">Score</th>
                  <th style="padding:7px 10px;color:#6b7280"></th>
                </tr>
              </thead>
              <tbody>{all_ciphers}</tbody>
            </table>
          </div>

          <!-- Findings -->
          <div style="padding:20px 24px;border-top:1px solid #f3f4f6;background:#fafafa">
            <h3 style="margin:0 0 12px;color:#0f172a;font-size:14px">
              ⚠️ Hallazgos y Recomendaciones
            </h3>
            {finding_cards(findings)}
          </div>
        </div>"""

    # Error servers
    error_section = ""
    for r in err:
        error_section += (
            f'<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;'
            f'padding:14px 18px;margin-bottom:16px;color:#dc2626">'
            f'❌ <strong>{r["hostname"]}:{r["port"]}</strong> — Sin conectividad</div>'
        )

    # Summary bar
    total_findings = sum(len(r.get("recommendations", [])) for r in ok)
    total_crit     = sum(1 for r in ok for f in r.get("recommendations", []) if f[1] == "CRÍTICO")
    total_high     = sum(1 for r in ok for f in r.get("recommendations", []) if f[1] == "ALTO")

    summary_cards = ""
    for val, label, color in [
        (len(results), "SERVIDORES", "#6366f1"),
        (total_crit,   "CRÍTICOS",   "#ef4444"),
        (total_high,   "ALTOS",      "#f97316"),
        (total_findings,"HALLAZGOS", "#6b7280"),
    ]:
        summary_cards += (
            f'<div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;'
            f'padding:18px 24px;text-align:center;flex:1">'
            f'<div style="font-size:2rem;font-weight:800;color:{color}">{val}</div>'
            f'<div style="font-size:11px;letter-spacing:1px;color:#9ca3af;margin-top:4px">'
            f'{label}</div></div>'
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Reporte TLS/SSL Audit — {ts}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8fafc; color: #1e293b;
      max-width: 1100px; margin: 0 auto; padding: 32px 24px;
    }}
    @media print {{
      body {{ max-width: 100%; padding: 0; background: #fff; }}
      .no-print {{ display: none; }}
    }}
  </style>
</head>
<body>

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0f172a 0%,#1e40af 100%);
              border-radius:14px;padding:36px 40px;margin-bottom:32px;color:#fff">
    <div style="font-size:13px;letter-spacing:2px;opacity:.7;margin-bottom:8px">
      REPORTE DE AUDITORÍA DE SEGURIDAD
    </div>
    <h1 style="font-size:28px;font-weight:800;margin-bottom:6px">
      🔐 TLS / SSL Security Auditor
    </h1>
    <div style="opacity:.8;font-size:14px">
      Generado: {ts} &nbsp;·&nbsp; {len(results)} servidor(es) analizados
    </div>
  </div>

  <!-- Summary -->
  <div style="display:flex;gap:14px;margin-bottom:32px;flex-wrap:wrap">
    {summary_cards}
  </div>

  {error_section}

  <!-- Server details -->
  {server_sections}

  <!-- Footer -->
  <div style="text-align:center;color:#9ca3af;font-size:12px;
              border-top:1px solid #e5e7eb;padding-top:20px;margin-top:8px">
    TLS/SSL Auditor &nbsp;·&nbsp; Reporte generado el {ts} &nbsp;·&nbsp;
    Uso exclusivamente defensivo
  </div>

</body>
</html>"""


# ── Rendering helpers ──────────────────────────────────────────────────────────
_SEV_NORM = {
    "CRÍTICO": "CRITICO",
    "ALTO": "ALTO",
    "MEDIO": "MEDIO",
    "BAJO": "BAJO",
}
_LABEL_NORM = {
    "FUERTE": "FUERTE",
    "BUENO": "BUENO",
    "ACEPTABLE": "ACEPTABLE",
    "DÉBIL": "DEBIL",
    "CRÍTICO": "CRITICO",
}
_SEV_ICON = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🔵"}
_LABEL_COLOR = {
    "FUERTE": "#00C853",
    "BUENO": "#64DD17",
    "ACEPTABLE": "#FFD740",
    "DEBIL": "#FF6D00",
    "CRITICO": "#DD2C00",
}


def _badge(sev: str) -> str:
    cls = _SEV_NORM.get(sev, "BAJO")
    return (f'<span class="sev-badge badge-{cls}">'
            f'{html.escape(sev)}</span>')


def _score_pill(score: float, label: str) -> str:
    cls = _LABEL_NORM.get(label, "ACEPTABLE")
    return (f'<span class="score-pill pill-{cls}">'
            f'{score:.1f}/10 &nbsp;{html.escape(label)}</span>')


def _sev_card(sev: str, title: str, risk: str, action: str) -> str:
    cls = _SEV_NORM.get(sev, "BAJO")
    return f"""
<div class="sev-card sev-{cls}">
  {_badge(sev)} <strong>{html.escape(title)}</strong>
  <div style="margin-top:6px; color:#cdd5e0; font-size:0.87rem">
    <b>Riesgo:</b> {html.escape(risk)}
  </div>
  <div style="margin-top:4px; color:#79c0ff; font-size:0.87rem">
    <b>Acción:</b> {html.escape(action)}
  </div>
</div>"""


# ── Section 1: Comparison ──────────────────────────────────────────────────────
def render_comparison(results: list) -> None:
    ok = [r for r in results if r["status"] == "ok"]
    if len(ok) < 2:
        return

    st.markdown('<div class="sec-header">🔀 Comparación de Servidores</div>',
                unsafe_allow_html=True)

    hosts = [r["key"] for r in ok]

    # ── Protocol matrix ────────────────────────────────────────────────
    st.markdown("**Matriz de soporte de protocolos**")
    rows = []
    for proto_name, _ in PROTOCOL_ATTRS:
        row: dict = {"Protocolo": proto_name}
        flags = []
        for r in ok:
            p = r["protocols"].get(proto_name, {})
            sup = p.get("supported")
            n = len(p.get("cipher_suites", []))
            if sup is True:
                row[r["key"]] = f"✅ SÍ ({n})"
                flags.append(True)
            elif sup is False:
                row[r["key"]] = "❌ NO"
                flags.append(False)
            else:
                row[r["key"]] = "⚠️ ERR"
                flags.append(None)
        non_null = [f for f in flags if f is not None]
        row["Discrepancia"] = "⚠️ DIFERENTE" if (
            non_null and len(set(non_null)) > 1) else "✔"
        rows.append(row)

    cols = ["Protocolo"] + hosts + ["Discrepancia"]
    df = pd.DataFrame(rows, columns=cols)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # ── Certificate summary ────────────────────────────────────────────
    st.markdown("**Resumen de certificados**")
    cert_rows = []
    for r in ok:
        c = r.get("certificate") or {}
        days = c.get("days_remaining")
        if c.get("expired"):
            days_str = f"EXPIRADO hace {abs(days)} días"
        elif days is not None:
            days_str = f"{days} días"
        else:
            days_str = "N/A"
        cert_rows.append({
            "Servidor": r["key"],
            "Tipo de Clave": c.get("key_type", "N/A"),
            "Confiable": "✅ Sí" if c.get("trusted") else "❌ No",
            "Días Restantes": days_str,
        })
    st.dataframe(pd.DataFrame(cert_rows),
                 use_container_width=True, hide_index=True)

    # ── Average cipher score matrix ────────────────────────────────────
    st.markdown(
        "**Puntuación media de cipher suites por protocolo (Escala de 0 a 10)**")
    score_rows = []
    for proto_name, _ in PROTOCOL_ATTRS:
        row = {"Protocolo": proto_name}
        for r in ok:
            suites = r["protocols"].get(
                proto_name, {}).get("cipher_suites", [])
            row[r["key"]] = (
                round(sum(s["score"] for s in suites) / len(suites), 2)
                if suites else None
            )
        score_rows.append(row)

    score_df = pd.DataFrame(score_rows)
    st.dataframe(score_df, use_container_width=True, hide_index=True)


# ── Section 1b: Cipher suite comparison ──────────────────────────────────────
def render_cipher_comparison(results: list) -> None:
    """Show a per-protocol cipher suite presence matrix across all scanned servers."""
    ok = [r for r in results if r["status"] == "ok"]
    if len(ok) < 2:
        return

    st.markdown(
        '<div class="sec-header">🔑 Comparación de Cipher Suites entre Servidores</div>',
        unsafe_allow_html=True,
    )

    hosts = [r["key"] for r in ok]

    # Collect cipher suites present in at least one server per protocol
    proto_universe: dict[str, set[str]] = {}
    for proto_name, _ in PROTOCOL_ATTRS:
        all_suites: set[str] = set()
        for r in ok:
            for s in r["protocols"].get(proto_name, {}).get("cipher_suites", []):
                all_suites.add(s["name"])
        if all_suites:
            proto_universe[proto_name] = all_suites

    if not proto_universe:
        st.info("No hay datos de cipher suites disponibles para comparar.")
        return

    # Protocol selector
    available_protos = list(proto_universe.keys())
    selected_proto = st.selectbox(
        "Protocolo",
        available_protos,
        key="cipher_cmp_proto",
        help="Seleccione el protocolo TLS/SSL para ver la comparación de cipher suites.",
    )

    # Filter options
    filter_col1, filter_col2 = st.columns([2, 2])
    with filter_col1:
        show_filter = st.radio(
            "Mostrar",
            ["Todos", "Solo comunes", "Solo exclusivos", "Solo débiles"],
            horizontal=True,
            key="cipher_cmp_filter",
        )
    with filter_col2:
        sort_by = st.radio(
            "Ordenar por",
            ["Nombre", "Score (mayor a menor)", "Presencia"],
            horizontal=True,
            key="cipher_cmp_sort",
        )

    universe = proto_universe[selected_proto]

    # Build lookup: suite_name -> {host -> suite_data | None}
    suite_map: dict[str, dict[str, dict | None]] = {}
    for name in universe:
        suite_map[name] = {}
        for r in ok:
            found = next(
                (s for s in r["protocols"].get(selected_proto, {}).get("cipher_suites", [])
                 if s["name"] == name),
                None,
            )
            suite_map[name][r["key"]] = found

    common_suites = {n for n, hm in suite_map.items() if all(
        v is not None for v in hm.values())}
    exclusive = {}
    for hi, host in enumerate(hosts):
        excl = {n for n, hm in suite_map.items()
                if hm[host] is not None and sum(1 for v in hm.values() if v is not None) == 1}
        if excl:
            exclusive[host] = excl
    weak_suites = {n for n in universe
                   if any(kw in n.upper() for kw in WEAK_CIPHER_KEYWORDS)}

    # Apply filter
    if show_filter == "Solo comunes":
        visible = common_suites
    elif show_filter == "Solo exclusivos":
        visible = {n for excl_set in exclusive.values() for n in excl_set}
    elif show_filter == "Solo débiles":
        visible = weak_suites
    else:
        visible = universe

    if not visible:
        st.info("No hay cipher suites que coincidan con el filtro seleccionado.")
        return

    # Sort
    def _avg_score(name: str) -> float:
        scores = [hm["score"]
                  for hm in suite_map[name].values() if hm is not None]
        return sum(scores) / len(scores) if scores else 0.0

    def _presence_count(name: str) -> int:
        return sum(1 for v in suite_map[name].values() if v is not None)

    if sort_by == "Score (mayor a menor)":
        sorted_suites = sorted(visible, key=_avg_score, reverse=True)
    elif sort_by == "Presencia":
        sorted_suites = sorted(visible, key=_presence_count, reverse=True)
    else:
        sorted_suites = sorted(visible)

    # Summary metrics
    m1, m2, m3, m4 = st.columns(4)
    for col, val, label, color in [
        (m1, len(universe),       "TOTAL UNIVERSO",   "#8b949e"),
        (m2, len(common_suites),  "COMUNES A TODOS",  "#3fb950"),
        (m3, len(weak_suites & universe), "DÉBILES", "#FF4B4B"),
        (m4, sum(len(v) for v in exclusive.values()), "EXCLUSIVOS", "#FFD700"),
    ]:
        col.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-val" style="color:{color}">{val}</div>'
            f'<div class="metric-lbl">{label}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Presence matrix table ─────────────────────────────────────────
    rows = []
    for name in sorted_suites:
        hm = suite_map[name]
        row: dict = {"Cipher Suite": name}

        # Presence columns
        for host in hosts:
            s = hm[host]
            if s is not None:
                lbl_norm = _LABEL_NORM.get(s["label"], "ACEPTABLE")
                row[host] = f"✅ {s['score']:.1f}"
            else:
                row[host] = "❌"

        # Avg score only from servers that support it
        scores = [hm[h]["score"] for h in hosts if hm[h] is not None]
        row["Score Avg"] = round(
            sum(scores) / len(scores), 2) if scores else 0.0
        row["Servidores"] = f"{sum(1 for h in hosts if hm[h] is not None)}/{len(hosts)}"

        # Tag
        tags = []
        if name in common_suites:
            tags.append("🟢 Común")
        elif name in {n for excl_set in exclusive.values() for n in excl_set}:
            tags.append("🟡 Exclusivo")
        else:
            tags.append("🔵 Parcial")
        if name in weak_suites:
            tags.append("🔴 Débil")
        row["Estado"] = " ".join(tags)

        rows.append(row)

    df = pd.DataFrame(rows)
    col_cfg: dict = {
        "Score Avg": st.column_config.ProgressColumn(
            "Score Avg", min_value=0, max_value=10, format="%.2f"
        ),
    }
    for host in hosts:
        col_cfg[host] = st.column_config.TextColumn(host, width="medium")

    st.dataframe(df, use_container_width=True,
                 hide_index=True, column_config=col_cfg)

    # ── Exclusive suites callout ─────────────────────────────────────
    if exclusive:
        st.markdown(
            "**Cipher suites exclusivos por servidor** *(presentes en uno solo)*")
        for host, excl_set in exclusive.items():
            with st.expander(f"🖥️ {host} — {len(excl_set)} exclusivo(s)"):
                for name in sorted(excl_set):
                    s = suite_map[name][host]
                    score_text = f"{s['score']:.1f}/10 — {s['label']}" if s else ""
                    weak_mark = " 🔴 DÉBIL" if name in weak_suites else ""
                    st.markdown(
                        f"- `{name}` &nbsp; **{score_text}**{weak_mark}",
                        unsafe_allow_html=True,
                    )

    # ── Suites present in some but not all ───────────────────────────
    partial = {
        n for n in universe
        if n not in common_suites
        and n not in {name for excl_set in exclusive.values() for name in excl_set}
    }
    if partial:
        with st.expander(f"🔵 Cipher suites presentes en algunos servidores — {len(partial)} suite(s)"):
            partial_rows = []
            for name in sorted(partial):
                hm = suite_map[name]
                present_in = [h for h in hosts if hm[h] is not None]
                absent_in = [h for h in hosts if hm[h] is None]
                scores = [hm[h]["score"] for h in present_in]
                avg = round(sum(scores) / len(scores), 2) if scores else 0.0
                partial_rows.append({
                    "Cipher Suite": name,
                    "Presente en": ", ".join(present_in),
                    "Ausente en":  ", ".join(absent_in),
                    "Score Avg":   avg,
                    "Débil": "🔴" if name in weak_suites else "",
                })
            st.dataframe(
                pd.DataFrame(partial_rows),
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Score Avg": st.column_config.ProgressColumn(
                        "Score Avg", min_value=0, max_value=10, format="%.2f"
                    )
                },
            )


# ── Section 2: Recommendations ────────────────────────────────────────────────
def render_recommendations(results: list) -> None:
    ok = [r for r in results if r["status"] == "ok"]
    if not ok:
        return

    st.markdown('<div class="sec-header">⚠️ Recomendaciones de Seguridad</div>',
                unsafe_allow_html=True)

    total = sum(len(r["recommendations"]) for r in ok)
    n_crit = sum(
        1 for r in ok for f in r["recommendations"] if f[1] == "CRÍTICO")
    n_high = sum(1 for r in ok for f in r["recommendations"] if f[1] == "ALTO")
    n_medium = sum(
        1 for r in ok for f in r["recommendations"] if f[1] == "MEDIO")
    n_clean = sum(1 for r in ok if not r["recommendations"])

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, val, label, color in [
        (c1, n_crit,   "CRÍTICOS",   "#FF4B4B"),
        (c2, n_high,   "ALTOS",      "#FF8C00"),
        (c3, n_medium, "MEDIOS",     "#FFD700"),
        (c4, total,    "TOTAL",      "#8b949e"),
        (c5, n_clean,  "SERVIDORES OK", "#3fb950"),
    ]:
        col.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-val" style="color:{color}">{val}</div>'
            f'<div class="metric-lbl">{label}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    for r in ok:
        host = r["key"]
        findings = r["recommendations"]
        if not findings:
            st.success(
                f"✅ **{host}** — Sin hallazgos. Configuración correcta.")
            continue

        n_crit_srv = sum(1 for f in findings if f[1] == "CRÍTICO")
        label_extra = f" — 🔴 {n_crit_srv} crítico(s)" if n_crit_srv else ""

        with st.expander(
            f"🖥️ {host}  ·  {len(findings)} hallazgo(s){label_extra}",
            expanded=True,
        ):
            for _, sev, title, risk, action in findings:
                st.markdown(_sev_card(sev, title, risk, action),
                            unsafe_allow_html=True)


# ── Section 3: Detailed server info ───────────────────────────────────────────
def render_details(results: list) -> None:
    st.markdown('<div class="sec-header">🔍 Información Detallada por Servidor</div>',
                unsafe_allow_html=True)

    for r in [x for x in results if x["status"] == "error"]:
        st.error(f"❌ **{r['key']}** — Sin conectividad: {r['error']}")

    ok = [r for r in results if r["status"] == "ok"]
    if not ok:
        return

    tabs = st.tabs([f"🖥️ {r['key']}" for r in ok])

    for tab, r in zip(tabs, ok):
        with tab:
            col_proto, col_cert = st.columns([3, 2], gap="large")

            # ── Protocols ─────────────────────────────────────────────
            with col_proto:
                st.markdown("#### 🔐 Protocolos y Cipher Suites")

                for proto_name, _ in PROTOCOL_ATTRS:
                    p = r["protocols"].get(proto_name, {})
                    sup = p.get("supported")
                    suites = p.get("cipher_suites", [])
                    err = p.get("error")

                    if sup is True:
                        badge = (f'<span style="color:#3fb950;font-weight:700">'
                                 f'✅ SOPORTADO ({len(suites)} suites)</span>')
                    elif sup is False:
                        badge = '<span style="color:#484f58">— No soportado</span>'
                    else:
                        badge = (f'<span style="color:#f85149">'
                                 f'⚠ Error{(" — "+html.escape(err)) if err else ""}'
                                 f'</span>')

                    st.markdown(
                        f'<div class="proto-row"><b>{proto_name}</b> &nbsp; {badge}</div>',
                        unsafe_allow_html=True,
                    )

                    if suites:
                        suite_rows = []
                        for s in suites:
                            lbl_norm = _LABEL_NORM.get(s["label"], "ACEPTABLE")
                            color = _LABEL_COLOR.get(lbl_norm, "#ffffff")
                            suite_rows.append({
                                "Cipher Suite": s["name"],
                                "Score": s["score"],
                                "Nivel": s["label"],
                                "Débil": "🔴" if s["is_weak"] else "",
                            })
                        df = pd.DataFrame(suite_rows)
                        st.dataframe(
                            df,
                            use_container_width=True,
                            hide_index=True,
                            column_config={
                                "Score": st.column_config.ProgressColumn(
                                    "Score",
                                    min_value=0,
                                    max_value=10,
                                    format="%.1f",
                                ),
                                "Débil": st.column_config.TextColumn(
                                    "⚠", width="small"),
                            },
                        )

            # ── Certificate ───────────────────────────────────────────
            with col_cert:
                st.markdown("#### 📜 Certificado TLS")
                cert = r.get("certificate")

                if cert:
                    days = cert.get("days_remaining")
                    if cert.get("expired"):
                        days_str = (f'<span class="cert-bad">'
                                    f'EXPIRADO hace {abs(days)} días</span>')
                    elif days is not None and days < 7:
                        days_str = (f'<span class="cert-bad">'
                                    f'Vence en {days} días — URGENTE 🚨</span>')
                    elif days is not None and days < 30:
                        days_str = (f'<span class="cert-warn">'
                                    f'Vence en {days} días — Próximo ⚠️</span>')
                    elif days is not None:
                        days_str = (f'<span class="cert-ok">'
                                    f'Vence en {days} días — OK ✅</span>')
                    else:
                        days_str = "Desconocido"

                    trusted_str = (
                        '<span class="cert-ok">✅ Confiable</span>'
                        if cert["trusted"] else
                        '<span class="cert-bad">❌ No confiable (autofirmado)</span>'
                    )

                    # shorten long strings safely
                    subj = html.escape(cert["subject"])
                    issr = html.escape(cert["issuer"])
                    if len(subj) > 60:
                        subj = subj[:60] + "…"
                    if len(issr) > 60:
                        issr = issr[:60] + "…"

                    key_size = cert.get("key_size")
                    key_type_raw = cert.get("key_type", "")
                    if key_size:
                        if key_type_raw in ("RSAPublicKey", "DSAPublicKey"):
                            algo = "RSA" if "RSA" in key_type_raw else "DSA"
                            if key_size < 2048:
                                key_size_str = (f'<span class="cert-bad">'
                                                f'{algo} {key_size} bits — 🔴 INSUFICIENTE</span>')
                            elif key_size < 3072:
                                key_size_str = (f'<span class="cert-warn">'
                                                f'{algo} {key_size} bits — ⚠️ Aceptable</span>')
                            else:
                                key_size_str = (f'<span class="cert-ok">'
                                                f'{algo} {key_size} bits — ✅ Fuerte</span>')
                        else:
                            key_size_str = f'<code>{key_type_raw}</code> (clave moderna)'
                    else:
                        key_size_str = "N/A"

                    st.markdown(f"""
<table class="cert-table">
  <tr><td>Sujeto</td><td><code>{subj}</code></td></tr>
  <tr><td>Emisor</td><td><code>{issr}</code></td></tr>
  <tr><td>Tipo / Tamaño de Clave</td><td>{key_size_str}</td></tr>
  <tr><td>Válido desde</td><td>{html.escape(cert['valid_from'])}</td></tr>
  <tr><td>Válido hasta</td><td>{html.escape(cert['valid_until'])}</td></tr>
  <tr><td>Vencimiento</td><td>{days_str}</td></tr>
  <tr><td>Confiabilidad</td><td>{trusted_str}</td></tr>
</table>""", unsafe_allow_html=True)

                    # Quick cert health bar
                    st.markdown("<br>", unsafe_allow_html=True)
                    health_items = [
                        ("CA Reconocida",   cert["trusted"],          True),
                        ("No Expirado",     not cert["expired"],      True),
                        ("Margen > 30 días",
                         (cert["days_remaining"] or 0) > 30 and not cert["expired"],
                         False),
                        ("Clave RSA ≥ 2048 bits",
                         not (cert.get("key_size") and
                              cert.get("key_type") in ("RSAPublicKey", "DSAPublicKey") and
                              cert["key_size"] < 2048),
                         True),
                    ]
                    for label, ok_flag, required in health_items:
                        icon = "✅" if ok_flag else ("🔴" if required else "⚠️")
                        st.markdown(f"{icon} &nbsp;{label}",
                                    unsafe_allow_html=True)
                else:
                    st.warning(
                        "No se pudo obtener información del certificado.")

            # ── Raw cipher component breakdown ────────────────────────
            with st.expander("🔬 Desglose de componentes por cipher suite"):
                for proto_name, _ in PROTOCOL_ATTRS:
                    suites = r["protocols"].get(
                        proto_name, {}).get("cipher_suites", [])
                    if not suites:
                        continue
                    st.markdown(f"**{proto_name}**")
                    comp_rows = []
                    for s in suites:
                        comps = s["components"]
                        comp_rows.append({
                            "Cipher Suite": s["name"],
                            "KEX": f"{comps['KEX'][0]} ({comps['KEX'][1]})",
                            "Auth": f"{comps['Auth'][0]} ({comps['Auth'][1]})",
                            "Cipher": f"{comps['Cipher'][0]} ({comps['Cipher'][1]})",
                            "Hash": f"{comps['Hash'][0]} ({comps['Hash'][1]})",
                            "Score": s["score"],
                        })
                    st.dataframe(
                        pd.DataFrame(comp_rows),
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "Score": st.column_config.ProgressColumn(
                                "Score", min_value=0, max_value=10, format="%.1f"),
                        },
                    )


# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔒 TLS/SSL Auditor")
    st.markdown("---")

    targets_raw = st.text_area(
        "Objetivos (uno por línea)",
        placeholder="google.com\ncloudflare.com:443\n192.168.1.1:8443",
        height=150,
        help="Formato: hostname  o  hostname:puerto. Puerto por defecto: 443.",
    )

    all_ports_cb = st.checkbox(
        "Escanear todos los puertos críticos",
        value=False,
        help=f"Escanea {len(ALL_AUDIT_PORTS)} puertos en lugar de solo el 443.",
    )

    scan_btn = st.button("🔍 Iniciar Escaneo", type="primary",
                         use_container_width=True)

    st.markdown("---")
    st.markdown("""
<small>
<b>Puertos críticos incluidos:</b><br>
LEGACY, STANDARD y MODERN<br><br>
<b>Formatos aceptados:</b><br>
<code>google.com</code><br>
<code>example.com:8443</code><br>
<code>192.168.1.10:443</code>
</small>
""", unsafe_allow_html=True)

    if "results" in st.session_state:
        st.markdown("---")
        ok_n = sum(
            1 for r in st.session_state["results"] if r["status"] == "ok")
        err_n = sum(
            1 for r in st.session_state["results"] if r["status"] == "error")
        st.markdown(f"**Último escaneo:** {ok_n} OK / {err_n} error(es)")
        if st.button("🗑️ Limpiar resultados", use_container_width=True):
            del st.session_state["results"]
            st.rerun()


# ── Main page ──────────────────────────────────────────────────────────────────
st.markdown("# 🔒 TLS/SSL Security Auditor")
st.markdown(
    "Analice la configuración TLS/SSL de uno o más servidores "
    "para identificar vulnerabilidades de seguridad en su stack criptográfico."
)

if scan_btn:
    raw = [t.strip() for t in targets_raw.strip().splitlines() if t.strip()]
    if not raw:
        st.error("⚠️ Ingrese al menos un objetivo en el panel lateral.")
    else:
        invalid = [t for t in raw if not is_valid_target(t.rsplit(":", 1)[0])]
        if invalid:
            st.warning(
                f"Los siguientes objetivos tienen formato incorrecto y serán ignorados: "
                + ", ".join(f"`{t}`" for t in invalid)
            )

        valid = [t for t in raw if is_valid_target(t.rsplit(":", 1)[0])]
        if not valid:
            st.error("No quedan objetivos válidos para escanear.")
        else:
            port_note = (f" × {len(ALL_AUDIT_PORTS)} puertos"
                         if all_ports_cb else "")
            with st.spinner(
                f"Escaneando {len(valid)} objetivo(s){port_note}… "
                "Esto puede tardar varios minutos."
            ):
                results = scan_servers(valid, all_ports=all_ports_cb)

            if not results:
                st.error(
                    "No se obtuvieron resultados. Verifique los objetivos y la conectividad.")
            else:
                st.session_state["results"] = results
                st.rerun()

# ── Render saved results ───────────────────────────────────────────────────────
if "results" in st.session_state:
    results = st.session_state["results"]
    ok_results = [r for r in results if r["status"] == "ok"]

    st.markdown("---")

    # Section 1 — Comparison (only when ≥ 2 servers responded)
    if len(ok_results) >= 2:
        render_comparison(results)
        st.markdown("---")

    # Section 2 — Recommendations
    render_recommendations(results)
    st.markdown("---")

    # Section 3 — Detailed info
    render_details(results)

    # Section 4 — Cipher suite comparison (only when ≥ 2 servers responded)
    if len(ok_results) >= 2:
        st.markdown("---")
        render_cipher_comparison(results)

    # ── Section 5 — Download reports ──────────────────────────────────────────
    st.markdown("---")
    st.markdown('<div class="sec-header">📥 Descargar Reporte</div>',
                unsafe_allow_html=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = f"tls_audit_{ts}"

    col_json, col_csv, col_html = st.columns(3)

    with col_json:
        json_data = _build_json(results)
        st.download_button(
            label="⬇️ Descargar JSON",
            data=json_data,
            file_name=f"{filename_base}.json",
            mime="application/json",
            use_container_width=True,
            help="Reporte completo con todos los datos (protocolos, cipher suites, certificados y hallazgos)",
        )
        st.caption(f"📄 {len(results)} servidor(es) · {len(json_data):,} bytes")

    with col_csv:
        csv_data = _build_csv(results)
        st.download_button(
            label="⬇️ Descargar CSV",
            data=csv_data,
            file_name=f"{filename_base}.csv",
            mime="text/csv",
            use_container_width=True,
            help="Vista tabular: una fila por cipher suite / hallazgo. Compatible con Excel y pandas.",
        )
        st.caption("📊 Listo para Excel / pandas · UTF-8")

    with col_html:
        html_data = _build_html(results)
        st.download_button(
            label="⬇️ Descargar HTML",
            data=html_data,
            file_name=f"{filename_base}.html",
            mime="text/html",
            use_container_width=True,
            help="Reporte visual listo para compartir — ábrelo en cualquier navegador sin instalar nada.",
        )
        st.caption("🌐 Abre en navegador · Imprimible · Sin dependencias")
else:
    # Landing placeholder
    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    for col, icon, title, body in [
        (c1, "🔐", "Protocolos",
         "Detecta SSL 2.0 / 3.0, TLS 1.0 / 1.1 obsoletos y verifica soporte de TLS 1.3."),
        (c2, "🏷️", "Cipher Suites",
         "Puntúa cada cipher suite de 0 a 10 e identifica algoritmos NULL, EXPORT, RC4, 3DES."),
        (c3, "📜", "Certificados",
         "Verifica confiabilidad de la CA, caducidad y días restantes de validez."),
    ]:
        col.markdown(
            f'<div class="metric-card" style="padding:20px">'
            f'<div style="font-size:2rem">{icon}</div>'
            f'<div style="font-weight:700;margin:8px 0 6px">{title}</div>'
            f'<div style="color:#8b949e;font-size:0.83rem">{body}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

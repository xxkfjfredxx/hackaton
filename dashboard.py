"""
TLS/SSL Auditor Dashboard — Streamlit UI
Run: streamlit run dashboard.py
"""
import html
import datetime
import warnings
import sys
import os

import streamlit as st
import pandas as pd

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze import (
    Scanner,
    ScanCommand,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerScanStatusEnum,
    ScanCommandAttemptStatusEnum,
)

# Make tlsauditor importable from the same folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tlsauditor import (
    score_cipher_suite,
    is_valid_target,
    SCAN_COMMANDS,
    PROTOCOL_ATTRS,
    WEAK_CIPHER_KEYWORDS,
    ALL_AUDIT_PORTS,
)

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
                 has_tls12, has_tls13):
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
        obs = ", ".join(p for p in ["TLS 1.0", "TLS 1.1"] if p in found_obsolete)
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
            proto_data = {"supported": None, "cipher_suites": [], "error": None}

            if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                accepted = attempt.result.accepted_cipher_suites
                if accepted:
                    proto_data["supported"] = True
                    supported_protos.append(proto_name)
                    for s in accepted:
                        name = s.cipher_suite.name
                        score, label, components = score_cipher_suite(name)
                        is_weak = any(kw in name.upper() for kw in WEAK_CIPHER_KEYWORDS)
                        proto_data["cipher_suites"].append({
                            "name": name,
                            "score": score,
                            "label": label,
                            "components": components,
                            "is_weak": is_weak,
                        })
                    weak = [s["name"] for s in proto_data["cipher_suites"] if s["is_weak"]]
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
                    "serial": str(leaf.serial_number),
                    "valid_from": str(not_before),
                    "valid_until": str(not_after),
                    "days_remaining": days_remaining,
                    "expired": is_expired,
                    "trusted": cert_trusted,
                }

        data["recommendations"] = get_findings(
            supported_protos, weak_ciphers_by_proto,
            cert_trusted, cert_expired, cert_days,
            has_tls12, has_tls13,
        )
        results.append(data)

    return results


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

    # ── Average cipher score matrix ────────────────────────────────────
    st.markdown("**Puntuación media de cipher suites por protocolo**")
    score_rows = []
    for proto_name, _ in PROTOCOL_ATTRS:
        row = {"Protocolo": proto_name}
        for r in ok:
            suites = r["protocols"].get(proto_name, {}).get("cipher_suites", [])
            row[r["key"]] = (
                round(sum(s["score"] for s in suites) / len(suites), 2)
                if suites else None
            )
        score_rows.append(row)

    score_df = pd.DataFrame(score_rows)
    st.dataframe(score_df, use_container_width=True, hide_index=True)

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
    st.dataframe(pd.DataFrame(cert_rows), use_container_width=True, hide_index=True)


# ── Section 2: Recommendations ────────────────────────────────────────────────
def render_recommendations(results: list) -> None:
    ok = [r for r in results if r["status"] == "ok"]
    if not ok:
        return

    st.markdown('<div class="sec-header">⚠️ Recomendaciones de Seguridad</div>',
                unsafe_allow_html=True)

    total     = sum(len(r["recommendations"]) for r in ok)
    n_crit    = sum(1 for r in ok for f in r["recommendations"] if f[1] == "CRÍTICO")
    n_high    = sum(1 for r in ok for f in r["recommendations"] if f[1] == "ALTO")
    n_medium  = sum(1 for r in ok for f in r["recommendations"] if f[1] == "MEDIO")
    n_clean   = sum(1 for r in ok if not r["recommendations"])

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
            st.success(f"✅ **{host}** — Sin hallazgos. Configuración correcta.")
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
                    sup    = p.get("supported")
                    suites = p.get("cipher_suites", [])
                    err    = p.get("error")

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

                    st.markdown(f"""
<table class="cert-table">
  <tr><td>Sujeto</td><td><code>{subj}</code></td></tr>
  <tr><td>Emisor</td><td><code>{issr}</code></td></tr>
  <tr><td>Tipo de Clave</td><td><code>{html.escape(cert['key_type'])}</code></td></tr>
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
                    ]
                    for label, ok_flag, required in health_items:
                        icon = "✅" if ok_flag else ("🔴" if required else "⚠️")
                        st.markdown(f"{icon} &nbsp;{label}", unsafe_allow_html=True)
                else:
                    st.warning("No se pudo obtener información del certificado.")

            # ── Raw cipher component breakdown ────────────────────────
            with st.expander("🔬 Desglose de componentes por cipher suite"):
                for proto_name, _ in PROTOCOL_ATTRS:
                    suites = r["protocols"].get(proto_name, {}).get("cipher_suites", [])
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
        ok_n  = sum(1 for r in st.session_state["results"] if r["status"] == "ok")
        err_n = sum(1 for r in st.session_state["results"] if r["status"] == "error")
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
                st.error("No se obtuvieron resultados. Verifique los objetivos y la conectividad.")
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

"""
app.py — TLS Auditor · Interfaz Streamlit profesional
------------------------------------------------------
Ejecutar:
    streamlit run app.py
"""

import sys
import os
import time
import queue
import threading
import datetime
import importlib
import importlib.util
import re
import ipaddress

import streamlit as st
import plotly.graph_objects as go

st.set_page_config(page_title="TLS Auditor", page_icon="🔐", layout="wide", initial_sidebar_state="collapsed")

# ── Catálogo de Puertos (igual que tslauditor1.py) ────────
COMMON_PORTS = {
    "LEGACY":   [443, 80, 8443, 21, 995, 993, 465, 8080, 5900, 1433, 3306, 6379, 25, 4433, 10000],
    "STANDARD": [443, 5432, 2376, 8443, 993, 995, 465, 587, 3389, 6443, 22, 1433, 8883, 5061, 4443],
    "MODERN":   [443, 8443, 2376, 6379, 5432, 4433, 8500, 2379, 9443, 3000, 5000, 8000, 11434, 4434, 9092]
}
ALL_AUDIT_PORTS = sorted(list(set(sum(COMMON_PORTS.values(), []))))

# ── Validación Estricta DNS / IP ─────────────────────────
def is_valid_target(target: str) -> bool:
    if "." in target or ":" in target:
        try: ipaddress.ip_address(target); return True
        except ValueError: pass
    if "." in target and any(c.isalpha() for c in target):
        return bool(re.compile(
            r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+'
            r'([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        ).match(target))
    return target.lower() == "localhost"

# ── PATH de módulos ───────────────────────────────────────
ROOT_DIR    = os.path.dirname(__file__)
SCANNER_DIR = os.path.join(ROOT_DIR, "scanner")
sys.path.insert(0, SCANNER_DIR)

def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCANNER_DIR, f"{name}.py"))
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# ── Pre-filtro TCP rápido ─────────────────────────────────
def _tcp_open(host: str, port: int, timeout: float = 0.8) -> bool:
    """Verifica si el puerto acepta conexiones TCP en menos de 1s."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout, ConnectionRefusedError):
        return False

# ── CSS ───────────────────────────────────────────────────
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
.stApp { background: linear-gradient(135deg, #0A0F1E 0%, #0D1424 50%, #0A1628 100%); min-height: 100vh; }
.tls-header {
    background: linear-gradient(135deg, #0F2444 0%, #162D4A 50%, #0F2444 100%);
    border: 1px solid #1E4D7B40; border-radius: 16px;
    padding: 32px 40px; margin-bottom: 24px; position: relative; overflow: hidden;
}
.tls-header::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, #3B82F6, #8B5CF6, #3B82F6, transparent);
}
.tls-header h1 { color: #F0F6FF; font-size: 2rem; font-weight: 700; margin: 0; }
.tls-header p  { color: #64A0D4; font-size: 0.95rem; margin: 6px 0 0; }
.input-card { background: #0D1B2E; border: 1px solid #1E3A5F50; border-radius: 14px; padding: 24px; margin-bottom: 16px; }
.progress-box {
    background: #07111F; border: 1px solid #1E3A5F60; border-radius: 12px;
    padding: 16px; font-family: 'JetBrains Mono'; font-size: 12px; color: #7AB3D4;
    max-height: 260px; overflow-y: auto; margin-top: 10px; line-height: 1.8;
}
.log-entry { display: flex; gap: 8px; padding: 2px 0; border-bottom: 1px solid #1E3A5F10; }
.log-time  { color: #2D4A6B; min-width: 65px; }
.proto-pill { display:inline-flex; align-items:center; gap:6px; padding:5px 10px; border-radius:6px; font-size:11px; font-weight:500; margin:2px; font-family:'JetBrains Mono'; }
.proto-danger { background:#2D0A0A; color:#F87171; border:1px solid #DC262640; }
.proto-warn   { background:#1F1500; color:#FDE68A; border:1px solid #CA8A0440; }
.proto-safe   { background:#0A1F14; color:#6EE7B7; border:1px solid #16A34A40; }
.proto-off    { background:#111827; color:#374151; border:1px solid #37415140; }
.section-title { color:#60A5FA; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:1.2px; margin:12px 0 8px; }
.metric-box  { background:#07111F; border-radius:10px; padding:14px; text-align:center; border:1px solid #1E3A5F40; }
.metric-val  { font-size:1.8rem; font-weight:700; }
.metric-lbl  { font-size:10px; color:#64A0D4; text-transform:uppercase; letter-spacing:0.8px; }
.finding-item { background:#07111F; border-radius:8px; padding:12px 14px; margin:6px 0; border-left:3px solid; font-size:12.5px; }
.finding-critical { border-left-color:#DC2626; }
.finding-high     { border-left-color:#EA580C; }
.finding-medium   { border-left-color:#CA8A04; }
.finding-low      { border-left-color:#3B82F6; }
.finding-info     { border-left-color:#475569; }
.port-tag { display:inline-block; background:#1E293B; border:1px solid #3B82F630; color:#60A5FA; padding:2px 8px; border-radius:4px; font-size:10px; font-family:'JetBrains Mono'; margin:2px; }
.stButton > button { background:linear-gradient(135deg,#2563EB,#1D4ED8)!important; color:white!important; border-radius:10px!important; font-weight:600!important; width:100%!important; box-shadow:0 4px 20px #2563EB40!important; }
.stCheckbox label { color:#A0C4E0!important; font-size:13px!important; }
</style>
"""

RISK_COLORS = {
    "CRITICAL": ("#DC2626", "#2D0A0A"), "HIGH":   ("#EA580C", "#1F1500"),
    "MEDIUM":   ("#CA8A04", "#201405"), "LOW":    ("#3B82F6", "#0A1628"),
    "OK":       ("#16A34A", "#0A1F14"),
}
SEVERITY_ICONS  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","OK":"✅","INFO":"ℹ️"}
FINDING_CLASS   = {"CRITICAL":"finding-critical","HIGH":"finding-high","MEDIUM":"finding-medium","LOW":"finding-low","INFO":"finding-info"}
OBSOLETE_PROTO  = {"SSL 2.0","SSL 3.0","TLS 1.0","TLS 1.1"}

def proto_pill_html(proto: str, srt) -> str:
    if srt is True and proto in OBSOLETE_PROTO: cls, icon = "proto-danger", "⚠"
    elif srt is True:  cls, icon = "proto-safe",   "✓"
    elif srt is False: cls, icon = "proto-off",    "—"
    else:              cls, icon = "proto-warn",   "?"
    return f'<span class="proto-pill {cls}">{icon} {proto}</span>'

def risk_gauge(score: int, level: str, key: str) -> None:
    clr, _ = RISK_COLORS.get(level, ("#6B7280","#111827"))
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        gauge={"axis":{"range":[0,100],"tickfont":{"color":"#2D4A6B","size":9}},
               "bar":{"color":clr,"thickness":0.25},
               "bgcolor":"#07111F","borderwidth":0,
               "steps":[{"range":[0,40],"color":"#0A1628"},{"range":[40,70],"color":"#0D1B2E"},{"range":[70,100],"color":"#111827"}],
               "threshold":{"line":{"color":clr,"width":3},"thickness":0.8,"value":score}},
        number={"suffix":"/100","font":{"size":28,"color":clr}},
    ))
    fig.update_layout(height=150, margin=dict(t=10,b=10,l=10,r=10), paper_bgcolor="rgba(0,0,0,0)", font_color="#C8DCEF")
    st.plotly_chart(fig, width="stretch", config={"displayModeBar":False}, key=key)

# ── Estado de sesión ──────────────────────────────────────
for k, v in {"running":False,"log_lines":[],"audit_result":None,"error":None,"progress":0}.items():
    if k not in st.session_state: st.session_state[k] = v

# ── Worker ────────────────────────────────────────────────
def _audit_worker(raw_targets: list[str], skip_nmap: bool, all_ports: bool, msg_queue: queue.Queue):
    def l(icon, msg, lvl="default"): msg_queue.put(("log", icon, msg, lvl))
    def s(desc, pct):               msg_queue.put(("step", desc, pct))

    try:
        s("Validando entradas...", 5)
        l("🔍", f"Recibidas {len(raw_targets)} entrada(s)...", "info")

        # Expandir cada target a (host, port) según catálogo
        endpoints = []
        for t in raw_targets:
            raw_host = t.split(":")[0] if ":" in t else t
            if not is_valid_target(raw_host):
                l("⚠️", f"Formato incorrecto: '{t}', saltando.", "warning")
                continue
            if ":" in t:
                endpoints.append((raw_host, int(t.split(":")[1])))
            elif all_ports:
                for p in ALL_AUDIT_PORTS:
                    endpoints.append((raw_host, p))
                l("📋", f"{raw_host} → {len(ALL_AUDIT_PORTS)} puertos del catálogo", "info")
            else:
                endpoints.append((raw_host, 443))

        if not endpoints:
            msg_queue.put(("error", "Sin objetivos válidos.")); return

        l("🚀", f"Total endpoints a escanear: {len(endpoints)}", "info")

        mod_tls      = _load_module("02_tls_scanner")
        mod_nmap     = _load_module("03_nmap_scanner")
        mod_crypto   = _load_module("04_crypto_analyzer")
        mod_risk     = _load_module("05_risk_evaluator")
        mod_reporter = _load_module("06_reporter")

        from concurrent.futures import ThreadPoolExecutor, as_completed

        # ── Pre-filtro TCP (paralelo, 0.8s por puerto) ────────────────
        s("Filtrando puertos activos...", 8)
        l("📡", f"Pre-scan TCP: verificando {len(endpoints)} endpoint(s)...", "info")

        open_endpoints = []
        with ThreadPoolExecutor(max_workers=30) as ex:
            future_tcp = {ex.submit(_tcp_open, h, p): (h, p) for h, p in endpoints}
            for ft in as_completed(future_tcp):
                h, p = future_tcp[ft]
                if ft.result():
                    open_endpoints.append((h, p))
                else:
                    msg_queue.put(("log", "⛔", f"Puerto cerrado/filtrado: {h}:{p}", "warning"))

        if not open_endpoints:
            msg_queue.put(("error", "Ningún puerto respondió al TCP pre-scan. Verifique la conectividad."))
            return

        l("✅", f"{len(open_endpoints)}/{len(endpoints)} puertos activos. Descartados: {len(endpoints)-len(open_endpoints)}", "success")
        endpoints = open_endpoints  # solo escanear los que responden

        # ── Fase 1: TLS + Crypto en PARALELO ─────────────────────────
        s(f"TLS/Crypto paralelo — {len(endpoints)} endpoint(s)...", 20)
        l("🔒", f"Lanzando {len(endpoints)} escaneo(s) TLS en paralelo (máx 10 hilos)...", "info")

        tls_results    = {}
        crypto_results = {}
        done_count     = [0]  # lista para mutabilidad en closure

        def _tls_worker(host, port):
            tls    = mod_tls.scan_target(host, port)
            crypto = mod_crypto.analyze_target(host, port)
            return (host, port), tls, crypto

        with ThreadPoolExecutor(max_workers=10) as ex:
            future_tls = {ex.submit(_tls_worker, h, p): (h, p) for h, p in endpoints}
            for ft in as_completed(future_tls):
                h, p = future_tls[ft]
                try:
                    (host, port), tls, crypto = ft.result()
                    tls_results[(host, port)]    = tls
                    crypto_results[(host, port)] = crypto
                    done_count[0] += 1
                    pct = 20 + int((done_count[0] / len(endpoints)) * 35)
                    s(f"TLS [{done_count[0]}/{len(endpoints)}] {host}:{port}", pct)
                    has_err = "error" in tls
                    msg_queue.put(("log", "🔒", f"TLS {'⚠️' if has_err else '✅'} {host}:{port}",
                                   "warning" if has_err else "success"))
                except Exception as exc:
                    msg_queue.put(("log", "❌", f"Error TLS {h}:{p} — {exc}", "error"))

        l("✅", f"TLS/Crypto completado para {len(tls_results)} endpoint(s)", "success")

        # ── Fase 2: Nmap en paralelo ──────────────────────────────────
        nmap_results = {}
        if not skip_nmap:
            s(f"Nmap paralelo — {len(endpoints)} endpoint(s)...", 60)
            l("🗺️", f"Lanzando Nmap en paralelo para {len(endpoints)} endpoint(s) (máx 6 hilos)...", "info")

            def _nmap_callback(host, port, result):
                status = "✅" if "error" not in result else "⚠️"
                vulns  = result.get("vulnerabilities", [])
                msg    = f"Nmap {status} {host}:{port}"
                if vulns:
                    msg += f" — {len(vulns)} vuln(s): {', '.join(v['name'] for v in vulns)}"
                msg_queue.put(("log", "🗺️", msg, "success" if "error" not in result else "warning"))

            nmap_results = mod_nmap.scan_targets_parallel(
                targets=endpoints, quick=False, max_workers=6, on_result=_nmap_callback,
            )
            l("✅", f"Nmap finalizado — {len(nmap_results)} endpoint(s)", "success")
        else:
            l("⏭️", "Nmap omitido (Modo Rápido activo)", "warning")

        # ── Fase 3: Evaluación de riesgo ──────────────────────────────
        s("Evaluando riesgos...", 90)
        evaluations = []
        for host, port in endpoints:
            ev = mod_risk.evaluate_host(
                host, port,
                tls_results.get((host, port)),
                nmap_results.get((host, port)),
                crypto_results.get((host, port)),
            )
            ev["tls_raw"]    = tls_results.get((host, port), {})
            ev["crypto_raw"] = crypto_results.get((host, port), {})
            evaluations.append(ev)
            l("✅", f"{host}:{port} → Score: {ev['risk_score']}/100 [{ev['risk_level']}]", "success")

        s("Generando reportes...", 95)
        audit_data = {
            "timestamp":   datetime.datetime.now().isoformat(),
            "evaluations": evaluations,
            "comparison":  mod_risk.compare_hosts(evaluations),
        }
        audit_data["reports"] = mod_reporter.generate_reports(audit_data, ["all"], os.path.join(ROOT_DIR, "reports"))
        l("🎉", f"Auditoría completa — {len(evaluations)} endpoint(s) analizados", "success")
        msg_queue.put(("result", audit_data))

    except Exception as e:
        import traceback
        msg_queue.put(("error", f"{e}\n{traceback.format_exc()}"))
    finally:
        msg_queue.put(("done",))


# ── Gestión de Estado de Sesión ──────────────────────────
def _init_session_state():
    """Inicializa claves de sesión solo si no existen todavía."""
    defaults = {
        "running":      False,
        "log_lines":    [],
        "audit_result": None,
        "error":        None,
        "progress":     0,
        "last_targets": "",
    }
    for clave, valor in defaults.items():
        if clave not in st.session_state:
            st.session_state[clave] = valor

def _reset_results():
    """Borra todos los resultados previos para dejar la pantalla limpia."""
    st.session_state.audit_result = None
    st.session_state.log_lines    = []
    st.session_state.error        = None
    st.session_state.progress     = 0


def main():
    _init_session_state()
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    st.markdown("""
    <div class="tls-header">
        <h1>🔐 TLS Auditor</h1>
        <p>Análisis profesional de configuración TLS/SSL y riesgo criptográfico</p>
    </div>""", unsafe_allow_html=True)

    # ── Panel de entrada ──────────────────────────────────
    c_input, c_opts = st.columns([3, 1])

    with c_input:
        st.markdown('<div class="input-card">', unsafe_allow_html=True)
        raw_input = st.text_area(
            "🌐 Dominios / IPs", height=120, key="raw_in",
            placeholder="google.com\ngithub.com\n1.1.1.1\nmyserver.com:8443",
            disabled=st.session_state.running
        )
        st.markdown('</div>', unsafe_allow_html=True)

    with c_opts:
        st.markdown('<div class="input-card">', unsafe_allow_html=True)
        st.markdown("**⚙️ Opciones**")
        skip_nmap = st.checkbox("⚡ Modo Rápido (sin Nmap)", value=True, disabled=st.session_state.running)
        all_ports = st.checkbox(
            "🔌 Escanear todos los puertos",
            value=False,
            help=f"Revisa los {len(ALL_AUDIT_PORTS)} puertos del catálogo (Legacy, Standard, Modern)",
            disabled=st.session_state.running
        )
        if all_ports:
            st.markdown(f'<div style="font-size:10px;color:#64A0D4;margin-top:4px">{len(ALL_AUDIT_PORTS)} puertos × cada host</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    btn_label = "⏳ Analizando..." if st.session_state.running else "🚀 Iniciar Auditoría"
    if st.button(btn_label, disabled=st.session_state.running, use_container_width=True):
        if not st.session_state.running:   # guard: evita doble ejecución por re-render
            targets = [t.strip() for t in re.split(r'[,\n;]+', raw_input) if t.strip()]
            if not targets:
                st.warning("⚠️ Ingresa al menos un servidor.")
                return

            # ── Marcar como running PRIMERO para bloquear el botón ────
            st.session_state.running      = True
            st.session_state.last_targets = raw_input.strip()
            # ── Limpiar resultados anteriores ─────────────────────────
            st.session_state.audit_result = None
            st.session_state.log_lines    = []
            st.session_state.error        = None
            st.session_state.progress     = 0

            q = queue.Queue()
            threading.Thread(target=_audit_worker, args=(targets, skip_nmap, all_ports, q), daemon=True).start()
            st.session_state._queue = q  # guardar queue en session_state para el loop

    # ── Loop de progreso (corre siempre que running=True) ─────────
    if st.session_state.running:
        q = st.session_state.get("_queue")
        spinner_ph = st.empty(); prog_ph = st.empty(); log_ph = st.empty()

        while st.session_state.running and q:
            try:
                while True:
                    msg = q.get_nowait()
                    if msg[0] == "log":
                        ts = datetime.datetime.now().strftime("%H:%M:%S")
                        st.session_state.log_lines.append((ts, msg[1], msg[2], msg[3]))
                    elif msg[0] == "step":
                        spinner_ph.info(f"🔄 {msg[1]}")
                        prog_ph.progress(msg[2] / 100)
                    elif msg[0] == "result": st.session_state.audit_result = msg[1]
                    elif msg[0] == "error":  st.session_state.error = msg[1]
                    elif msg[0] == "done":   st.session_state.running = False
            except queue.Empty: pass

            level_colors = {"success":"#34D399","error":"#F87171","warning":"#FBBF24","info":"#60A5FA","default":"#7AB3D4"}
            rows = "".join([
                f'<div class="log-entry"><span class="log-time">{ts}</span><span>{ic}</span>'
                f'<span style="color:{level_colors.get(lv,"#7AB3D4")}">{mg}</span></div>'
                for ts, ic, mg, lv in st.session_state.log_lines[-15:]
            ])
            log_ph.markdown(f'<div class="progress-box">{rows}</div>', unsafe_allow_html=True)
            time.sleep(0.15)

        st.rerun()


    # ── Botón limpiar (solo visible cuando hay resultados) ────────
    if st.session_state.get("audit_result") and not st.session_state.running:
        if st.button("🔄 Limpiar y hacer nueva auditoría", use_container_width=True):
            _reset_results()
            st.rerun()

    # ── Errores ───────────────────────────────────────────
    if st.session_state.error:
        st.error(f"❌ {st.session_state.error}")

    # ── Resultados ────────────────────────────────────────
    if st.session_state.audit_result:
        data = st.session_state.audit_result
        evs  = data.get("evaluations", [])
        if not evs: return

        # Resumen
        st.markdown("---")
        m1, m2, m3, m4 = st.columns(4)
        avg = sum(e["risk_score"] for e in evs) // len(evs)
        for col, val, lbl, clr in [
            (m1, len(evs),                              "Endpoints",     "#60A5FA"),
            (m2, sum(1 for e in evs if e["risk_level"] in ("CRITICAL","HIGH")), "En riesgo", "#F87171"),
            (m3, sum(1 for e in evs if e["risk_level"] in ("OK","LOW")),         "Seguros",   "#34D399"),
            (m4, f"{avg}/100",                          "Score medio",   "#FBBF24"),
        ]:
            with col:
                st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:{clr}">{val}</div><div class="metric-lbl">{lbl}</div></div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Tabla Comparativa ─────────────────────────────
        if len(evs) >= 1:
            st.markdown('<div class="section-title">📊 Comparativa entre Servidores</div>', unsafe_allow_html=True)

            ALL_PROTOS = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]

            # Cabecera de la tabla
            header_cols = st.columns([2] + [1]*len(evs))
            header_cols[0].markdown('<div style="color:#64A0D4;font-size:11px;font-weight:600;padding:6px 0">CARACTERÍSTICA</div>', unsafe_allow_html=True)
            for i, ev in enumerate(evs):
                clr, _ = RISK_COLORS.get(ev["risk_level"], ("#6B7280","#111827"))
                header_cols[i+1].markdown(
                    f'<div style="text-align:center;font-size:10px;font-family:JetBrains Mono;color:{clr};font-weight:700;padding:4px 2px">'
                    f'{ev["host"]}<br>:{ev["port"]}</div>', unsafe_allow_html=True
                )

            st.markdown('<div style="height:1px;background:#1E3A5F40;margin:4px 0"></div>', unsafe_allow_html=True)

            # Fila: Score de riesgo
            row = st.columns([2] + [1]*len(evs))
            row[0].markdown('<div style="color:#7AB3D4;font-size:12px;padding:6px 0">⚖️ Score de Riesgo</div>', unsafe_allow_html=True)
            for i, ev in enumerate(evs):
                clr, _ = RISK_COLORS.get(ev["risk_level"], ("#6B7280","#111827"))
                row[i+1].markdown(f'<div style="text-align:center;font-size:13px;font-weight:700;color:{clr}">{ev["risk_score"]}/100</div>', unsafe_allow_html=True)

            # Filas: Protocolos
            for proto in ALL_PROTOS:
                row = st.columns([2] + [1]*len(evs))
                is_obs = proto in OBSOLETE_PROTO
                row[0].markdown(f'<div style="color:#{"F87171" if is_obs else "7AB3D4"};font-size:12px;padding:4px 0">{"⚠️" if is_obs else "🔒"} {proto}</div>', unsafe_allow_html=True)
                for i, ev in enumerate(evs):
                    protos  = ev["tls_raw"].get("protocols", {})
                    srt     = protos.get(proto, {}).get("supported")
                    if srt is True:
                        icon, clr_cell = ("🔴 SÍ", "#F87171") if is_obs else ("✅ SÍ", "#34D399")
                    elif srt is False:
                        icon, clr_cell = ("✓ NO", "#34D399") if is_obs else ("— NO", "#374151")
                    else:
                        icon, clr_cell = "❓ ?", "#FBBF24"
                    row[i+1].markdown(f'<div style="text-align:center;font-size:11px;color:{clr_cell};font-family:JetBrains Mono">{icon}</div>', unsafe_allow_html=True)

            # Fila: Certificado confiable
            row = st.columns([2] + [1]*len(evs))
            row[0].markdown('<div style="color:#7AB3D4;font-size:12px;padding:4px 0">📜 Cert. Confiable</div>', unsafe_allow_html=True)
            for i, ev in enumerate(evs):
                certs   = ev["tls_raw"].get("certificates", [])
                trusted = certs[0].get("trusted", False) if certs else False
                row[i+1].markdown(
                    f'<div style="text-align:center;font-size:12px;color:{"#34D399" if trusted else "#F87171"}">'
                    f'{"✅ Sí" if trusted else "❌ No"}</div>', unsafe_allow_html=True
                )

            # Fila: TLS 1.3
            row = st.columns([2] + [1]*len(evs))
            row[0].markdown('<div style="color:#7AB3D4;font-size:12px;padding:4px 0">🏆 TLS 1.3 Moderno</div>', unsafe_allow_html=True)
            for i, ev in enumerate(evs):
                protos = ev["tls_raw"].get("protocols", {})
                has13  = protos.get("TLS 1.3", {}).get("supported") is True
                row[i+1].markdown(
                    f'<div style="text-align:center;font-size:12px;color:{"#34D399" if has13 else "#F87171"}">'
                    f'{"✅ Sí" if has13 else "❌ No"}</div>', unsafe_allow_html=True
                )

            # Fila: Vencimiento del certificado
            row = st.columns([2] + [1]*len(evs))
            row[0].markdown('<div style="color:#7AB3D4;font-size:12px;padding:4px 0">⏳ Cert. Vence en</div>', unsafe_allow_html=True)
            for i, ev in enumerate(evs):
                certs = ev["tls_raw"].get("certificates", [])
                if certs:
                    cert   = certs[0]
                    days   = cert.get("days_remaining")
                    expired = cert.get("expired", False)
                    if expired or (days is not None and days <= 0):
                        label, clr_cell, bg = "💀 EXPIRADO", "#F87171", "#2D0A0A"
                    elif days is not None and days < 7:
                        label, clr_cell, bg = f"🔴 {days}d", "#F87171", "#2D0A0A"
                    elif days is not None and days < 30:
                        label, clr_cell, bg = f"🟠 {days}d", "#FB923C", "#1F1500"
                    elif days is not None and days < 90:
                        label, clr_cell, bg = f"🟡 {days}d", "#FCD34D", "#201405"
                    else:
                        label, clr_cell, bg = f"✅ {days}d", "#34D399", "#0A1F14"
                else:
                    label, clr_cell, bg = "❓ N/D", "#FBBF24", "#111827"

                row[i+1].markdown(
                    f'<div style="text-align:center;font-size:11px;font-weight:600;color:{clr_cell};'
                    f'background:{bg};border-radius:5px;padding:3px 4px;font-family:JetBrains Mono">'
                    f'{label}</div>', unsafe_allow_html=True
                )

            st.markdown("<br>", unsafe_allow_html=True)

        # ── Recomendaciones para el Usuario Final ───────────────
        all_findings_map: dict = {}
        for ev in evs:
            for f in ev.get("findings", []):
                fid = f["id"]
                if fid not in all_findings_map:
                    all_findings_map[fid] = {"finding": f, "hosts": []}
                all_findings_map[fid]["hosts"].append(f"{ev['host']}:{ev['port']}")

        SEV_ORDER   = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_recs = sorted(all_findings_map.values(), key=lambda x: SEV_ORDER.get(x["finding"]["severity"], 9))

        # Informe para cliente final: (título, qué es, impacto negocio, qué pedirle al desarrollador)
        USER_FRIENDLY = {
            "PROTO_SSL_20": (
                "Su servidor usa un protocolo de seguridad del año 1995",
                "El cifrado SSL 2.0 fue roto por investigadores hace décadas. Cualquier persona con acceso a la red puede leer la información que sus clientes envían (contraseñas, datos personales).",
                "Si un cliente o auditor escanea su sitio, verá tecnología obsoleta de hace 30 años. Esto genera pérdida de confianza inmediata y puede incumplir normativas.",
                "Dígale a su proveedor de hosting: «Deshabiliten SSL 2.0 en el servidor web. No debe aparecer en ninguna configuración activa.»"
            ),
            "PROTO_SSL_30": (
                "Su servidor es vulnerable a un ataque conocido desde 2014 (POODLE)",
                "SSL 3.0 tiene una vulnerabilidad llamada POODLE que permite a un atacante interceptar y leer conversaciones cifradas entre su servidor y sus usuarios.",
                "Esta vulnerabilidad tiene herramientas automáticas para explotarla. Es como dejar la puerta trasera de su negocio abierta.",
                "Dígale a su proveedor: «Deshabiliten SSL 3.0 en el servidor. Hay un exploit público (CVE-2014-3566) que lo hace peligroso.»"
            ),
            "PROTO_TLS10": (
                "Protocolo de seguridad obsoleto activo — TLS 1.0",
                "TLS 1.0 fue oficialmente retirado en 2021. Chrome, Firefox y Safari ya no lo recomiendan. Su servidor acepta conexiones menos seguras de las necesarias.",
                "Organismos como PCI-DSS (pagos con tarjeta) prohíben TLS 1.0 explícitamente. Si procesa pagos en línea, podría estar fuera de cumplimiento regulatorio.",
                "Dígale a su desarrollador: «Deshabiliten TLS 1.0 y dejen solo TLS 1.2 y TLS 1.3. Aquí está el estándar de referencia: RFC 8996.»"
            ),
            "PROTO_TLS11": (
                "Protocolo de seguridad desactualizado activo — TLS 1.1",
                "TLS 1.1 también fue retirado en 2021. No soporta los algoritmos de cifrado modernos y expone al servidor a ataques de degradación de protocolo.",
                "Los navegadores modernos marcan sitios con TLS 1.1 como 'conexión no completamente segura'. Sus usuarios pueden ver advertencias al visitar el sitio.",
                "Dígale a su desarrollador: «Deshabiliten TLS 1.1. Solo deben estar activos TLS 1.2 y TLS 1.3.»"
            ),
            "PROTO_TLS13_MISSING": (
                "Su servidor no usa la versión más segura disponible — TLS 1.3",
                "TLS 1.3 es la versión más moderna del cifrado web. Es más rápida y tiene mejores protecciones. Su servidor no la ofrece a sus usuarios.",
                "Sus competidores que sí la tienen tienen ventaja en velocidad y seguridad. Algunos escáneres de seguridad penalizan su ausencia en reportes de auditoría.",
                "Dígale a su desarrollador: «Habiliten TLS 1.3 en el servidor. No requiere cambios en los certificados y mejora velocidad y seguridad automáticamente.»"
            ),
            "PROTO_NO_SECURE": (
                "Su servidor no tiene cifrado seguro funcional",
                "No se encontró ninguna versión segura de TLS. Toda la información que pase por este servidor puede ser interceptada en texto plano.",
                "Este es el peor escenario posible. Cualquier usuario en la misma red puede leer los datos de sus clientes sin herramientas especiales.",
                "Dígale a su proveedor de hosting: «El servidor no tiene TLS configurado. Necesitan instalar un certificado SSL/TLS y habilitar TLS 1.2 y TLS 1.3 urgentemente.»"
            ),
            "CERT_UNTRUSTED": (
                "El candado de seguridad del sitio no es reconocido por los navegadores",
                "El certificado fue creado internamente, no por una entidad de confianza. Los navegadores muestran un error de seguridad a sus visitantes antes de dejarlos entrar.",
                "El 85% de los usuarios abandona un sitio web cuando ve un error de seguridad. Esto afecta directamente sus ventas y la confianza de sus clientes.",
                "Dígale a su desarrollador: «Necesitamos un certificado SSL de una autoridad reconocida. Let's Encrypt es gratuito y automático. También sirven Sectigo o DigiCert.»"
            ),
            "CERT_EXPIRED": (
                "El certificado de seguridad del sitio está vencido",
                "El certificado venció. Los navegadores muestran una página de error completa antes de permitir el acceso. La mayoría de usuarios no continuará.",
                "Con un certificado vencido, su sitio está efectivamente fuera de servicio para usuarios normales. Cualquier dato transmitido ya no está protegido.",
                "Dígale a su proveedor AHORA: «El certificado SSL está vencido. Renóvenlo de inmediato. Si usan Let's Encrypt, ejecuten: certbot renew»"
            ),
            "CERT_EXPIRING_SOON": (
                "El certificado de seguridad está próximo a vencer",
                "En pocos días el certificado expirará. Cuando eso pase, los usuarios verán un error de seguridad y no podrán acceder al sitio.",
                "Si no se renueva a tiempo, su sitio será inaccesible para usuarios normales, generando pérdida de ventas y daño a la reputación de su marca.",
                "Dígale a su desarrollador: «El certificado SSL vence pronto. Renuévenlo antes de que expire y configuren renovación automática para evitar este problema.»"
            ),
            "CERT_UNAVAILABLE": (
                "No se pudo verificar el certificado de seguridad",
                "El sistema no pudo obtener información del certificado. Puede indicar que el servidor no tiene TLS configurado o que hay un error en la instalación.",
                "Sin un certificado funcional, los usuarios ven advertencias de seguridad y el sitio no aparece como seguro en los resultados de búsqueda de Google.",
                "Dígale a su desarrollador: «Verifiquen que el certificado SSL está instalado correctamente y que el servidor responde en el puerto 443.»"
            ),
            "CERT_LONG_LIVED": (
                "El certificado tiene una fecha de validez demasiado larga",
                "El certificado fue emitido con una vigencia mayor a la permitida (~2 años). Los navegadores modernos pueden rechazarlo o marcarlo como no confiable.",
                "Apple, Google y Mozilla establecieron que los certificados deben renovarse frecuentemente. Un certificado de vida larga es señal de mala práctica de seguridad.",
                "Dígale a su desarrollador: «Reemplacen este certificado por uno con vigencia máxima de 1 año. Lo ideal es renovación automática cada 90 días con Let's Encrypt.»"
            ),
            "CRYPTO_WEAK_KEY": (
                "La clave de cifrado del certificado es demasiado corta",
                "El certificado usa una clave criptográfica que, con computadoras modernas, podría ser factible de romper en el futuro.",
                "Una clave débil es como una contraseña de 4 dígitos. Si se rompe, toda la comunicación histórica con sus usuarios quedaría expuesta.",
                "Dígale a su desarrollador: «Generen un nuevo certificado con clave RSA de al menos 2048 bits, o mejor aún, usen ECDSA P-256.»"
            ),
            "CRYPTO_WEAK_SIGNATURE": (
                "El certificado usa un algoritmo de firma anticuado",
                "El certificado está firmado con SHA-1 o MD5, algoritmos que fueron rotos. Chrome, Firefox y Safari los marcan como no confiables.",
                "Un certificado con firma débil puede ser falsificado. Un atacante podría crear un certificado falso de su dominio para engañar a sus usuarios.",
                "Dígale a su desarrollador: «El certificado debe ser reemplazado por uno firmado con SHA-256 o SHA-384. La mayoría de proveedores lo usan por defecto hoy.»"
            ),
        }

        if sorted_recs:
            st.markdown("---")
            has_critical = any(item["finding"]["severity"] in ("CRITICAL","HIGH") for item in sorted_recs)
            header_clr   = "#F87171" if has_critical else "#FBBF24"
            header_bg    = "#1A0505" if has_critical else "#12100A"
            header_icon  = "🚨" if has_critical else "⚠️"
            n_critical   = sum(1 for item in sorted_recs if item["finding"]["severity"] == "CRITICAL")
            n_high       = sum(1 for item in sorted_recs if item["finding"]["severity"] == "HIGH")
            n_medium     = sum(1 for item in sorted_recs if item["finding"]["severity"] == "MEDIUM")

            # ── Encabezado del informe ─────────────────────────────
            badges = ""
            if n_critical: badges += f'<span style="background:#F8717120;color:#F87171;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600">🔴 {n_critical} Críticos</span> '
            if n_high:     badges += f'<span style="background:#FB923C20;color:#FB923C;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600">🟠 {n_high} Altos</span> '
            if n_medium:   badges += f'<span style="background:#FCD34D20;color:#FCD34D;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600">🟡 {n_medium} Medios</span>'

            st.markdown(f"""
            <div style="background:{header_bg};border:2px solid {header_clr}50;border-radius:16px;padding:28px 32px;margin:20px 0">
                <div style="font-size:1.35rem;font-weight:800;color:{header_clr};margin-bottom:12px">
                    {header_icon} Informe de Seguridad para el Cliente
                </div>
                <div style="color:#C8DCEF;font-size:14px;line-height:1.8;margin-bottom:16px">
                    El análisis de sus servidores detectó
                    <b style="color:{header_clr}">{len(sorted_recs)} problema(s) de seguridad</b>
                    {f'— de los cuales <b style="color:#F87171">{n_critical} son críticos</b>' if n_critical else ''}
                    {f'y <b style="color:#FB923C">{n_high} de alta prioridad</b>' if n_high else ''}.
                    A continuación encontrará una explicación en lenguaje claro de cada problema,
                    su impacto en su negocio y la acción exacta que debe pedirle a su equipo técnico.
                </div>
                <div style="display:flex;gap:10px;flex-wrap:wrap">{badges}</div>
            </div>""", unsafe_allow_html=True)

            # ── Una tarjeta por hallazgo ───────────────────────────
            for idx, item in enumerate(sorted_recs, 1):
                hallazgo        = item["finding"]
                hosts_afectados = item["hosts"]
                sev             = hallazgo["severity"]
                fid             = hallazgo["id"]
                clr, dark       = RISK_COLORS.get(sev, ("#6B7280","#111827"))
                icon            = SEVERITY_ICONS.get(sev, "•")
                sev_label       = {"CRITICAL":"Crítico","HIGH":"Alto","MEDIUM":"Medio","LOW":"Bajo","INFO":"Info"}.get(sev, sev)

                uf = USER_FRIENDLY.get(fid)
                if uf:
                    titulo, que_es, impacto, que_pedir = uf
                else:
                    titulo    = hallazgo["title"]
                    que_es    = hallazgo["description"]
                    impacto   = "Este problema puede afectar la seguridad y confianza de su servicio."
                    que_pedir = hallazgo["recommendation"]

                hosts_html = " ".join([
                    f'<code style="background:#1E293B;color:#93C5FD;padding:2px 8px;border-radius:4px;font-size:11px">{h}</code>'
                    for h in hosts_afectados
                ])

                st.markdown(f"""
                <div style="background:{dark};border-left:5px solid {clr};border-radius:0 14px 14px 0;
                            padding:22px 26px;margin:14px 0;border:1px solid {clr}15;border-left:5px solid {clr}">
                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap">
                        <span style="font-size:1.3rem">{icon}</span>
                        <span style="font-size:15px;font-weight:700;color:#F0F6FF;flex:1">{idx}. {titulo}</span>
                        <span style="background:{clr};color:white;padding:3px 12px;border-radius:20px;font-size:11px;font-weight:700">{sev_label}</span>
                    </div>
                    <div style="background:#07111F;border-radius:10px;padding:14px 16px;margin-bottom:10px">
                        <div style="font-size:10px;color:#64A0D4;font-weight:700;letter-spacing:1px;margin-bottom:6px">🔍 RIESGO IDENTIFICADO</div>
                        <div style="font-size:13px;color:#C8DCEF;line-height:1.7">{que_es}</div>
                    </div>
                    <div style="background:#130A00;border-radius:10px;padding:14px 16px;margin-bottom:10px;border:1px solid #EA580C15">
                        <div style="font-size:10px;color:#FB923C;font-weight:700;letter-spacing:1px;margin-bottom:6px">💼 IMPACTO EN SU NEGOCIO</div>
                        <div style="font-size:13px;color:#FED7AA;line-height:1.7">{impacto}</div>
                    </div>
                    <div style="background:#071A10;border-radius:10px;padding:14px 16px;border:1px solid #16A34A20">
                        <div style="font-size:10px;color:#34D399;font-weight:700;letter-spacing:1px;margin-bottom:6px">✅ QUÉ PEDIRLE A SU DESARROLLADOR</div>
                        <div style="font-size:13px;color:#A7F3D0;line-height:1.7;font-style:italic">"{que_pedir}"</div>
                    </div>
                    <div style="margin-top:10px;font-size:11px;color:#2D4A6B">Detectado en: {hosts_html}</div>
                </div>""", unsafe_allow_html=True)

            # ── Cierre: pasos a seguir ─────────────────────────────
            st.markdown("""
            <div style="background:#071A10;border:1px solid #16A34A30;border-radius:12px;padding:22px 26px;margin:20px 0">
                <div style="font-size:14px;font-weight:700;color:#34D399;margin-bottom:10px">
                    📋 Próximos pasos recomendados
                </div>
                <div style="font-size:13px;color:#A7F3D0;line-height:2">
                    1. Comparta este informe con su equipo técnico o proveedor de hosting.<br>
                    2. Priorice los problemas <b style="color:#F87171">Críticos</b> — deben resolverse en menos de 48 horas.<br>
                    3. Los problemas <b style="color:#FB923C">Altos</b> deben resolverse en los próximos 7 días.<br>
                    4. Solicite una nueva auditoría tras aplicar los cambios para confirmar que todo fue corregido.<br>
                    5. Configure alertas de renovación de certificados para evitar vencimientos inesperados.
                </div>
            </div>""", unsafe_allow_html=True)

        # Tabs por host
        tab_labels = [f"{e['host']}:{e['port']} {SEVERITY_ICONS.get(e['risk_level'],'')}" for e in evs]
        tabs = st.tabs(tab_labels)
        for tab, ev in zip(tabs, evs):
            with tab:
                host, port = ev["host"], ev["port"]
                clr, dark  = RISK_COLORS.get(ev["risk_level"], ("#6B7280","#111827"))

                # Header tarjeta
                risk_level_label = ev["risk_level"]
                total_findings   = ev["total_findings"]
                st.markdown(f"""
                <div style="background:{dark};border-left:4px solid {clr};padding:18px 22px;border-radius:12px;margin-bottom:12px">
                    <span style="font-family:'JetBrains Mono';font-size:1.1rem;font-weight:700;color:#E0EEFF">{host}:{port}</span>
                    <span style="float:right;background:{clr};color:white;padding:3px 12px;border-radius:6px;font-weight:700">{risk_level_label}</span>
                    <div style="font-size:12px;color:#64A0D4;margin-top:4px">{total_findings} hallazgo(s)</div>
                </div>""", unsafe_allow_html=True)

                col1, col2 = st.columns([3, 2])

                with col1:
                    # Protocolos
                    st.markdown('<div class="section-title">Protocolos TLS/SSL</div>', unsafe_allow_html=True)
                    protos = ev["tls_raw"].get("protocols", {})
                    pills  = "".join([proto_pill_html(p, d.get("supported")) for p, d in protos.items()])
                    st.markdown(f'<div style="background:#07111F;padding:12px;border-radius:8px">{pills}</div>', unsafe_allow_html=True)

                    # Cert lifecycle
                    certs = ev["tls_raw"].get("certificates", [])
                    if certs:
                        c = certs[0]; days = c.get("days_remaining", 0); pct = c.get("percentage_elapsed", 0)
                        d_clr = "#F87171" if days < 30 else ("#FBBF24" if days < 90 else "#34D399")
                        st.markdown(f"""
                        <div style="background:#07111F;padding:14px;border-radius:10px;margin-top:10px">
                            <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:6px">
                                <span style="color:#64A0D4">📜 Ciclo de vida del certificado</span>
                                <span style="color:{d_clr};font-weight:600">{'EXPIRADO' if c.get('expired') else f'Vence en {days} días'}</span>
                            </div>
                            <div style="width:100%;height:6px;background:#1E293B;border-radius:3px">
                                <div style="width:{pct}%;height:100%;background:linear-gradient(90deg,#3B82F6,{d_clr});border-radius:3px"></div>
                            </div>
                            <div style="display:flex;justify-content:space-between;margin-top:6px;font-size:10px;color:#2D4A6B">
                                <span>Desde: {str(c.get('not_before','N/A'))[:10]}</span>
                                <span>{pct}% transcurrido</span>
                                <span>Hasta: {str(c.get('valid_until','N/A'))[:10]}</span>
                            </div>
                        </div>""", unsafe_allow_html=True)

                    # Hallazgos
                    if ev["findings"]:
                        st.markdown('<div class="section-title">Hallazgos</div>', unsafe_allow_html=True)
                        for f in ev["findings"]:
                            sev   = f.get("severity","INFO")
                            fcls  = FINDING_CLASS.get(sev,"finding-info")
                            ficon = SEVERITY_ICONS.get(sev,"•")
                            ftitle = f["title"]; fdesc = f["description"]; frec = f["recommendation"]
                            st.markdown(f"""
                            <div class="finding-item {fcls}">
                                <b>{ficon} {ftitle}</b>
                                <div style="color:#7AB3D4;margin-top:4px">{fdesc}</div>
                                <div style="color:#34D399;margin-top:4px;font-size:11px">→ {frec}</div>
                            </div>""", unsafe_allow_html=True)

                with col2:
                    risk_gauge(ev["risk_score"], ev["risk_level"], key=f"g_{host}_{port}")
                    # Conteo por severidad
                    sc = ev.get("severity_counts", {})
                    st.markdown('<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px">', unsafe_allow_html=True)
                    for sev, lbl, cc in [("CRITICAL","Crítico","#F87171"),("HIGH","Alto","#FB923C"),("MEDIUM","Medio","#FCD34D"),("LOW","Bajo","#60A5FA")]:
                        st.markdown(f"""
                        <div style="background:#07111F;border-radius:8px;padding:8px;text-align:center;border:1px solid {cc}30">
                            <div style="font-size:1.4rem;font-weight:700;color:{cc}">{sc.get(sev,0)}</div>
                            <div style="font-size:9px;color:#2D4A6B">{lbl}</div>
                        </div>""", unsafe_allow_html=True)
                    st.markdown('</div>', unsafe_allow_html=True)

        # ── Log persistente ───────────────────────────────
        if st.session_state.log_lines:
            with st.expander("📋 Log de ejecución completo"):
                level_colors = {"success":"#34D399","error":"#F87171","warning":"#FBBF24","info":"#60A5FA","default":"#7AB3D4"}
                rows = "".join([
                    f'<div class="log-entry"><span class="log-time">{ts}</span><span>{ic}</span>'
                    f'<span style="color:{level_colors.get(lv,"#7AB3D4")}">{mg}</span></div>'
                    for ts, ic, mg, lv in st.session_state.log_lines
                ])
                st.markdown(f'<div class="progress-box">{rows}</div>', unsafe_allow_html=True)

        # ── Descargas ─────────────────────────────────────
        rpts = data.get("reports", {})
        if rpts:
            st.markdown("---")
            st.markdown('<div class="section-title">Descargar Reportes</div>', unsafe_allow_html=True)
            dcols = st.columns(len(rpts))
            for (fmt, path), dcol in zip(rpts.items(), dcols):
                with dcol:
                    try:
                        with open(path, "r", encoding="utf-8") as f: content = f.read().encode("utf-8")
                        mime_map = {"json":"application/json","csv":"text/csv","html":"text/html","txt":"text/plain"}
                        st.download_button(f"⬇ {fmt.upper()}", data=content, file_name=os.path.basename(path),
                                           mime=mime_map.get(fmt,"text/plain"), use_container_width=True)
                    except Exception: pass


if __name__ == "__main__":
    main()

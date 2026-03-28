"""
06_reporter.py
--------------
Módulo de generación de reportes en múltiples formatos:
  - JSON   : datos estructurados para integración/GUI
  - CSV    : vista tabular para análisis en Excel / pandas
  - HTML   : reporte visual auto-contenido (sin dependencias externas)
  - TXT    : salida de consola estructurada

Uso standalone:
    python 06_reporter.py --input audit_data.json --format html
    python 06_reporter.py --input audit_data.json --format csv
    python 06_reporter.py --input audit_data.json --format all --out ./reports/
"""

import json
import csv
import os
import argparse
import datetime
from typing import Any

# ──────────────────────────────────────────────
#  Constantes de estilo (para HTML)
# ──────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "#DC2626",
    "HIGH":     "#EA580C",
    "MEDIUM":   "#CA8A04",
    "LOW":      "#2563EB",
    "INFO":     "#6B7280",
    "OK":       "#16A34A",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "ℹ️",
    "OK":       "✅",
}

RISK_BADGES = {
    "CRITICAL": ("CRÍTICO",  "#7F1D1D", "#FEF2F2"),
    "HIGH":     ("ALTO",     "#7C2D12", "#FFF7ED"),
    "MEDIUM":   ("MEDIO",    "#713F12", "#FEFCE8"),
    "LOW":      ("BAJO",     "#1E3A5F", "#EFF6FF"),
    "OK":       ("SEGURO",   "#14532D", "#F0FDF4"),
}


# ──────────────────────────────────────────────
#  Formato JSON
# ──────────────────────────────────────────────
def to_json(audit_data: dict, out_path: str) -> str:
    """Exporta el resultado completo a JSON."""
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(audit_data, f, indent=2, ensure_ascii=False, default=str)
    return out_path


# ──────────────────────────────────────────────
#  Formato CSV
# ──────────────────────────────────────────────
def to_csv(audit_data: dict, out_path: str) -> str:
    """
    Exporta los hallazgos a CSV (una fila por hallazgo por host).
    """
    rows = []
    evaluations = audit_data.get("evaluations", [])

    for ev in evaluations:
        host = ev.get("host", "")
        port = ev.get("port", 443)
        risk_level = ev.get("risk_level", "")
        risk_score = ev.get("risk_score", 0)

        if not ev.get("findings"):
            rows.append({
                "host": host, "port": port,
                "risk_score": risk_score, "risk_level": risk_level,
                "finding_id": "", "severity": "", "title": "",
                "description": "", "recommendation": "",
            })
        else:
            for finding in ev["findings"]:
                rows.append({
                    "host":           host,
                    "port":           port,
                    "risk_score":     risk_score,
                    "risk_level":     risk_level,
                    "finding_id":     finding.get("id", ""),
                    "severity":       finding.get("severity", ""),
                    "title":          finding.get("title", ""),
                    "description":    finding.get("description", ""),
                    "recommendation": finding.get("recommendation", ""),
                })

    fieldnames = [
        "host", "port", "risk_score", "risk_level",
        "finding_id", "severity", "title", "description", "recommendation"
    ]

    with open(out_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return out_path


# ──────────────────────────────────────────────
#  Formato HTML
# ──────────────────────────────────────────────
def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6B7280")
    return (
        f'<span style="background:{color};color:white;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:bold;">{severity}</span>'
    )


def _risk_badge(risk_level: str, score: int) -> str:
    label, text_color, bg_color = RISK_BADGES.get(
        risk_level, ("DESCONOCIDO", "#374151", "#F9FAFB")
    )
    return (
        f'<span style="background:{bg_color};color:{text_color};'
        f'padding:4px 12px;border-radius:6px;font-weight:bold;font-size:13px;">'
        f'{label} ({score}/100)</span>'
    )


def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return '<p style="color:#16A34A;font-weight:bold;">✅ Sin hallazgos críticos</p>'
    rows = ""
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "#6B7280")
        rows += f"""
        <tr>
          <td style="border-left:4px solid {color};padding-left:8px">
            {SEVERITY_ICONS.get(f["severity"], "")} {f.get("title", "")}
          </td>
          <td>{_severity_badge(f["severity"])}</td>
          <td style="color:#374151">{f.get("description", "")}</td>
          <td style="color:#1D4ED8"><em>{f.get("recommendation", "")}</em></td>
        </tr>"""
    return f"""
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead>
        <tr style="background:#F3F4F6">
          <th style="text-align:left;padding:8px">Hallazgo</th>
          <th style="padding:8px">Severidad</th>
          <th style="text-align:left;padding:8px">Descripción</th>
          <th style="text-align:left;padding:8px">Recomendación</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>"""


def _comparison_table(comparison: dict) -> str:
    if not comparison.get("ranking"):
        return ""
    rows = ""
    for row in comparison["ranking"]:
        risk = row.get("risk_level", "OK")
        color = SEVERITY_COLORS.get(risk, "#16A34A")
        icon = SEVERITY_ICONS.get(risk, "")
        rows += f"""
        <tr>
          <td style="font-weight:bold;padding:8px">#{row['rank']}</td>
          <td style="padding:8px">{row['host']}:{row['port']}</td>
          <td style="padding:8px">
            <span style="background:{color};color:white;padding:2px 10px;border-radius:4px">
              {icon} {row['risk_level']}
            </span>
          </td>
          <td style="padding:8px;font-weight:bold">{row['risk_score']}/100</td>
          <td style="padding:8px;color:#DC2626">{row.get('critical', 0)}</td>
          <td style="padding:8px;color:#EA580C">{row.get('high', 0)}</td>
          <td style="padding:8px;color:#CA8A04">{row.get('medium', 0)}</td>
        </tr>"""
    return f"""
    <h2 style="color:#1E293B;margin-top:40px">📊 Comparativa de Exposición</h2>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead>
        <tr style="background:#F3F4F6">
          <th style="padding:8px">#</th>
          <th style="text-align:left;padding:8px">Servidor</th>
          <th style="padding:8px">Nivel Riesgo</th>
          <th style="padding:8px">Score</th>
          <th style="padding:8px;color:#DC2626">Críticos</th>
          <th style="padding:8px;color:#EA580C">Altos</th>
          <th style="padding:8px;color:#CA8A04">Medios</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>"""


def to_html(audit_data: dict, out_path: str) -> str:
    """Genera un reporte HTML auto-contenido y estético."""
    ts = audit_data.get("timestamp", datetime.datetime.now().isoformat())
    evaluations = audit_data.get("evaluations", [])
    comparison  = audit_data.get("comparison", {})

    host_sections = ""
    for ev in evaluations:
        risk_level = ev.get("risk_level", "OK")
        border_color = SEVERITY_COLORS.get(risk_level, "#16A34A")
        badge_html = _risk_badge(risk_level, ev.get("risk_score", 0))
        findings_html = _findings_table(ev.get("findings", []))
        sc = ev.get("severity_counts", {})

        # Barra de protocolo (info del TLS scan)
        proto_bars = ""
        tls = ev.get("tls_raw", {})
        for proto, data in tls.get("protocols", {}).items():
            s = data.get("supported")
            color = "#16A34A" if s is False else (
                "#EA580C" if proto in {"TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0"}
                else "#16A34A"
            )
            label = "✅ Soportado" if s else ("❌ No soportado" if s is False else "⚠️ Error")
            proto_bars += (
                f'<span style="display:inline-block;margin:3px 6px 3px 0;'
                f'background:#F3F4F6;border:1px solid #E5E7EB;padding:4px 10px;'
                f'border-radius:20px;font-size:12px;">'
                f'<b>{proto}</b>: <span style="color:{color}">{label}</span></span>'
            )

        host_sections += f"""
        <div style="border:1px solid #E5E7EB;border-left:5px solid {border_color};
                    border-radius:8px;padding:24px;margin-bottom:28px;">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap">
            <h2 style="margin:0;color:#1E293B">
              🔍 {ev.get('host')}:{ev.get('port')}
            </h2>
            {badge_html}
          </div>
          <div style="margin-top:12px;color:#6B7280;font-size:13px">
            Hallazgos totales: <b>{ev.get('total_findings', 0)}</b> &nbsp;|&nbsp;
            🔴 Críticos: <b>{sc.get('CRITICAL', 0)}</b> &nbsp;
            🟠 Altos: <b>{sc.get('HIGH', 0)}</b> &nbsp;
            🟡 Medios: <b>{sc.get('MEDIUM', 0)}</b> &nbsp;
            🔵 Bajos: <b>{sc.get('LOW', 0)}</b>
          </div>
          <div style="margin-top:16px">{proto_bars}</div>
          <div style="margin-top:20px">{findings_html}</div>
        </div>"""

    comparison_html = _comparison_table(comparison)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reporte TLS Audit</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      max-width: 1200px; margin: 0 auto; padding: 32px;
      background: #F8FAFC; color: #1E293B;
    }}
    h1 {{ color: #0F172A; }}
    th {{ font-weight: 600; color: #374151; }}
    tr:hover {{ background: #F9FAFB; }}
    td, th {{ padding: 10px; vertical-align: top; border-bottom: 1px solid #E5E7EB; }}
    @media print {{
      body {{ max-width: 100%; padding: 16px; }}
    }}
  </style>
</head>
<body>
  <div style="background:linear-gradient(135deg,#1E293B,#0F172A);color:white;
              border-radius:12px;padding:32px;margin-bottom:32px;">
    <h1 style="margin:0;font-size:28px">🔐 Reporte de Auditoría TLS/SSL</h1>
    <p style="margin:8px 0 0;opacity:0.8">Generado: {ts}</p>
    <p style="margin:4px 0 0;opacity:0.7;font-size:13px">
      Servidores analizados: {len(evaluations)}
    </p>
  </div>

  {comparison_html}

  <h2 style="color:#1E293B;margin-top:40px">📋 Detalle por Servidor</h2>
  {host_sections}

  <div style="text-align:center;color:#9CA3AF;font-size:12px;margin-top:48px;
              border-top:1px solid #E5E7EB;padding-top:16px">
    TLS Auditor — Sistema de Análisis de Configuración TLS y Riesgo de Exposición
  </div>
</body>
</html>"""

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return out_path


# ──────────────────────────────────────────────
#  Formato TXT (consola estructurada)
# ──────────────────────────────────────────────
def to_txt(audit_data: dict, out_path: str) -> str:
    """Genera reporte en texto plano estructurado."""
    lines = []
    lines.append("=" * 65)
    lines.append("  REPORTE DE AUDITORÍA TLS/SSL")
    lines.append(f"  Fecha: {audit_data.get('timestamp', 'N/A')}")
    lines.append("=" * 65)

    for ev in audit_data.get("evaluations", []):
        lines.append(f"\n{'─'*65}")
        lines.append(f"  Servidor : {ev['host']}:{ev['port']}")
        lines.append(f"  Riesgo   : {ev['risk_level']} ({ev['risk_score']}/100)")
        sc = ev.get("severity_counts", {})
        lines.append(
            f"  Hallazgos: {ev['total_findings']} total  "
            f"| C:{sc.get('CRITICAL',0)} H:{sc.get('HIGH',0)} "
            f"M:{sc.get('MEDIUM',0)} L:{sc.get('LOW',0)}"
        )
        lines.append(f"{'─'*65}")

        for f in ev.get("findings", []):
            icon = SEVERITY_ICONS.get(f["severity"], "-")
            lines.append(f"\n  {icon} [{f['severity']}] {f['title']}")
            lines.append(f"     Descripción   : {f['description']}")
            lines.append(f"     Recomendación : {f['recommendation']}")

    comp = audit_data.get("comparison", {})
    if comp.get("ranking"):
        lines.append(f"\n{'='*65}")
        lines.append("  RANKING DE EXPOSICIÓN")
        lines.append(f"{'='*65}")
        for row in comp["ranking"]:
            lines.append(
                f"  #{row['rank']:2d}  {row['host']:<40}  "
                f"{row['risk_level']:<10}  {row['risk_score']}/100"
            )

    lines.append(f"\n{'='*65}\n")
    content = "\n".join(lines)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(content)
    return out_path


# ──────────────────────────────────────────────
#  Función principal para llamada desde GUI/CLI
# ──────────────────────────────────────────────
def generate_reports(
    audit_data: dict,
    formats: list[str],
    output_dir: str = "reports",
    base_name: str | None = None,
) -> dict[str, str]:
    """
    Genera reportes en los formatos especificados.
    Retorna dict {formato: ruta_del_archivo}.
    """
    os.makedirs(output_dir, exist_ok=True)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = base_name or f"tls_audit_{ts}"

    generated: dict[str, str] = {}

    if "json" in formats or "all" in formats:
        path = os.path.join(output_dir, f"{name}.json")
        generated["json"] = to_json(audit_data, path)

    if "csv" in formats or "all" in formats:
        path = os.path.join(output_dir, f"{name}.csv")
        generated["csv"] = to_csv(audit_data, path)

    if "html" in formats or "all" in formats:
        path = os.path.join(output_dir, f"{name}.html")
        generated["html"] = to_html(audit_data, path)

    if "txt" in formats or "all" in formats:
        path = os.path.join(output_dir, f"{name}.txt")
        generated["txt"] = to_txt(audit_data, path)

    return generated


# ──────────────────────────────────────────────
#  CLI standalone
# ──────────────────────────────────────────────
def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Generador de reportes — Módulo 06"
    )
    parser.add_argument('--input', '-i', required=True,
                        help='JSON de entrada con datos de auditoría')
    parser.add_argument('--format', '-f',
                        choices=['json', 'csv', 'html', 'txt', 'all'],
                        default='all',
                        help='Formato de salida (default: all)')
    parser.add_argument('--out', '-o', default='reports',
                        help='Directorio de salida (default: reports/)')
    args = parser.parse_args()

    with open(args.input, 'r', encoding='utf-8') as f:
        data = json.load(f)

    generated = generate_reports(data, [args.format], output_dir=args.out)

    print(f"\n[Reporter] Reportes generados en '{args.out}':")
    for fmt, path in generated.items():
        print(f"  [{fmt.upper():4s}] {path}")


if __name__ == '__main__':
    _cli()

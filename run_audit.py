"""
run_audit.py
------------
Orquestador principal del sistema de auditoría TLS.

Coordina los 5 módulos de análisis y genera los reportes finales.
Este script es el punto de entrada tanto para CLI como para la futura GUI.

Uso:
    # Un solo objetivo
    python run_audit.py google.com

    # Múltiples objetivos
    python run_audit.py google.com cloudflare.com github.com

    # Con puerto personalizado
    python run_audit.py myserver.com:8443

    # Desde archivo de targets
    python run_audit.py --file targets.txt

    # Especificar formatos de reporte
    python run_audit.py google.com --format html json

    # Saltar módulo nmap (si no está instalado)
    python run_audit.py google.com --skip-nmap

    # Modo silencioso (solo errores en stdout)
    python run_audit.py google.com --quiet
"""

import sys
import os
import json
import argparse
import datetime
import importlib
import importlib.util

SCANNER_DIR = os.path.join(os.path.dirname(__file__), "scanner")
sys.path.insert(0, SCANNER_DIR)

import importlib

def _load_module(name: str):
    """Carga un módulo del directorio scanner."""
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(SCANNER_DIR, f"{name}.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ----------------------------------------------
#  Carga lazy de módulos (para no romper si falta algo)
# ----------------------------------------------
def _try_load(module_name: str):
    try:
        return _load_module(module_name)
    except Exception as exc:
        print(f"  [!]  No se pudo cargar {module_name}: {exc}")
        return None


# ----------------------------------------------
#  Banner
# ----------------------------------------------
BANNER = """
=================================================================
  TLS AUDITOR v1.0
  Sistema de Analisis de Configuracion TLS y Riesgo de Exposicion
=================================================================
"""


def _print(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, flush=True)


# ----------------------------------------------
#  Pipeline de auditoría
# ----------------------------------------------
def run_audit(
    raw_targets: list[str],
    formats: list[str] = None,
    skip_nmap: bool = False,
    output_dir: str = "reports",
    quiet: bool = False,
) -> dict:
    """
    Ejecuta el pipeline completo de auditoría sobre la lista de targets.

    Parámetros:
        raw_targets : list de strings "host" o "host:port"
        formats     : lista de formatos de reporte ["json","csv","html","txt","all"]
        skip_nmap   : omitir módulo nmap (si no está instalado)
        output_dir  : directorio donde se guardan los reportes
        quiet       : suprimir mensajes de progreso

    Retorna:
        dict con claves: timestamp, targets, evaluations, comparison, reports
    """
    if formats is None:
        formats = ["all"]

    timestamp = datetime.datetime.now().isoformat()

    # -- MÓDULO 01: Validación ------------------------------------------
    _print("\n[01/05] [*] Validando objetivos...", quiet)
    mod_validator = _try_load("01_validator")
    if mod_validator is None:
        _print("[X] Error crítico: no se puede cargar el validador.", quiet)
        return {}

    validation = mod_validator.validate_targets(raw_targets)

    if validation.invalid:
        _print("  [!]  Entradas inválidas:", quiet)
        for inv in validation.invalid:
            _print(f"     ✗ {inv['input']}  →  {inv['reason']}", quiet)

    if not validation.valid:
        _print("  [X] Sin objetivos válidos para analizar.", quiet)
        return {"error": "Sin objetivos válidos", "invalid": validation.invalid}

    _print(f"  [OK] {len(validation.valid)} objetivo(s) válido(s)", quiet)

    # -- MÓDULO 02: Escaneo TLS -----------------------------------------
    _print("\n[02/05] [TLS] Escaneo TLS/SSL (sslyze)...", quiet)
    mod_tls = _try_load("02_tls_scanner")
    tls_results: dict[tuple, dict] = {}

    if mod_tls:
        for t in validation.valid:
            _print(f"  [~] {t.host}:{t.port}...", quiet)
            r = mod_tls.scan_target(t.host, t.port)
            tls_results[(t.host, t.port)] = r
            status = "[OK]" if "error" not in r else "[!] "
            _print(f"  {status} {t.host}:{t.port}", quiet)

    # -- MÓDULO 03: Nmap NSE --------------------------------------------
    _print("\n[03/05] [MAP]  Escaneo Nmap NSE...", quiet)
    mod_nmap = _try_load("03_nmap_scanner") if not skip_nmap else None
    nmap_results: dict[tuple, dict] = {}

    if mod_nmap:
        for t in validation.valid:
            _print(f"  [~] nmap {t.host}:{t.port}...", quiet)
            r = mod_nmap.scan_target(t.host, t.port)
            nmap_results[(t.host, t.port)] = r
            status = "[OK]" if "error" not in r else "[!] "
            _print(f"  {status} {t.host}:{t.port}", quiet)
    else:
        _print("  [i]  Nmap omitido.", quiet)

    # -- MÓDULO 04: Criptografía ----------------------------------------
    _print("\n[04/05] [KEY] Análisis criptográfico de certificados...", quiet)
    mod_crypto = _try_load("04_crypto_analyzer")
    crypto_results: dict[tuple, dict] = {}

    if mod_crypto:
        for t in validation.valid:
            _print(f"  [~] crypto {t.host}:{t.port}...", quiet)
            r = mod_crypto.analyze_target(t.host, t.port)
            crypto_results[(t.host, t.port)] = r
            status = "[OK]" if "error" not in r else "[!] "
            _print(f"  {status} {t.host}:{t.port}", quiet)

    # -- MÓDULO 05: Evaluación de riesgo -------------------------------
    _print("\n[05/05] [RISK]  Evaluando riesgos y generando recomendaciones...", quiet)
    mod_risk = _try_load("05_risk_evaluator")
    evaluations: list[dict] = []

    if mod_risk:
        for t in validation.valid:
            key = (t.host, t.port)
            ev = mod_risk.evaluate_host(
                host=t.host,
                port=t.port,
                tls_result=tls_results.get(key),
                nmap_result=nmap_results.get(key),
                crypto_result=crypto_results.get(key),
            )
            # Incrustar datos crudos para el reporter
            ev["tls_raw"]    = tls_results.get(key, {})
            ev["nmap_raw"]   = nmap_results.get(key, {})
            ev["crypto_raw"] = crypto_results.get(key, {})
            evaluations.append(ev)

        comparison = mod_risk.compare_hosts(evaluations)
    else:
        comparison = {}

    # -- Armar datos completos ------------------------------------------
    audit_data = {
        "timestamp":   timestamp,
        "targets":     [t._asdict() for t in validation.valid],
        "evaluations": evaluations,
        "comparison":  comparison,
    }

    # -- MÓDULO 06: Reportes --------------------------------------------
    mod_reporter = _try_load("06_reporter")
    generated_reports: dict[str, str] = {}

    if mod_reporter:
        generated_reports = mod_reporter.generate_reports(
            audit_data, formats, output_dir=output_dir
        )
        _print(f"\n[DOC] Reportes guardados en '{output_dir}':", quiet)
        for fmt, path in generated_reports.items():
            _print(f"   [{fmt.upper():4s}] {path}", quiet)

    audit_data["reports"] = generated_reports
    return audit_data


# ----------------------------------------------
#  Resumen en consola (siempre mostrado)
# ----------------------------------------------
def _print_summary(audit_data: dict) -> None:
    evaluations = audit_data.get("evaluations", [])
    comparison  = audit_data.get("comparison", {})

    ICONS = {
        "CRITICAL": "[C]", "HIGH": "[H]", "MEDIUM": "[M]",
        "LOW": "[L]", "OK": "[OK]",
    }

    print(f"\n{'='*65}")
    print("  RESUMEN DE AUDITORÍA")
    print(f"{'='*65}")

    for ev in evaluations:
        icon = ICONS.get(ev["risk_level"], "[?]")
        sc = ev.get("severity_counts", {})
        print(f"\n  {icon}  {ev['host']}:{ev['port']}")
        print(f"      Nivel de riesgo : {ev['risk_level']}  ({ev['risk_score']}/100)")
        print(f"      Hallazgos       : {ev['total_findings']} total")
        print(f"      Desglose        : [C] {sc.get('CRITICAL',0)} críticos | "
              f"[H] {sc.get('HIGH',0)} altos | "
              f"[M] {sc.get('MEDIUM',0)} medios | "
              f"[L] {sc.get('LOW',0)} bajos")

        # Top 3 findings críticos
        top3 = [f for f in ev.get("findings", [])
                if f["severity"] in ("CRITICAL", "HIGH")][:3]
        if top3:
            print("      Top hallazgos   :")
            for f in top3:
                print(f"        * [{f['severity']}] {f['title']}")

    if comparison.get("ranking"):
        print(f"\n  {'-'*60}")
        print(f"  [BAR] Servidor más expuesto : {comparison.get('most_critical')}")
        print(f"  [BAR] Servidor más seguro   : {comparison.get('safest')}")

    print(f"\n{'='*65}\n")


# ----------------------------------------------
#  CLI
# ----------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_audit.py",
        description="Sistema de Auditoría TLS — Orquestador principal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python run_audit.py google.com
  python run_audit.py google.com cloudflare.com github.com
  python run_audit.py --file targets.txt --format html csv
  python run_audit.py api.myserver.com:8443 --skip-nmap
        """,
    )
    # Targets como posicional opcional (0+)
    parser.add_argument('targets', nargs='*', metavar='HOST[:PORT]',
                        help='Dominios o IPs a auditar')
    # Alternativa: desde archivo
    parser.add_argument('--file', '-f', metavar='FILE',
                        help='Archivo con un objetivo por línea (alternativo a targets)')
    parser.add_argument('--format', nargs='+',
                        choices=['json', 'csv', 'html', 'txt', 'all'],
                        default=['all'],
                        help='Formatos de reporte (default: all)')
    parser.add_argument('--out', '-o', default='reports',
                        help='Directorio de salida (default: reports/)')
    parser.add_argument('--skip-nmap', action='store_true',
                        help='Omitir escaneo Nmap (más rápido)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suprimir salida de progreso')
    parser.add_argument('--json-out', action='store_true',
                        help='Mostrar JSON completo en stdout al final')
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if not args.quiet:
        print(BANNER)

    # Cargar targets
    if args.file:
        mod_v = _try_load("01_validator")
        if mod_v is None:
            sys.exit(1)
        raw_targets = mod_v.load_from_file(args.file)
        _print(f"  [DIR] Cargando targets desde '{args.file}': {len(raw_targets)} entradas")
    else:
        raw_targets = args.targets

    if not raw_targets:
        print("[X] Error: debes especificar al menos un objetivo.")
        sys.exit(1)

    # Pipeline
    audit_data = run_audit(
        raw_targets=raw_targets,
        formats=args.format,
        skip_nmap=args.skip_nmap,
        output_dir=args.out,
        quiet=args.quiet,
    )

    if not audit_data or "error" in audit_data:
        print(f"\n[X] {audit_data.get('error', 'Error desconocido')}")
        sys.exit(1)

    # Resumen
    _print_summary(audit_data)

    if args.json_out:
        print(json.dumps(audit_data, indent=2, ensure_ascii=False, default=str))


if __name__ == '__main__':
    main()

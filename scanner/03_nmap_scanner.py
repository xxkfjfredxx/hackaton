"""
03_nmap_scanner.py
------------------
Módulo de escaneo de puertos y servicios mediante Nmap con scripts NSE
orientados a TLS/SSL.

Scripts NSE utilizados:
  - ssl-enum-ciphers  : enumera cipher suites y versiones soportadas
  - ssl-cert          : extrae info del certificado
  - ssl-dh-params     : detecta parámetros DH débiles (LOGJAM)
  - ssl-heartbleed    : detecta vulnerabilidad Heartbleed
  - ssl-poodle        : detecta vulnerabilidad POODLE
  - tls-alpn          : detecta protocolos ALPN soportados
  - http-security-headers: headers de seguridad HTTP

Uso standalone:
    python 03_nmap_scanner.py google.com github.com
    python 03_nmap_scanner.py 8.8.8.8:443 --json
    python 03_nmap_scanner.py google.com --quick   # solo puertos, sin NSE
"""

import subprocess
import shutil
import json
import re
import argparse
from typing import Any


# ──────────────────────────────────────────────
#  Verificación de Nmap
# ──────────────────────────────────────────────
def _nmap_available() -> bool:
    """Devuelve True si el ejecutable 'nmap' está disponible en el PATH del sistema."""
    return shutil.which("nmap") is not None


def _nmap_version() -> str:
    """Retorna la versión de nmap instalada, o 'not_found' si no está disponible."""
    try:
        r = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10)
        match = re.search(r"Nmap version ([\d.]+)", r.stdout)
        return match.group(1) if match else "unknown"
    except Exception:
        return "not_found"


# ──────────────────────────────────────────────
#  Parsers de salida Nmap
# ──────────────────────────────────────────────
def _parse_ssl_enum_ciphers(output: str) -> dict:
    """
    Parsea la salida de ssl-enum-ciphers para extraer
    protocolos y cipher suites.
    """
    result: dict[str, Any] = {}
    current_proto = None

    for line in output.splitlines():
        # Detectar protocolo: "| ssl-enum-ciphers:" o "TLSv1.2:" etc.
        proto_match = re.search(
            r'\|\s+(SSL|TLS)v?([\d.]+):?\s*$', line, re.IGNORECASE
        )
        if proto_match:
            proto_full = proto_match.group(1).upper() + " " + proto_match.group(2)
            current_proto = proto_full
            result[current_proto] = {"ciphers": [], "grade": None}
            continue

        if current_proto is None:
            continue

        # Cipher suite
        cipher_match = re.search(r'\|\s+(TLS_[A-Z0-9_]+)', line)
        if cipher_match:
            result[current_proto]["ciphers"].append(cipher_match.group(1))

        # Grade
        grade_match = re.search(r'least strength:\s*([A-F])', line, re.IGNORECASE)
        if grade_match and current_proto:
            result[current_proto]["grade"] = grade_match.group(1).upper()

    return result


def _parse_ssl_cert(output: str) -> dict:
    """Parsea la sección ssl-cert de la salida de nmap."""
    cert = {}
    patterns = {
        "subject": r'Subject:\s*(.+)',
        "issuer":  r'Issuer:\s*(.+)',
        "not_before": r'Not valid before:\s*(.+)',
        "not_after":  r'Not valid after:\s*(.+)',
        "public_key": r'Public Key type:\s*(.+)',
        "key_bits":   r'Public Key bits:\s*(\d+)',
        "md5":  r'MD5:\s*(.+)',
        "sha1": r'SHA-1:\s*(.+)',
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            cert[key] = m.group(1).strip()
    return cert


def _detect_vulnerabilities(output: str) -> list[dict]:
    """Detecta vulnerabilidades conocidas en la salida de nmap."""
    vulns = []

    if re.search(r'heartbleed.*VULNERABLE', output, re.IGNORECASE):
        vulns.append({
            "id": "CVE-2014-0160",
            "name": "Heartbleed",
            "severity": "CRITICAL",
            "desc": "El servidor es vulnerable a Heartbleed (fuga de memoria en OpenSSL)"
        })

    if re.search(r'poodle.*VULNERABLE', output, re.IGNORECASE):
        vulns.append({
            "id": "CVE-2014-3566",
            "name": "POODLE",
            "severity": "HIGH",
            "desc": "Vulnerable a POODLE — SSLv3 permite degradación del protocolo"
        })

    if re.search(r'dh-params.*VULNERABLE|logjam', output, re.IGNORECASE):
        vulns.append({
            "id": "CVE-2015-4000",
            "name": "LOGJAM / Weak DH",
            "severity": "HIGH",
            "desc": "Parámetros Diffie-Hellman débiles — vulnerable a LOGJAM"
        })

    if re.search(r'freak.*VULNERABLE', output, re.IGNORECASE):
        vulns.append({
            "id": "CVE-2015-0204",
            "name": "FREAK",
            "severity": "HIGH",
            "desc": "Vulnerable a FREAK — soporta cipher suites de exportación"
        })

    return vulns


def _parse_open_ports(output: str) -> list[dict]:
    """Extrae los puertos abiertos de la salida de nmap.
    Retorna lista de dicts con claves: port, protocol, service.
    """
    ports = []
    for line in output.splitlines():
        m = re.match(r'\s*(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
        if m:
            ports.append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "service": m.group(3),
            })
    return ports


# ──────────────────────────────────────────────
#  Escaneo principal
# ──────────────────────────────────────────────
NSE_SCRIPTS = ",".join([
    "ssl-enum-ciphers",
    "ssl-cert",
    "ssl-dh-params",
    "ssl-heartbleed",
    "ssl-poodle",
    "tls-alpn",
    "http-security-headers",
])


def _run_nmap(host: str, port: int, quick: bool = False,
              timeout: int = 60) -> tuple[bool, str]:
    """Construye y ejecuta el comando nmap para un host:port.

    Args:
        host    : Nombre de host o IP a escanear.
        port    : Puerto destino.
        quick   : Si True, omite los scripts NSE (solo deteción de servicio).
        timeout : Tiempo máximo de espera en segundos.

    Returns:
        Tupla (exito: bool, salida_texto: str).
    """
    if quick:
        # -Pn: No ping (asume que el host está vivo)
        # -p: Solo el puerto específico
        cmd = ["nmap", "-Pn", "-sV", "--open", "-p", str(port), host]
    else:
        cmd = [
            "nmap", "-Pn", "-sV", "--open",
            "-p", str(port),
            f"--script={NSE_SCRIPTS}",
            "--script-timeout", "30s",
            host,
        ]

    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return True, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return False, f"Timeout ({timeout}s) ejecutando nmap para {host}:{port}"
    except FileNotFoundError:
        return False, "nmap no encontrado en el sistema"
    except Exception as exc:
        return False, f"Error al ejecutar nmap: {exc}"


def scan_target(host: str, port: int = 443,
                quick: bool = False) -> dict[str, Any]:
    """
    Escanea un objetivo con Nmap + NSE y retorna resultados parseados.
    """
    if not _nmap_available():
        return {
            "host": host, "port": port,
            "backend": "nmap",
            "error": "Nmap no está instalado o no se encuentra en el PATH",
            "install_hint": "Descarga desde https://nmap.org/download.html",
        }

    success, output = _run_nmap(host, port, quick=quick)

    if not success:
        return {
            "host": host, "port": port,
            "backend": "nmap",
            "error": output,
        }

    # Parsear resultados
    open_ports   = _parse_open_ports(output)
    ciphers_data = _parse_ssl_enum_ciphers(output) if not quick else {}
    cert_data    = _parse_ssl_cert(output)          if not quick else {}
    vulns        = _detect_vulnerabilities(output) if not quick else []

    # ALPN
    alpn_match = re.search(r'tls-alpn:\s*\n((?:\|.*\n)*)', output)
    alpn = []
    if alpn_match:
        alpn = re.findall(r'\|\s+(\S+)', alpn_match.group(1))

    # Headers de seguridad
    sec_headers: dict[str, str] = {}
    headers_section = re.search(
        r'http-security-headers:(.*?)(?=\||$)', output, re.DOTALL
    )
    if headers_section:
        for h_line in headers_section.group(1).splitlines():
            hm = re.match(r'\s+([A-Za-z-]+):\s+(.+)', h_line)
            if hm:
                sec_headers[hm.group(1)] = hm.group(2).strip()

    return {
        "backend": "nmap",
        "nmap_version": _nmap_version(),
        "host": host,
        "port": port,
        "open_ports": open_ports,
        "tls_ciphers_by_protocol": ciphers_data,
        "certificate": cert_data,
        "vulnerabilities": vulns,
        "alpn_protocols": alpn,
        "security_headers": sec_headers,
        "raw_output": output,  # para debugging / análisis posterior
    }


def scan_targets(targets: list[tuple[str, int]],
                 quick: bool = False) -> list[dict[str, Any]]:
    """Escaneo secuencial de múltiples targets con Nmap (versión legacy).
    Para mejor rendimiento usar scan_targets_parallel().
    """
    results = []
    for host, port in targets:
        r = scan_target(host, port, quick=quick)
        results.append(r)
    return results


def scan_targets_parallel(
    targets: list[tuple[str, int]],
    quick: bool = False,
    max_workers: int = 6,
    on_result=None,
) -> dict[tuple[str, int], dict[str, Any]]:
    """
    Escanea múltiples targets con Nmap en paralelo usando ThreadPoolExecutor.

    Args:
        targets    : Lista de (host, port)
        quick      : Si True, omite los scripts NSE (más rápido)
        max_workers: Número máximo de hilos concurrentes (default 6)
        on_result  : Callback opcional fn(host, port, result) llamado
                     cuando cada escaneo termina (útil para logs en tiempo real)

    Returns:
        dict {(host, port): result_dict}
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: dict[tuple[str, int], dict] = {}

    def _worker(host: str, port: int) -> tuple[tuple, dict]:
        r = scan_target(host, port, quick=quick)
        return (host, port), r

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_worker, host, port): (host, port)
            for host, port in targets
        }

        for future in as_completed(future_map):
            (host, port), result = future.result()
            results[(host, port)] = result
            if on_result:
                on_result(host, port, result)

    return results



# ──────────────────────────────────────────────
#  CLI standalone
# ──────────────────────────────────────────────
def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Escáner Nmap NSE — Módulo 03"
    )
    parser.add_argument('targets', nargs='+', metavar='HOST[:PORT]')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--quick', action='store_true',
                        help='Solo puertos abiertos, sin NSE (más rápido)')
    args = parser.parse_args()

    parsed = []
    for raw in args.targets:
        if ':' in raw:
            h, p = raw.rsplit(':', 1)
            parsed.append((h, int(p)))
        else:
            parsed.append((raw, 443))

    avail = _nmap_available()
    print(f"\n[Nmap Scanner] Disponible: {'✅ Sí' if avail else '❌ No'}")
    if avail:
        print(f"[Nmap Scanner] Versión: {_nmap_version()}")
    print(f"[Nmap Scanner] Objetivos: {len(parsed)}\n")

    results = scan_targets(parsed, quick=args.quick)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
        return

    for r in results:
        print(f"\n{'='*55}")
        print(f"  HOST: {r['host']}:{r['port']}")
        if "error" in r:
            print(f"  ❌ {r['error']}")
            if "install_hint" in r:
                print(f"  💡 {r['install_hint']}")
            continue

        ports_desc = [f"{p['port']}/{p['service']}" for p in r['open_ports']]
        print(f"  Puertos abiertos: {ports_desc}")

        if r.get("tls_ciphers_by_protocol"):
            print("  TLS/SSL (ssl-enum-ciphers):")
            for proto, data in r["tls_ciphers_by_protocol"].items():
                grade = data.get("grade", "?")
                ccount = len(data.get("ciphers", []))
                print(f"    {proto} — {ccount} ciphers | Grade: {grade}")

        if r.get("vulnerabilities"):
            print("  ⚠️  VULNERABILIDADES DETECTADAS:")
            for v in r["vulnerabilities"]:
                print(f"    [{v['severity']}] {v['name']} ({v['id']})")
                print(f"      {v['desc']}")
        else:
            print("  ✅ Sin vulnerabilidades críticas detectadas por Nmap NSE")

        if r.get("security_headers"):
            print("  Headers de seguridad HTTP:")
            for h, val in r["security_headers"].items():
                print(f"    {h}: {val}")




if __name__ == '__main__':
    _cli()

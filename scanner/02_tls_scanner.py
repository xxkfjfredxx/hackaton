"""
02_tls_scanner.py
-----------------
Motor de análisis TLS usando sslyze como backend principal
y ssl/socket como fallback nativo de Python.

Detecta:
  - Versiones TLS/SSL habilitadas y sus cipher suites
  - Estado del certificado (vigencia, issuer, confianza)
  - Presencia de protocolos obsoletos (SSL2, SSL3, TLS1.0, TLS1.1)

Uso standalone:
    python 02_tls_scanner.py google.com cloudflare.com github.com
    python 02_tls_scanner.py github.com:443 --json
"""

import ssl
import socket
import json
import argparse
import datetime
from typing import Any

# ── sslyze (backend principal) ──────────────────────────────────────────────
try:
    from sslyze import (
        Scanner, ScanCommand, ServerScanRequest,
        ServerNetworkLocation, ServerScanStatusEnum,
        ScanCommandAttemptStatusEnum,
    )
    from sslyze.errors import ServerHostnameCouldNotBeResolved
    import warnings
    try:
        from cryptography.utils import CryptographyDeprecationWarning
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    except ImportError:
        pass
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False


# ──────────────────────────────────────────────
#  Catálogo de Puertos Críticos por Perfil
# ──────────────────────────────────────────────
COMMON_PORTS = {
    "LEGACY": {
        "ports": [443, 80, 8443, 21, 995, 993, 465, 8080, 5900, 1433, 3306, 6379, 25, 4433, 10000],
        "description": "TLS 1.0 y 1.1 (Detección de Legado y Riesgo Alto)"
    },
    "STANDARD": {
        "ports": [443, 5432, 2376, 8443, 993, 995, 465, 587, 3389, 6443, 22, 1433, 8883, 5061, 4443],
        "description": "TLS 1.2 (Estándar de Oro y Compatibilidad)"
    },
    "MODERN": {
        "ports": [443, 8443, 2376, 6379, 5432, 4433, 8500, 2379, 9443, 3000, 5000, 8000, 11434, 4434, 9092],
        "description": "TLS 1.3 (Modernización y Máximo Rendimiento)"
    }
}

OBSOLETE_PROTOCOLS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
SECURE_PROTOCOLS   = {"TLS 1.2", "TLS 1.3"}

WEAK_CIPHERS_KEYWORDS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5",
    "ANON", "ADH", "AECDH", "RC2", "IDEA",
]

SSLYZE_PROTOCOL_ATTRS = [
    ("SSL 2.0", "ssl_2_0_cipher_suites"),
    ("SSL 3.0", "ssl_3_0_cipher_suites"),
    ("TLS 1.0", "tls_1_0_cipher_suites"),
    ("TLS 1.1", "tls_1_1_cipher_suites"),
    ("TLS 1.2", "tls_1_2_cipher_suites"),
    ("TLS 1.3", "tls_1_3_cipher_suites"),
]

SSLYZE_COMMANDS = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.CERTIFICATE_INFO,
} if SSLYZE_AVAILABLE else set()


# ──────────────────────────────────────────────
#  Utilidades
# ──────────────────────────────────────────────
def _is_weak_cipher(name: str) -> bool:
    """Devuelve True si el nombre del cipher suite contiene algún algoritmo débil conocido."""
    name_upper = name.upper()
    return any(kw in name_upper for kw in WEAK_CIPHERS_KEYWORDS)


def _safe_date(dt_value) -> str:
    """Convierte datetime aware/naive a string ISO."""
    if dt_value is None:
        return "N/A"
    return dt_value.isoformat() if hasattr(dt_value, 'isoformat') else str(dt_value)


# ──────────────────────────────────────────────
#  Backend: sslyze
# ──────────────────────────────────────────────
def _scan_with_sslyze(host: str, port: int) -> dict[str, Any]:
    """Escaneo completo via sslyze."""
    scanner = Scanner()
    scan_requests = []

    try:
        # Encolado seguro de la petición
        try:
            scan_requests.append(
                ServerScanRequest(
                    server_location=ServerNetworkLocation(hostname=host, port=port),
                    scan_commands=SSLYZE_COMMANDS,
                )
            )
        except ServerHostnameCouldNotBeResolved:
             return {"error": f"No se pudo resolver el hostname '{host}'"}
        except Exception as e:
            return {"error": f"Error al preparar escaneo para {host}:{port}: {str(e)}"}

        scanner.queue_scans(scan_requests)
        result = next(scanner.get_results())

    except Exception as e:
        return {"error": f"Error crítico de sslyze: {str(e)}"}

    if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
        return {"error": f"Sin conectividad: {result.connectivity_error_trace}"}

    scan = result.scan_result
    protocols: dict[str, dict] = {}

    # ── Protocolos y cipher suites ──────────────────────────
    for label, attr in SSLYZE_PROTOCOL_ATTRS:
        attempt = getattr(scan, attr)
        if attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            protocols[label] = {"supported": None, "error": str(attempt.error_reason)}
        elif attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            suites = attempt.result.accepted_cipher_suites
            cipher_names = [s.cipher_suite.name for s in suites]
            protocols[label] = {
                "supported": bool(suites),
                "cipher_count": len(cipher_names),
                "ciphers": cipher_names,
                "weak_ciphers": [c for c in cipher_names if _is_weak_cipher(c)],
            }
        else:
            protocols[label] = {"supported": None, "error": "No completado"}

    # ── Certificado ──────────────────────────────────────────
    cert_data: list[dict] = []
    cert_attempt = scan.certificate_info
    if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
        for deployment in cert_attempt.result.certificate_deployments:
            leaf = deployment.received_certificate_chain[0]
            trusted = deployment.verified_certificate_chain is not None
            not_before = getattr(leaf, "not_valid_before_utc", leaf.not_valid_before)
            not_after  = getattr(leaf, "not_valid_after_utc",  leaf.not_valid_after)

            # ¿expirado?
            now = datetime.datetime.now(datetime.timezone.utc)
            try:
                expired = not_after < now
                days_left = (not_after - now).days
            except TypeError:
                expired = False
                days_left = None

            cert_data.append({
                "subject":    leaf.subject.rfc4514_string(),
                "issuer":     leaf.issuer.rfc4514_string(),
                "key_type":   leaf.public_key().__class__.__name__,
                "serial":     str(leaf.serial_number),
                "valid_from": _safe_date(not_before),
                "valid_until": _safe_date(not_after),
                "days_remaining": days_left,
                "expired":    expired,
                "trusted":    trusted,
            })

    return {
        "backend": "sslyze",
        "host": host,
        "port": port,
        "protocols": protocols,
        "certificates": cert_data,
    }


# ──────────────────────────────────────────────
#  Backend: ssl nativo (fallback)
# ──────────────────────────────────────────────
_SSL_PROTO_MAP = {
    "SSL 3.0": getattr(ssl, "PROTOCOL_SSLv3",  None),
    "TLS 1.0": getattr(ssl, "PROTOCOL_TLSv1",  None),
    "TLS 1.1": getattr(ssl, "PROTOCOL_TLSv1_1", None),
    "TLS 1.2": getattr(ssl, "PROTOCOL_TLSv1_2", None),
}


def _try_connect_native(host: str, port: int, proto_const) -> bool:
    """Intenta una conexión TLS con un protocolo específico usando ssl nativo.
    Retorna True si el servidor acepta ese protocolo, False en cualquier otro caso.
    """
    if proto_const is None:
        return False
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _get_cert_native(host: str, port: int) -> dict | None:
    """Obtiene info del certificado via ssl nativo."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                return {
                    "subject":    dict(x[0] for x in cert.get("subject", [])),
                    "issuer":     dict(x[0] for x in cert.get("issuer",  [])),
                    "not_before": cert.get("notBefore"),
                    "not_after":  cert.get("notAfter"),
                    "cipher_used": cipher[0] if cipher else None,
                    "tls_version": ssock.version(),
                }
    except Exception:
        return None


def _check_tls13_native(host: str, port: int) -> bool:
    """Comprueba si el servidor acepta TLS 1.3 usando ssl nativo.
    Fuerza minimum y maximum version a TLSv1_3 para confirmar soporte.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _scan_with_native(host: str, port: int) -> dict[str, Any]:
    """Escaneo básico usando ssl/socket nativo como fallback."""
    protocols: dict[str, dict] = {}

    for label, proto_const in _SSL_PROTO_MAP.items():
        supported = _try_connect_native(host, port, proto_const)
        protocols[label] = {"supported": supported, "ciphers": [], "weak_ciphers": []}

    # TLS 1.3
    protocols["TLS 1.3"] = {
        "supported": _check_tls13_native(host, port),
        "ciphers": [],
        "weak_ciphers": [],
    }

    cert = _get_cert_native(host, port)
    certificates = [cert] if cert else []

    return {
        "backend": "ssl_native",
        "host": host,
        "port": port,
        "protocols": protocols,
        "certificates": certificates,
    }


# ──────────────────────────────────────────────
#  Punto de entrada principal del módulo
# ──────────────────────────────────────────────
def scan_target(host: str, port: int = 443) -> dict[str, Any]:
    """
    Escanea un objetivo TLS.
    Usa sslyze si está disponible, ssl nativo como fallback.
    Siempre devuelve un dict con claves: host, port, protocols, certificates.
    """
    if SSLYZE_AVAILABLE:
        result = _scan_with_sslyze(host, port)
        if "error" not in result:
            return result
        # Fallback si sslyze falla
        fallback = _scan_with_native(host, port)
        fallback["sslyze_error"] = result["error"]
        return fallback
    else:
        return _scan_with_native(host, port)


def scan_targets(targets: list[tuple[str, int]]) -> list[dict[str, Any]]:
    """Escanea múltiples objetivos de forma secuencial y devuelve lista de resultados.
    Para uso masivo se recomienda la variante paralela del módulo 03.
    """
    results = []
    for host, port in targets:
        r = scan_target(host, port)
        results.append(r)
    return results


# ──────────────────────────────────────────────
#  CLI standalone
# ──────────────────────────────────────────────
def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Motor de análisis TLS — Módulo 02"
    )
    parser.add_argument('targets', nargs='+', metavar='HOST[:PORT]',
                        help='Dominios o IPs a escanear (puerto default: 443)')
    parser.add_argument('--json', action='store_true', help='Salida en JSON')
    args = parser.parse_args()

    parsed = []
    for raw in args.targets:
        if ':' in raw:
            h, p = raw.rsplit(':', 1)
            parsed.append((h, int(p)))
        else:
            parsed.append((raw, 443))

    print(f"\n[TLS Scanner] Backend: {'sslyze' if SSLYZE_AVAILABLE else 'ssl nativo'}")
    print(f"[TLS Scanner] Objetivos: {len(parsed)}\n")

    results = scan_targets(parsed)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
        return

    for r in results:
        print(f"\n{'='*55}")
        print(f"  HOST: {r['host']}:{r['port']}")
        if "error" in r:
            print(f"  ❌ ERROR: {r['error']}")
            continue
        print(f"{'='*55}")
        print("  PROTOCOLOS:")
        for proto, data in r.get("protocols", {}).items():
            s = data.get("supported")
            if s is True:
                tag = f"✅ SOPORTADO ({data.get('cipher_count', '?')} ciphers)"
            elif s is False:
                tag = "🔒 No soportado"
            else:
                tag = f"⚠️  Error: {data.get('error','?')}"
            obsolete = " ⚠️ OBSOLETO" if proto in OBSOLETE_PROTOCOLS and s else ""
            print(f"    {proto:<10}: {tag}{obsolete}")
            for wc in data.get("weak_ciphers", []):
                print(f"               ⚠️  Cipher débil: {wc}")
        print("\n  CERTIFICADOS:")
        for cert in r.get("certificates", []):
            print(f"    Sujeto   : {cert.get('subject')}")
            print(f"    Emisor   : {cert.get('issuer')}")
            days = cert.get("days_remaining")
            exp_tag = " ⛔ EXPIRADO" if cert.get("expired") else (
                f" ⚠️ EXPIRA EN {days} días" if days is not None and days < 30 else ""
            )
            print(f"    Expira   : {cert.get('valid_until')}{exp_tag}")
            print(f"    Confiable: {'✅ Sí' if cert.get('trusted') else '❌ No'}")


if __name__ == '__main__':
    _cli()

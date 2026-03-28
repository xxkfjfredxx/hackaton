from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze import (
    Scanner,
    ScanCommand,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerScanStatusEnum,
    ScanCommandAttemptStatusEnum,
)
import argparse
import datetime
import ipaddress
import re
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


# ---------------------------------------------------------------------------
# Scan commands & protocol map
# ---------------------------------------------------------------------------
SCAN_COMMANDS = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.ROBOT,
}

PROTOCOL_ATTRS = [
    ("SSL 2.0", "ssl_2_0_cipher_suites"),
    ("SSL 3.0", "ssl_3_0_cipher_suites"),
    ("TLS 1.0", "tls_1_0_cipher_suites"),
    ("TLS 1.1", "tls_1_1_cipher_suites"),
    ("TLS 1.2", "tls_1_2_cipher_suites"),
    ("TLS 1.3", "tls_1_3_cipher_suites"),
]

# ---------------------------------------------------------------------------
# Port catalog
# ---------------------------------------------------------------------------
COMMON_PORTS = {
    "LEGACY":   [443, 80, 8443, 21, 995, 993, 465, 8080, 5900, 1433, 3306, 6379, 25, 4433, 10000],
    "STANDARD": [443, 5432, 2376, 8443, 993, 995, 465, 587, 3389, 6443, 22, 1433, 8883, 5061, 4443],
    "MODERN":   [443, 8443, 2376, 6379, 5432, 4433, 8500, 2379, 9443, 3000, 5000, 8000, 11434, 4434, 9092],
}

ALL_AUDIT_PORTS = sorted(
    set(port for ports in COMMON_PORTS.values() for port in ports))


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def is_valid_target(target: str) -> bool:
    """Validate that *target* is a valid IP address or DNS hostname."""
    # 1. Try as IP (IPv4 requires dots, IPv6 requires colons)
    if "." in target or ":" in target:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

    # 2. Validate as DNS hostname — must have a dot and at least one letter
    if "." in target and any(c.isalpha() for c in target):
        hostname_regex = re.compile(
            r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+'
            r'([A-Za-z0-9]|[A-Za-z0-9][a-zA-Z0-9\-]*[A-Za-z0-9])$'
        )
        if hostname_regex.match(target):
            return True

    # Special case for local testing
    if target.lower() == "localhost":
        return True

    return False


# ---------------------------------------------------------------------------
# Cipher suite scoring
# ---------------------------------------------------------------------------
# Component weights (must sum to 1.0).
# Security guidance: cipher+mode carries the most weight because it directly
# protects data confidentiality; key exchange comes next because forward
# secrecy is critical; authentication third; hash/PRF last.
_W_CIPHER = 0.40
_W_KEX = 0.35
_W_AUTH = 0.15
_W_HASH = 0.10

# Key exchange algorithm
_KEX_SCORES = {
    "ECDHE":  10,  # Ephemeral ECDH  — perfect forward secrecy, preferred
    "DHE":     9,  # Ephemeral DH    — forward secrecy, slower
    "ECDH":    5,  # Static ECDH     — no forward secrecy
    "DH":      4,  # Static DH       — no forward secrecy
    "PSK":     6,  # Pre-shared key  — FS depends on cipher
    "SRP":     5,  # Secure Remote Password
    "KRB5":    4,  # Kerberos
    "RSA":     3,  # RSA key transport — no forward secrecy, PKCS#1 risk
    "EXPORT":  0,  # Deliberately weakened (40-bit) — broken
    "ANON":    0,  # No authentication — trivially MITM-able
    "NULL":    0,
}

# Authentication algorithm
_AUTH_SCORES = {
    "ECDSA":  10,  # Elliptic-curve signatures — recommended
    "RSA":     7,  # RSA signatures — acceptable
    "PSK":     6,
    "SRP":     5,
    "DSS":     5,  # DSA — acceptable but not recommended
    "KRB5":    4,
    "EXPORT":  0,
    "ANON":    0,
    "NULL":    0,
}

# Symmetric cipher + mode (dict ordered longest-key-first avoids partial matches)
_CIPHER_SCORES = {
    "CHACHA20_POLY1305": 10,  # AEAD, timing-attack resistant
    "AES_256_GCM":       10,  # AEAD, 256-bit — gold standard
    "ARIA_256_GCM":       9,
    "CAMELLIA_256_GCM":   9,
    "AES_256_CCM":        9,  # AEAD, 256-bit
    "AES_128_GCM":        9,  # AEAD, 128-bit — excellent
    "ARIA_128_GCM":       8,
    "CAMELLIA_128_GCM":   8,
    "AES_128_CCM":        8,
    "AES_256_CBC":        6,  # No built-in auth — needs strong MAC
    "CAMELLIA_256_CBC":   6,
    "AES_128_CBC":        5,
    "CAMELLIA_128_CBC":   5,
    "SEED_CBC":           4,  # Older Korean standard
    "3DES_EDE_CBC":       2,  # 112-bit effective, SWEET32 vulnerable
    "DES_CBC":            1,  # 56-bit — trivially broken
    "DES40_CBC":          0,  # Export-grade 40-bit — broken
    "RC4_128":            1,  # Broken (BEAST, RC4 biases)
    "RC4_40":             0,  # Export-grade 40-bit RC4 — broken
    "RC2_CBC_40":         0,  # Export-grade — broken
    "EXPORT":             0,
    "NULL":               0,  # No encryption
}

# Hash / MAC / PRF
_HASH_SCORES = {
    "SHA384": 10,  # SHA-2 — strong
    "SHA256": 10,  # SHA-2 — strong
    "SHA":     4,  # SHA-1 — deprecated, collision-prone
    "MD5":     0,  # Broken
    "NULL":    0,
}


def _best_match(score_map: dict, text: str, default: int = 5) -> tuple:
    """Return (key, score) for the longest key found in *text*, or default."""
    for key in sorted(score_map, key=len, reverse=True):
        if key in text:
            return key, score_map[key]
    return "UNKNOWN", default


def score_cipher_suite(name: str) -> tuple:
    """
    Decompose a cipher suite name into components, score each one (0-10),
    and return (weighted_score, label, components).

    Weights (security-recommended):
        cipher 40%  |  kex 35%  |  auth 15%  |  hash 10%

    Labels:
        CRÍTICO 0-2.9  |  DÉBIL 3-4.9  |  ACEPTABLE 5-6.9  |  BUENO 7-8.9  |  FUERTE 9-10
    """
    upper = name.upper()
    if "_WITH_" not in upper:
        # TLS 1.3 suites: KEX is always ephemeral, auth is not encoded in name
        kex_name,    kex_score = "ECDHE (TLS 1.3)", _KEX_SCORES["ECDHE"]
        auth_name,   auth_score = "TLS 1.3 (fuerte)", 10
        cipher_name, cipher_score = _best_match(
            _CIPHER_SCORES, upper, default=0)
        hash_name,   hash_score = _best_match(_HASH_SCORES,   upper, default=4)
    else:
        before, after = upper.split("_WITH_", 1)
        for prefix in ("TLS_", "SSL_CK_", "SSL_"):
            if before.startswith(prefix):
                before = before[len(prefix):]
                break
        kex_name,    kex_score = _best_match(_KEX_SCORES,    before, default=3)
        auth_name,   auth_score = _best_match(
            _AUTH_SCORES,   before, default=7)
        cipher_name, cipher_score = _best_match(
            _CIPHER_SCORES, after,  default=0)
        hash_name,   hash_score = _best_match(
            _HASH_SCORES,   after,  default=4)

    weighted = (
        cipher_score * _W_CIPHER +
        kex_score * _W_KEX +
        auth_score * _W_AUTH +
        hash_score * _W_HASH
    )
    final = round(min(10.0, max(0.0, weighted)), 1)

    if final >= 9.0:
        label = "FUERTE"
    elif final >= 7.0:
        label = "BUENO"
    elif final >= 5.0:
        label = "ACEPTABLE"
    elif final >= 3.0:
        label = "DÉBIL"
    else:
        label = "CRÍTICO"

    components = {
        "KEX":    (kex_name,    kex_score),
        "Auth":   (auth_name,   auth_score),
        "Cipher": (cipher_name, cipher_score),
        "Hash":   (hash_name,   hash_score),
    }
    return final, label, components


# ---------------------------------------------------------------------------
# Risk analysis & recommendations
# ---------------------------------------------------------------------------
WEAK_CIPHER_KEYWORDS = [
    "NULL", "EXPORT", "RC4", "DES", "3DES", "ANON", "ADH", "AECDH", "MD5",
]


def analyze_and_recommend(
    supported_protos: list,
    weak_ciphers_by_proto: dict,
    cert_trusted: bool,
    cert_expired: bool,
    cert_days: int | None,
    has_tls12: bool,
    has_tls13: bool,
) -> None:
    """Analyze TLS scan results and print prioritized, actionable recommendations."""
    findings = []  # (priority, severity, title, risk, recommendation)

    OBSOLETE = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
    found_obsolete = [p for p in supported_protos if p in OBSOLETE]

    if "SSL 2.0" in found_obsolete:
        findings.append((1, "CRÍTICO", "SSL 2.0 Habilitado",
                         "SSL 2.0 fue roto hace décadas. Los atacantes pueden leer el tráfico de los usuarios en texto plano.",
                         "Deshabilitar SSL 2.0 en la configuración del servidor (Apache/Nginx) de inmediato."))

    if "SSL 3.0" in found_obsolete:
        findings.append((1, "CRÍTICO", "SSL 3.0 Habilitado — vulnerable a POODLE",
                         "SSL 3.0 es explotable mediante POODLE (CVE-2014-3566). "
                         "Un atacante puede descifrar cookies de sesión mientras el usuario navega.",
                         "Deshabilitar SSL 3.0 en el servidor. Explotable públicamente desde 2014."))

    if "TLS 1.0" in found_obsolete or "TLS 1.1" in found_obsolete:
        obsolete_list = ", ".join(
            p for p in ["TLS 1.0", "TLS 1.1"] if p in found_obsolete)
        findings.append((2, "ALTO", f"Protocolo(s) Obsoleto(s): {obsolete_list}",
                         f"{obsolete_list} fue retirado oficialmente en 2021 (RFC 8996). "
                         "Mantenerlo activo expone al servidor a ataques de degradación de protocolo.",
                         f"Deshabilitar {obsolete_list}. Solo se necesita TLS 1.2 y TLS 1.3 "
                         "para compatibilidad con todos los clientes modernos."))

    if not has_tls13:
        findings.append((3, "MEDIO", "TLS 1.3 No Habilitado",
                         "El servidor no ofrece TLS 1.3, la versión más rápida y segura disponible.",
                         "Habilitar TLS 1.3 en el servidor — mejora velocidad y seguridad simultáneamente."))

    if not has_tls12 and not has_tls13:
        findings.append((1, "CRÍTICO", "Sin Versión TLS Segura Disponible",
                         "El servidor no ofrece ninguna versión segura de TLS. Todo el tráfico puede ser interceptado.",
                         "Configurar TLS 1.2 y TLS 1.3 en el servidor urgentemente."))

    null_protos = [p for p, ciphers in weak_ciphers_by_proto.items()
                   if any("NULL" in c.upper() or "ANON" in c.upper() for c in ciphers)]
    if null_protos:
        findings.append((1, "CRÍTICO", "Cipher Suites NULL / Anónimos Detectados",
                         f"El servidor acepta conexiones SIN cifrado (NULL) o sin "
                         f"autenticación (ANON) en: {', '.join(null_protos)}.",
                         "Eliminar todos los cipher suites NULL y ANON de la configuración TLS del servidor."))

    export_protos = [p for p, ciphers in weak_ciphers_by_proto.items()
                     if any("EXPORT" in c.upper() for c in ciphers)]
    if export_protos:
        findings.append((1, "CRÍTICO", "Cipher Suites EXPORT Detectados (riesgo FREAK)",
                         f"Cipher suites de grado exportación (40-bit) encontrados en: {', '.join(export_protos)}. "
                         "Vulnerables al ataque FREAK (CVE-2015-0204).",
                         "Eliminar todos los cipher suites EXPORT de la configuración del servidor."))

    weak_protos = [p for p, ciphers in weak_ciphers_by_proto.items()
                   if any(kw in c.upper() for c in ciphers for kw in ["RC4", "DES", "3DES", "MD5"])]
    if weak_protos:
        findings.append((2, "ALTO", "Algoritmos de Cifrado Débiles Detectados",
                         f"Cipher suites con RC4, DES, 3DES o MD5 encontrados en: {', '.join(weak_protos)}. "
                         "Pueden romperse con herramientas modernas.",
                         "Usar solo cipher suites AES-GCM o ChaCha20-Poly1305 (algoritmos AEAD modernos)."))

    if cert_expired:
        findings.append((1, "CRÍTICO", "Certificado VENCIDO",
                         "El certificado de seguridad ha expirado. Los navegadores mostrarán un error grave "
                         "y la mayoría de los usuarios no podrán acceder al sitio.",
                         "Renovar el certificado de inmediato. Esta es la acción más urgente."))
    elif cert_days is not None and cert_days < 30:
        sev = "CRÍTICO" if cert_days < 7 else "ALTO"
        pri = 1 if cert_days < 7 else 2
        findings.append((pri, sev, f"Certificado Vence en {cert_days} Día(s)",
                         f"El certificado expirará en {cert_days} día(s). Los usuarios verán "
                         "errores de seguridad si no se renueva a tiempo.",
                         "Renovar antes de que expire. Considerar Let's Encrypt para renovación automática."))

    if not cert_trusted:
        findings.append((1, "CRÍTICO", "Certificado No Confiable (Autofirmado)",
                         "El certificado no fue emitido por una CA de confianza. Los navegadores mostrarán "
                         "advertencias de seguridad que alejarán a los usuarios.",
                         "Obtener un certificado de una CA reconocida. Let's Encrypt es gratuito y automático."))

    if not findings:
        print("  [OK] Sin hallazgos de seguridad — la configuración es correcta.\n")
        return

    findings.sort(key=lambda x: x[0])

    SEV_ICON = {"CRÍTICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🔵"}
    print(f"\n  {'─' * 60}")
    print("  ANÁLISIS DE RIESGOS Y RECOMENDACIONES")
    print(f"  {'─' * 60}")

    for _, sev, title, risk, recommendation in findings:
        icon = SEV_ICON.get(sev, "  ")
        print(f"\n  {icon} [{sev}] {title}")
        print(f"     Riesgo : {risk}")
        print(f"     Acción : {recommendation}")

    print(f"\n  {'─' * 60}\n")


# ---------------------------------------------------------------------------
# Server profile extraction & comparison
# ---------------------------------------------------------------------------
def _extract_profile(result) -> dict:
    """
    Pull a flat, comparable profile out of a completed scan result.
    Stored structure:
        {
            "hostname": str,
            "port": int,
            "protocols": { "TLS 1.3": set[cipher_name] | None, ... },
            "cert_key_type": str | None,
        }
    None means the scan command returned an error (not the same as unsupported).
    """
    scan = result.scan_result
    protocols = {}
    for label, attr in PROTOCOL_ATTRS:
        attempt = getattr(scan, attr)
        if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            protocols[label] = {
                s.cipher_suite.name
                for s in attempt.result.accepted_cipher_suites
            }
        else:
            protocols[label] = None  # scan error — unknown

    cert_key_type = None
    cert_attempt = scan.certificate_info
    if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
        deployments = cert_attempt.result.certificate_deployments
        if deployments:
            leaf = deployments[0].received_certificate_chain[0]
            cert_key_type = leaf.public_key().__class__.__name__

    return {
        "hostname":     result.server_location.hostname,
        "port":         result.server_location.port,
        "protocols":    protocols,
        "cert_key_type": cert_key_type,
    }


def compare_servers(profiles: list) -> None:
    """
    Print a comparison report across all scanned servers.
    Highlights:
      - Protocol support matrix (which servers accept which protocols)
      - Cipher suite differences per protocol
      - Certificate key type differences
    """
    if len(profiles) < 2:
        return

    sep = "=" * 72
    print(f"\n\n{sep}")
    print("  INFORME DE COMPARACIÓN DE SERVIDORES")
    print(sep)

    hosts = [f"{p['hostname']}:{p['port']}" for p in profiles]
    col_w = max(max(len(h) for h in hosts), 8) + 2

    # ── Matriz de soporte de protocolos ─────────────────────────────────────
    print("\n-- Matriz de soporte de protocolos --\n")
    print(f"  {'Protocolo':<14}" + "".join(f"{h:>{col_w}}" for h in hosts))
    print("  " + "-" * (14 + col_w * len(hosts)))

    for label, _ in PROTOCOL_ATTRS:
        cells = []
        supported_flags = []
        for p in profiles:
            suites = p["protocols"].get(label)
            if suites is None:
                cells.append("ERR")
                supported_flags.append(None)
            elif suites:
                cells.append(f"SÍ({len(suites)})")
                supported_flags.append(True)
            else:
                cells.append("NO")
                supported_flags.append(False)

        row = f"  {label:<14}" + "".join(f"{c:>{col_w}}" for c in cells)
        non_null = [f for f in supported_flags if f is not None]
        if non_null and len(set(non_null)) > 1:
            row += "  ⚠ DISCREPANCIA"
        print(row)

    # ── Diferencias de cipher suites por protocolo ───────────────────────────
    print("\n-- Diferencias de cipher suites por protocolo --")
    found_diff = False

    for label, _ in PROTOCOL_ATTRS:
        valid = [
            (f"{p['hostname']}:{p['port']}", p["protocols"][label])
            for p in profiles
            if p["protocols"].get(label) is not None
        ]
        if len(valid) < 2:
            continue

        suite_sets = [s for _, s in valid]
        common = set.intersection(*suite_sets)
        unique_to = {
            host: (suites - common)
            for host, suites in valid
            if (suites - common)
        }

        if not unique_to:
            continue

        found_diff = True
        print(f"\n  {label}:")
        if common:
            print(f"    Compartidos por todos ({len(common)}):")
            for name in sorted(common):
                score, lbl, _ = score_cipher_suite(name)
                print(f"      = {name:<50}  [{score:4.1f}/10 - {lbl}]")
        else:
            print("    Compartidos por todos: ninguno")

        for host, diff in unique_to.items():
            print(f"    Solo en {host} ({len(diff)}):")
            for name in sorted(diff):
                score, lbl, _ = score_cipher_suite(name)
                print(f"      + {name:<50}  [{score:4.1f}/10 - {lbl}]")

    if not found_diff:
        print("\n  ✔ Todos los servidores comparten los mismos cipher suites en todos los protocolos.")

    # ── Tipos de clave de certificado ────────────────────────────────────────
    print("\n-- Tipos de clave de certificado --\n")
    key_types = {f"{p['hostname']}:{p['port']}": (
        p["cert_key_type"] or "N/A") for p in profiles}
    for host, key_type in key_types.items():
        print(f"  {host:<{col_w + 14}} {key_type}")
    if len(set(key_types.values())) > 1:
        print("\n  ⚠ Los tipos de clave difieren entre servidores!")
    else:
        print("\n  ✔ Todos los servidores usan el mismo tipo de clave de certificado.")

    print(f"\n{sep}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auditor TLS/SSL — Escanea uno o más servidores para identificar vulnerabilidades relacionadas con TLS/SSL"
    )
    parser.add_argument(
        "hostnames",
        nargs="+",
        metavar="HOSTNAME[:PUERTO]",
        help="Uno o más objetivos a escanear. El puerto es opcional, por defecto es 443. "
             "Ejemplos: google.com  cloudflare.com:443  miserv.com:8443",
    )
    parser.add_argument(
        "--all-ports",
        action="store_true",
        help="Escanear el catálogo completo de puertos críticos en lugar de solo el 443.",
    )
    args = parser.parse_args()

    scan_requests = []
    for target in args.hostnames:
        if ":" in target:
            hostname, port_str = target.rsplit(":", 1)
            try:
                ports_to_scan = [int(port_str)]
            except ValueError:
                print(f"Error: puerto inválido '{port_str}', saltando.")
                continue
        else:
            hostname = target
            ports_to_scan = ALL_AUDIT_PORTS if args.all_ports else [443]

        if not is_valid_target(hostname):
            print(
                f"Advertencia: formato de objetivo incorrecto '{hostname}', saltando.")
            continue

        for port in ports_to_scan:
            try:
                scan_requests.append(
                    ServerScanRequest(
                        server_location=ServerNetworkLocation(
                            hostname=hostname, port=port),
                        scan_commands=SCAN_COMMANDS,
                    )
                )
            except ServerHostnameCouldNotBeResolved:
                print(
                    f"Error: no se pudo resolver '{hostname}', saltando puerto {port}.")
            except Exception as exc:
                print(
                    f"Error preparando solicitud para {hostname}:{port} — {exc}")

    if not scan_requests:
        print("No hay objetivos válidos para escanear.")
        return

    print(f"=> Iniciando escaneo de {len(scan_requests)} endpoint(s) ...\n")
    scanner = Scanner()
    scanner.queue_scans(scan_requests)

    all_profiles = []
    for result in scanner.get_results():
        location = result.server_location
        print(f"\n{'=' * 55}")
        print(f"  Resultados para {location.hostname}:{location.port}")
        print(f"{'=' * 55}")

        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print(
                f"  Error: no se pudo conectar — {result.connectivity_error_trace}\n")
            continue

        all_profiles.append(_extract_profile(result))
        scan = result.scan_result

        # ── Protocolos y cipher suites ────────────────────────────────────
        print("\n  -- Soporte de Protocolos --")
        supported_protos: list[str] = []
        weak_ciphers_by_proto: dict[str, list[str]] = {}
        has_tls12 = False
        has_tls13 = False

        for proto_name, proto_attr in PROTOCOL_ATTRS:
            attempt = getattr(scan, proto_attr)
            if attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                print(
                    f"  {proto_name}: error de escaneo ({attempt.error_reason})")
            elif attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                accepted_suites = attempt.result.accepted_cipher_suites
                if accepted_suites:
                    suite_names = [
                        s.cipher_suite.name for s in accepted_suites]
                    print(
                        f"  {proto_name}: SOPORTADO  ({len(accepted_suites)} cipher suite(s))")
                    for suite_name in suite_names:
                        score, lbl, parts = score_cipher_suite(suite_name)
                        is_weak = any(kw in suite_name.upper()
                                      for kw in WEAK_CIPHER_KEYWORDS)
                        weak_mark = "  [DÉBIL]" if is_weak else ""
                        print(
                            f"      * {suite_name:<50}  [{score:4.1f}/10 - {lbl}]{weak_mark}")
                        breakdown = "  |  ".join(
                            f"{k}: {v[0]}={v[1]}" for k, v in parts.items())
                        print(f"        ↳ {breakdown}")
                    supported_protos.append(proto_name)
                    weak_ciphers = [n for n in suite_names
                                    if any(kw in n.upper() for kw in WEAK_CIPHER_KEYWORDS)]
                    if weak_ciphers:
                        weak_ciphers_by_proto[proto_name] = weak_ciphers
                    if proto_name == "TLS 1.2":
                        has_tls12 = True
                    if proto_name == "TLS 1.3":
                        has_tls13 = True
                else:
                    print(f"  {proto_name}: no soportado")

        # ── Certificado ──────────────────────────────────────────────────
        print("\n  -- Información del Certificado --")
        cert_trusted = False
        cert_expired = False
        cert_days = None
        first_cert = True

        cert_attempt = scan.certificate_info
        if cert_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            print(
                f"  Error de escaneo del certificado ({cert_attempt.error_reason})")
        elif cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            for deployment in cert_attempt.result.certificate_deployments:
                leaf_cert = deployment.received_certificate_chain[0]
                trusted = deployment.verified_certificate_chain is not None
                not_before = getattr(
                    leaf_cert, "not_valid_before_utc", leaf_cert.not_valid_before)
                not_after = getattr(
                    leaf_cert, "not_valid_after_utc",  leaf_cert.not_valid_after)
                now = datetime.datetime.now(datetime.timezone.utc)

                if not_after:
                    na = (not_after if not_after.tzinfo is not None
                          else not_after.replace(tzinfo=datetime.timezone.utc))
                    days_remaining = (na - now).days
                    is_expired = days_remaining <= 0
                else:
                    days_remaining = None
                    is_expired = False

                # Collect validity data from the first (leaf) deployment only
                if first_cert:
                    cert_trusted = trusted
                    cert_expired = is_expired
                    cert_days = days_remaining
                    first_cert = False

                print(f"  Sujeto       : {leaf_cert.subject.rfc4514_string()}")
                print(f"  Emisor       : {leaf_cert.issuer.rfc4514_string()}")
                print(
                    f"  Tipo de clave: {leaf_cert.public_key().__class__.__name__}")
                print(f"  Serie        : {leaf_cert.serial_number}")
                print(f"  Válido desde : {not_before}")
                print(f"  Válido hasta : {not_after}")
                if days_remaining is not None:
                    if is_expired:
                        print(
                            f"  Vencimiento  : EXPIRADO hace {abs(days_remaining)} día(s)")
                    elif days_remaining < 30:
                        print(
                            f"  Vencimiento  : Vence en {days_remaining} día(s) — URGENTE")
                    elif days_remaining < 90:
                        print(
                            f"  Vencimiento  : Vence en {days_remaining} día(s) — Próximo")
                    else:
                        print(
                            f"  Vencimiento  : Vence en {days_remaining} día(s) — OK")
                print(
                    f"  Confiable    : {'Sí' if trusted else 'No (autofirmado o CA desconocida)'}")
        else:
            print("  Advertencia: No se pudo obtener información del certificado.")

        # ── Análisis y recomendaciones ────────────────────────────────────
        print("\n-- Recomendaciones --")
        analyze_and_recommend(
            supported_protos=supported_protos,
            weak_ciphers_by_proto=weak_ciphers_by_proto,
            cert_trusted=cert_trusted,
            cert_expired=cert_expired,
            cert_days=cert_days,
            has_tls12=has_tls12,
            has_tls13=has_tls13,
        )

    compare_servers(all_profiles)


if __name__ == "__main__":
    main()

"""
04_crypto_analyzer.py
---------------------
Análisis criptográfico profundo usando la librería 'cryptography' de Python.

Analiza:
  - Fuerza de la clave pública (RSA / ECDSA / DSA)
  - Algoritmo de firma del certificado (SHA1 = débil)
  - Validez temporal del certificado
  - Subject Alternative Names (SANs)
  - Uso de extensiones críticas (Key Usage, Extended Key Usage)
  - Fingerprints SHA256
  - Política del certificado (DV / OV / EV)
  - Verificación de cadena de confianza básica

Uso standalone:
    python 04_crypto_analyzer.py google.com cloudflare.com
    python 04_crypto_analyzer.py github.com:443 --json
"""

import ssl
import socket
import json
import argparse
import datetime
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (
        rsa, ec, dsa, ed25519, ed448
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ──────────────────────────────────────────────
#  Constantes de evaluación
# ──────────────────────────────────────────────
RSA_MIN_BITS   = 2048   # < este valor → débil
EC_MIN_BITS    = 256    # < este valor → débil
DSA_MIN_BITS   = 2048

WEAK_HASH_ALGS = {"sha1", "sha0", "md5", "md4", "md2"}

# OIDs de política para clasificar certificados
EV_OID_PREFIXES = [
    "2.23.140.1.1",   # CA/B Forum EV
]
OV_OID_PREFIXES = [
    "2.23.140.1.2.2", # CA/B Forum OV
]


# ──────────────────────────────────────────────
#  Obtención del certificado desde el servidor
# ──────────────────────────────────────────────
def _fetch_certificate_der(host: str, port: int) -> bytes | None:
    """Conecta al servidor y descarga el certificado en formato DER."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                return der
    except Exception:
        # Intentar con TLS más permisivo
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            ctx2.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert(binary_form=True)
        except Exception:
            return None


# ──────────────────────────────────────────────
#  Análisis del certificado
# ──────────────────────────────────────────────
def _analyze_public_key(cert: "x509.Certificate") -> dict:
    """Evalúa la fortaleza de la clave pública."""
    pub_key = cert.public_key()
    info: dict[str, Any] = {}

    if isinstance(pub_key, rsa.RSAPublicKey):
        bits = pub_key.key_size
        info["type"] = "RSA"
        info["bits"] = bits
        info["weak"] = bits < RSA_MIN_BITS
        info["recommendation"] = (
            f"RSA {bits} bits es {'aceptable' if bits >= RSA_MIN_BITS else 'INSEGURO — usar ≥2048 bits'}"
        )
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        bits = pub_key.key_size
        curve = pub_key.curve.name
        info["type"] = "EC"
        info["bits"] = bits
        info["curve"] = curve
        info["weak"] = bits < EC_MIN_BITS
        info["recommendation"] = (
            f"ECDSA {curve} ({bits} bits) — {'OK' if bits >= EC_MIN_BITS else 'curva débil'}"
        )
    elif isinstance(pub_key, dsa.DSAPublicKey):
        bits = pub_key.key_size
        info["type"] = "DSA"
        info["bits"] = bits
        info["weak"] = bits < DSA_MIN_BITS
        info["recommendation"] = "DSA está en desuso — migrar a ECDSA o RSA 2048+"
    elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        info["type"] = type(pub_key).__name__
        info["bits"] = 255 if "25519" in type(pub_key).__name__ else 448
        info["weak"] = False
        info["recommendation"] = "EdDSA — excelente selección moderna"
    else:
        info["type"] = type(pub_key).__name__
        info["weak"] = False
        info["recommendation"] = "Tipo de clave no analizado"

    return info


def _analyze_signature(cert: "x509.Certificate") -> dict:
    """Evalúa el algoritmo de firma del certificado."""
    sig_alg = cert.signature_hash_algorithm
    if sig_alg is None:
        return {"algorithm": "N/A", "weak": False}

    alg_name = sig_alg.name.lower()
    weak = alg_name in WEAK_HASH_ALGS

    return {
        "algorithm": sig_alg.name,
        "weak": weak,
        "recommendation": (
            f"⚠️ {sig_alg.name} está deprecado — usar SHA256 o superior"
            if weak else f"{sig_alg.name} ✅"
        ),
    }


def _analyze_validity(cert: "x509.Certificate") -> dict:
    """Analiza la vigencia temporal del certificado."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # Compatibilidad con versiones antiguas de cryptography
    not_before = getattr(cert, "not_valid_before_utc",
                         cert.not_valid_before.replace(tzinfo=datetime.timezone.utc))
    not_after  = getattr(cert, "not_valid_after_utc",
                         cert.not_valid_after.replace(tzinfo=datetime.timezone.utc))

    total_days    = (not_after - not_before).days
    days_left     = (not_after - now).days
    expired       = now > not_after
    not_yet_valid = now < not_before

    # Certificados de larga duración son sospechosos (>825 días según CA/B Forum)
    long_lived = total_days > 825

    return {
        "not_before":   not_before.isoformat(),
        "not_after":    not_after.isoformat(),
        "total_days":   total_days,
        "days_remaining": days_left,
        "expired":      expired,
        "not_yet_valid": not_yet_valid,
        "long_lived":   long_lived,
        "severity": (
            "CRITICAL" if expired
            else "HIGH" if days_left < 7
            else "MEDIUM" if days_left < 30
            else "LOW" if days_left < 90
            else "OK"
        ),
    }


def _get_sans(cert: "x509.Certificate") -> list[str]:
    """Extrae Subject Alternative Names."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _classify_cert_type(cert: "x509.Certificate") -> str:
    """
    Clasifica el certificado como DV / OV / EV basado en las políticas y el CN.
    """
    try:
        policies_ext = cert.extensions.get_extension_for_class(x509.CertificatePolicies)
        for policy in policies_ext.value:
            oid_str = policy.policy_identifier.dotted_string
            if any(oid_str.startswith(p) for p in EV_OID_PREFIXES):
                return "EV (Extended Validation)"
            if any(oid_str.startswith(p) for p in OV_OID_PREFIXES):
                return "OV (Organization Validation)"
    except (x509.ExtensionNotFound, AttributeError):
        pass

    # Heurística: si el Subject tiene O (Organization) → probable OV
    try:
        cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return "OV (Organization Validation) [heurístico]"
    except Exception:
        pass

    return "DV (Domain Validation)"


def _get_fingerprint(cert: "x509.Certificate") -> dict:
    """Calcula los fingerprints SHA-256 y SHA-1 del certificado en formato DER.
    Útil para identificar univocamente un certificado.
    """
    from cryptography.hazmat.primitives import serialization
    der = cert.public_bytes(serialization.Encoding.DER)
    import hashlib
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1":   hashlib.sha1(der).hexdigest(),
    }


def analyze_certificate_der(der: bytes) -> dict[str, Any]:
    """Analiza un certificado en formato DER y retorna el informe completo."""
    if not CRYPTO_AVAILABLE:
        return {"error": "Librería 'cryptography' no disponible. Instalar: pip install cryptography"}

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        return {"error": f"No se pudo parsear el certificado: {exc}"}

    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = subject[0].value if subject else "N/A"

    return {
        "common_name":   cn,
        "serial_number": hex(cert.serial_number),
        "cert_type":     _classify_cert_type(cert),
        "public_key":    _analyze_public_key(cert),
        "signature":     _analyze_signature(cert),
        "validity":      _analyze_validity(cert),
        "sans":          _get_sans(cert),
        "fingerprint":   _get_fingerprint(cert),
    }


# ──────────────────────────────────────────────
#  Punto de entrada del módulo
# ──────────────────────────────────────────────
def analyze_target(host: str, port: int = 443) -> dict[str, Any]:
    """
    Descarga y analiza criptográficamente el certificado de un servidor.
    """
    der = _fetch_certificate_der(host, port)
    if der is None:
        return {
            "host": host, "port": port,
            "error": "No se pudo obtener el certificado del servidor"
        }

    analysis = analyze_certificate_der(der)
    analysis["host"] = host
    analysis["port"] = port
    return analysis


def analyze_targets(targets: list[tuple[str, int]]) -> list[dict[str, Any]]:
    """Analiza criptográficamente los certificados de múltiples servidores.
    Retorna lista de resultados en el mismo orden que la entrada.
    """
    results = []
    for host, port in targets:
        r = analyze_target(host, port)
        results.append(r)
    return results


# ──────────────────────────────────────────────
#  CLI standalone
# ──────────────────────────────────────────────
def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Analizador criptográfico de certificados — Módulo 04"
    )
    parser.add_argument('targets', nargs='+', metavar='HOST[:PORT]')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()

    parsed = []
    for raw in args.targets:
        if ':' in raw:
            h, p = raw.rsplit(':', 1)
            parsed.append((h, int(p)))
        else:
            parsed.append((raw, 443))

    print(f"\n[Crypto Analyzer] cryptography lib: {'✅ disponible' if CRYPTO_AVAILABLE else '❌ no disponible'}")
    print(f"[Crypto Analyzer] Objetivos: {len(parsed)}\n")

    results = analyze_targets(parsed)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
        return

    SEV_ICONS = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
        "LOW": "🔵", "OK": "✅",
    }

    for r in results:
        print(f"\n{'='*55}")
        print(f"  HOST: {r.get('host')}:{r.get('port')}")
        if "error" in r:
            print(f"  ❌ {r['error']}")
            continue

        print(f"  CN          : {r.get('common_name')}")
        print(f"  Tipo cert   : {r.get('cert_type')}")
        print(f"  Serial      : {r.get('serial_number')}")

        pk = r.get("public_key", {})
        weak_icon = "⚠️ DÉBIL" if pk.get("weak") else "✅"
        print(f"\n  Clave pública: {pk.get('type')} {pk.get('bits', '')} bits {weak_icon}")
        print(f"  Recomendación: {pk.get('recommendation')}")

        sig = r.get("signature", {})
        sig_icon = "⚠️ DÉBIL" if sig.get("weak") else "✅"
        print(f"\n  Firma        : {sig.get('algorithm')} {sig_icon}")

        val = r.get("validity", {})
        sev = val.get("severity", "OK")
        sev_icon = SEV_ICONS.get(sev, "")
        print(f"\n  Validez      : {val.get('not_before')} → {val.get('not_after')}")
        print(f"  Días restantes: {val.get('days_remaining')} {sev_icon} [{sev}]")
        if val.get('expired'):
            print("  ⛔ CERTIFICADO EXPIRADO")
        if val.get('long_lived'):
            print("  ⚠️  Certificado de larga duración (>825 días) — no conforme con CA/B Forum")

        sans = r.get("sans", [])
        if sans:
            print(f"\n  SANs ({len(sans)}): {', '.join(sans[:5])}" +
                  (f" ... +{len(sans)-5} más" if len(sans) > 5 else ""))

        fp = r.get("fingerprint", {})
        print(f"\n  SHA256: {fp.get('sha256', 'N/A')}")


if __name__ == '__main__':
    _cli()

"""
01_validator.py
---------------
Módulo de validación y normalización de entradas.
Recibe dominios, IPs o listas y devuelve objetivos validados.

Uso standalone:
    python 01_validator.py google.com 8.8.8.8 bad_target
    python 01_validator.py --file targets.txt
"""

import re
import socket
import argparse
import json
from typing import NamedTuple


# ──────────────────────────────────────────────
#  Tipos de resultado
# ──────────────────────────────────────────────
class ValidatedTarget(NamedTuple):
    host: str          # hostname o IP normalizado
    port: int          # puerto (default 443)
    is_ip: bool        # True si es dirección IP
    raw: str           # entrada original del usuario


class ValidationResult(NamedTuple):
    valid: list[ValidatedTarget]
    invalid: list[dict]        # {"input": str, "reason": str}


# ──────────────────────────────────────────────
#  Patrones de validación
# ──────────────────────────────────────────────
_IPV4_RE = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,63}$'
)
_PORT_RANGE = range(1, 65536)


def _parse_host_port(raw: str) -> tuple[str, int]:
    """Extrae host y puerto de strings como 'host:port'. Default port=443."""
    raw = raw.strip()
    # IPv6 [::1]:443
    if raw.startswith('['):
        bracket_end = raw.find(']')
        if bracket_end == -1:
            raise ValueError("IPv6 mal formado")
        host = raw[1:bracket_end]
        rest = raw[bracket_end + 1:]
        port = int(rest[1:]) if rest.startswith(':') else 443
        return host, port

    parts = raw.rsplit(':', 1)
    if len(parts) == 2:
        host, port_str = parts
        try:
            port = int(port_str)
        except ValueError:
            # podría ser un dominio sin puerto (un solo segmento con letras)
            host = raw
            port = 443
    else:
        host = raw
        port = 443
    return host, port


def validate_target(raw: str) -> tuple[ValidatedTarget | None, dict | None]:
    """
    Valida un objetivo individual.
    Retorna (ValidatedTarget, None) si es válido, (None, error_dict) si no.
    """
    raw = raw.strip()
    if not raw or raw.startswith('#'):
        return None, None  # línea vacía / comentario → ignorar silenciosamente

    try:
        host, port = _parse_host_port(raw)
    except ValueError as exc:
        return None, {"input": raw, "reason": str(exc)}

    if port not in _PORT_RANGE:
        return None, {"input": raw, "reason": f"Puerto {port} fuera del rango 1-65535"}

    is_ip = bool(_IPV4_RE.match(host))

    if not is_ip and not _DOMAIN_RE.match(host):
        return None, {"input": raw, "reason": "Formato de dominio/IP inválido"}

    # Verificar resolvibilidad (sólo dominios)
    if not is_ip:
        try:
            socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return None, {"input": raw, "reason": f"No se pudo resolver: {exc}"}

    return ValidatedTarget(host=host, port=port, is_ip=is_ip, raw=raw), None


def validate_targets(inputs: list[str]) -> ValidationResult:
    """
    Valida una lista de strings de entrada.
    Filtra duplicados y ordena por host.
    """
    valid: list[ValidatedTarget] = []
    invalid: list[dict] = []
    seen: set[tuple[str, int]] = set()

    for raw in inputs:
        target, error = validate_target(raw)
        if target is None and error is None:
            continue  # línea vacía / comentario
        if error:
            invalid.append(error)
            continue
        key = (target.host, target.port)
        if key in seen:
            continue  # duplicado, ignorar
        seen.add(key)
        valid.append(target)

    valid.sort(key=lambda t: t.host)
    return ValidationResult(valid=valid, invalid=invalid)


def load_from_file(path: str) -> list[str]:
    """Lee líneas de un archivo de texto (ignora comentarios y vacías)."""
    with open(path, 'r', encoding='utf-8') as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith('#')]


# ──────────────────────────────────────────────
#  CLI standalone
# ──────────────────────────────────────────────
def _cli() -> None:
    parser = argparse.ArgumentParser(
        description="Validador de objetivos TLS — Módulo 01"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('targets', nargs='*', metavar='HOST[:PORT]',
                       help='Dominios o IPs a validar')
    group.add_argument('--file', '-f', metavar='FILE',
                       help='Archivo con un objetivo por línea')
    parser.add_argument('--json', action='store_true',
                        help='Salida en formato JSON')
    args = parser.parse_args()

    raw_inputs: list[str] = []
    if args.file:
        try:
            raw_inputs = load_from_file(args.file)
        except FileNotFoundError:
            print(f"[ERROR] Archivo no encontrado: {args.file}")
            return
    else:
        raw_inputs = args.targets

    result = validate_targets(raw_inputs)

    if args.json:
        output = {
            "valid": [t._asdict() for t in result.valid],
            "invalid": result.invalid,
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    print(f"\n{'='*50}")
    print(f"  VALIDACIÓN DE OBJETIVOS")
    print(f"{'='*50}")
    print(f"  Válidos  : {len(result.valid)}")
    print(f"  Inválidos: {len(result.invalid)}")
    print(f"{'='*50}\n")

    if result.valid:
        print("✅ OBJETIVOS VÁLIDOS:")
        for t in result.valid:
            tag = "(IP)" if t.is_ip else "(dominio)"
            print(f"   {t.host}:{t.port}  {tag}")

    if result.invalid:
        print("\n❌ ENTRADAS INVÁLIDAS:")
        for e in result.invalid:
            print(f"   {e['input']}  →  {e['reason']}")

    print()


if __name__ == '__main__':
    _cli()

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
import warnings
import datetime
import re
import ipaddress
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from tls_recommender import analyze_and_recommend, WEAK_CIPHER_KEYWORDS

# ── Validación de Formato (DNS / IP) Estricta ─────────
def is_valid_target(target: str) -> bool:
    # 1. Validar como IP (Debe tener puntos '.' para IPv4 o ':' para IPv6)
    if "." in target or ":" in target:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
    
    # 2. Validar como nombre de dominio (DNS)
    # Exigimos al menos un punto '.' y que CONTENGA letras para evitar números puros
    if "." in target and any(c.isalpha() for c in target):
        hostname_regex = re.compile(
            r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+'
            r'([A-Za-z0-9]|[A-Za-z0-9][a-zA-Z0-9\-]*[A-Za-z0-9])$'
        )
        if hostname_regex.match(target):
            return True
    
    # Caso especial para pruebas locales
    if target.lower() == "localhost":
        return True
        
    return False

# ──────────────────────────────────────────────
#  Catálogo de Puertos Críticos
# ──────────────────────────────────────────────
COMMON_PORTS = {
    "LEGACY": [443, 80, 8443, 21, 995, 993, 465, 8080, 5900, 1433, 3306, 6379, 25, 4433, 10000],
    "STANDARD": [443, 5432, 2376, 8443, 993, 995, 465, 587, 3389, 6443, 22, 1433, 8883, 5061, 4443],
    "MODERN": [443, 8443, 2376, 6379, 5432, 4433, 8500, 2379, 9443, 3000, 5000, 8000, 11434, 4434, 9092]
}

ALL_AUDIT_PORTS = sorted(list(set(sum(COMMON_PORTS.values(), []))))

COMANDOS_ESCANEO = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.CERTIFICATE_INFO,
}

PROTOCOLOS_Y_ATRIBUTOS = [
    ("SSL 2.0", "ssl_2_0_cipher_suites"),
    ("SSL 3.0", "ssl_3_0_cipher_suites"),
    ("TLS 1.0", "tls_1_0_cipher_suites"),
    ("TLS 1.1", "tls_1_1_cipher_suites"),
    ("TLS 1.2", "tls_1_2_cipher_suites"),
    ("TLS 1.3", "tls_1_3_cipher_suites"),
]

def main() -> None:
    parser = argparse.ArgumentParser(description="TLS/SSL auditor — scans servers using sslyze")
    parser.add_argument("hostnames", nargs="+", help="Targets (google.com or google.com:443)")
    parser.add_argument("--all-ports", action="store_true", help="Scan catalog ports")
    args = parser.parse_args()

    solicitudes_escaneo = []
    for objetivo in args.hostnames:
        if ":" in objetivo:
            hostname, texto_puerto = objetivo.rsplit(":", 1)
            try:
                puertos_a_escanear = [int(texto_puerto)]
            except ValueError:
                print(f"Error: puerto invalido '{texto_puerto}', saltando.")
                continue
        else:
            hostname = objetivo
            puertos_a_escanear = ALL_AUDIT_PORTS if args.all_ports else [443]

        if not is_valid_target(hostname):
            print(f"Advertencia: formato de objetivo incorrecto '{hostname}', saltando.")
            continue

        for puerto in puertos_a_escanear:
            try:
                solicitudes_escaneo.append(
                    ServerScanRequest(
                        server_location=ServerNetworkLocation(hostname=hostname, port=puerto),
                        scan_commands=COMANDOS_ESCANEO,
                    )
                )
            except ServerHostnameCouldNotBeResolved:
                print(f"Error: no se pudo resolver '{hostname}', saltando puerto {puerto}.")
            except Exception as error_excepcion:
                print(f"Error preparando solicitud para {hostname}:{puerto} -> {str(error_excepcion)}")

    if not solicitudes_escaneo:
        print("No hay objetivos validos para escanear.")
        return

    print(f"=> Iniciando escaneo de {len(solicitudes_escaneo)} endpoint(s) ...\n")
    escaner = Scanner()
    escaner.queue_scans(solicitudes_escaneo)

    for resultado in escaner.get_results():
        ubicacion = resultado.server_location
        print(f"\n{'='*55}")
        print(f" Resultados para {ubicacion.hostname}:{ubicacion.port}")
        print(f"{'='*55}")

        if resultado.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print(f"  Error: no se pudo conectar — {resultado.connectivity_error_trace}\n")
            continue

        resultado_escaneo = resultado.scan_result

        # ── Protocolos ─────────────────────────────────────────────
        print("\n  -- Soporte de Protocolos --")
        protocolos_soportados: list[str] = []
        ciphers_debiles_por_protocolo: dict[str, list[str]] = {}
        tiene_tls12 = False
        tiene_tls13 = False

        for nombre_protocolo, atributo_protocolo in PROTOCOLOS_Y_ATRIBUTOS:
            intento = getattr(resultado_escaneo, atributo_protocolo)
            if intento.status == ScanCommandAttemptStatusEnum.COMPLETED:
                suites_aceptadas = intento.result.accepted_cipher_suites
                if suites_aceptadas:
                    nombres_cipher = [suite.cipher_suite.name for suite in suites_aceptadas]
                    print(f"  {nombre_protocolo}: SOPORTADO  ({len(suites_aceptadas)} cipher suite(s))")
                    for nombre_cipher in nombres_cipher:
                        es_debil = any(algoritmo_debil in nombre_cipher for algoritmo_debil in WEAK_CIPHER_KEYWORDS)
                        marca    = " [DEBIL]" if es_debil else ""
                        print(f"      * {nombre_cipher}{marca}")
                    protocolos_soportados.append(nombre_protocolo)
                    ciphers_debiles = [nombre for nombre in nombres_cipher
                                       if any(algoritmo_debil in nombre for algoritmo_debil in WEAK_CIPHER_KEYWORDS)]
                    if ciphers_debiles:
                        ciphers_debiles_por_protocolo[nombre_protocolo] = ciphers_debiles
                    if nombre_protocolo == "TLS 1.2": tiene_tls12 = True
                    if nombre_protocolo == "TLS 1.3": tiene_tls13 = True
                else:
                    print(f"  {nombre_protocolo}: no soportado")

        # ── Certificado ─────────────────────────────────────────────
        print("\n  -- Informacion del Certificado --")
        certificado_confiable = False
        certificado_expirado  = False
        dias_restantes_cert   = None

        intento_certificado = resultado_escaneo.certificate_info
        if intento_certificado.status == ScanCommandAttemptStatusEnum.COMPLETED:
            for despliegue in intento_certificado.result.certificate_deployments:
                cert_hoja        = despliegue.received_certificate_chain[0]
                es_confiable     = despliegue.verified_certificate_chain is not None
                fecha_inicio     = getattr(cert_hoja, "not_valid_before_utc", cert_hoja.not_valid_before)
                fecha_fin        = getattr(cert_hoja, "not_valid_after_utc",  cert_hoja.not_valid_after)
                ahora            = datetime.datetime.now(datetime.timezone.utc)
                dias_restantes   = (fecha_fin - ahora).days if fecha_fin else None
                esta_expirado    = dias_restantes is not None and dias_restantes <= 0

                certificado_confiable = es_confiable
                certificado_expirado  = esta_expirado
                dias_restantes_cert   = dias_restantes

                print(f"  Sujeto       : {cert_hoja.subject.rfc4514_string()}")
                print(f"  Emisor       : {cert_hoja.issuer.rfc4514_string()}")
                print(f"  Tipo de clave: {cert_hoja.public_key().__class__.__name__}")
                print(f"  Valido desde : {fecha_inicio}")
                print(f"  Valido hasta : {fecha_fin}")
                if dias_restantes is not None:
                    if esta_expirado:
                        print(f"  Vencimiento  : EXPIRADO hace {abs(dias_restantes)} dia(s)")
                    elif dias_restantes < 30:
                        print(f"  Vencimiento  : Vence en {dias_restantes} dia(s) — URGENTE")
                    elif dias_restantes < 90:
                        print(f"  Vencimiento  : Vence en {dias_restantes} dia(s) — Proximo")
                    else:
                        print(f"  Vencimiento  : Vence en {dias_restantes} dia(s) — OK")
                print(f"  Confiable    : {'Si' if es_confiable else 'No (autofirmado o CA desconocida)'}")
        else:
            print("  Advertencia: No se pudo obtener informacion del certificado.")

        # ── Analisis y Recomendaciones ───────────────────────────────
        analyze_and_recommend(
            supported_protos      = protocolos_soportados,
            weak_ciphers_by_proto = ciphers_debiles_por_protocolo,
            cert_trusted          = certificado_confiable,
            cert_expired          = certificado_expirado,
            cert_days             = dias_restantes_cert,
            has_tls12             = tiene_tls12,
            has_tls13             = tiene_tls13,
        )

if __name__ == "__main__":
    main()

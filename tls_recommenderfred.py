"""
tls_recommender.py
------------------
Motor de análisis y recomendaciones para auditorías TLS/SSL.
Importado por tslauditor1.py para mantener el código modular.

Uso:
    from tls_recommender import analyze_and_recommend
"""

WEAK_CIPHER_KEYWORDS = ["NULL", "EXPORT", "RC4", "DES", "3DES", "ANON", "ADH", "AECDH", "MD5"]


def analyze_and_recommend(
    supported_protos: list[str],
    weak_ciphers_by_proto: dict,
    cert_trusted: bool,
    cert_expired: bool,
    cert_days: int | None,
    has_tls12: bool,
    has_tls13: bool,
) -> None:
    """
    Analiza los resultados de un escaneo TLS y muestra recomendaciones
    claras y accionables ordenadas por prioridad.

    Args:
        supported_protos      : Lista de protocolos soportados (e.g. ["TLS 1.0", "TLS 1.2"])
        weak_ciphers_by_proto : Dict {protocolo: [cipher_names débiles]}
        cert_trusted          : True si el certificado es de confianza
        cert_expired          : True si el certificado está vencido
        cert_days             : Días restantes de validez del certificado (None si desconocido)
        has_tls12             : True si TLS 1.2 está soportado
        has_tls13             : True si TLS 1.3 está soportado
    """
    findings = []  # (prioridad, severidad, titulo, riesgo, recomendacion)

    OBSOLETE = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
    found_obsolete = [p for p in supported_protos if p in OBSOLETE]

    # ── Protocolos obsoletos ────────────────────────────────────────
    if "SSL 2.0" in found_obsolete:
        findings.append((1, "CRITICO", "SSL 2.0 Activado",
            "SSL 2.0 fue hackeado hace decadas. Cualquier atacante puede "
            "leer el trafico de sus usuarios en texto plano.",
            "Desactivar SSL 2.0 en la configuracion del servidor (Apache/Nginx) inmediatamente."))

    if "SSL 3.0" in found_obsolete:
        findings.append((1, "CRITICO", "SSL 3.0 Activado (vulnerable a POODLE)",
            "SSL 3.0 es explotable con el ataque POODLE (CVE-2014-3566). "
            "Un atacante puede descifrar cookies de sesion mientras el usuario navega.",
            "Desactivar SSL 3.0 en el servidor. Vulnerabilidad publica explotable desde 2014."))

    if "TLS 1.0" in found_obsolete or "TLS 1.1" in found_obsolete:
        obsolete_list = ", ".join(p for p in ["TLS 1.0", "TLS 1.1"] if p in found_obsolete)
        findings.append((2, "ALTO", f"Protocolo(s) Obsoleto(s): {obsolete_list}",
            f"{obsolete_list} fue retirado oficialmente en 2021 (RFC 8996). "
            "Mantenerlo activo expone al servidor a ataques de degradacion de protocolo "
            "donde un atacante fuerza conexiones menos seguras.",
            f"Deshabilitar {obsolete_list} en el servidor. Solo se necesita TLS 1.2 y TLS 1.3 "
            "para compatibilidad con todos los navegadores modernos."))

    # ── TLS moderno ─────────────────────────────────────────────────
    if not has_tls13:
        findings.append((3, "MEDIO", "TLS 1.3 No Habilitado",
            "El servidor no ofrece TLS 1.3, la version mas rapida y segura disponible. "
            "Los usuarios con navegadores modernos no reciben la mejor proteccion.",
            "Habilitar TLS 1.3 en el servidor. Mejora velocidad y seguridad simultaneamente."))

    if not has_tls12 and not has_tls13:
        findings.append((1, "CRITICO", "Sin Cifrado Seguro Disponible",
            "El servidor no ofrece ninguna version segura de TLS. "
            "Toda comunicacion puede ser interceptada.",
            "Configurar TLS 1.2 y TLS 1.3 en el servidor urgentemente."))

    # ── Ciphers peligrosos ──────────────────────────────────────────
    null_protos = [p for p, ciphers in weak_ciphers_by_proto.items()
                   if any("NULL" in c or "ANON" in c for c in ciphers)]
    if null_protos:
        findings.append((1, "CRITICO", "Cifrado NULL / Anonimo Detectado",
            f"El servidor acepta conexiones SIN cifrado (NULL) o sin autenticacion (ANON) "
            f"en: {', '.join(null_protos)}. El trafico va en texto plano aunque use HTTPS.",
            "Eliminar todos los cipher suites con NULL o ANON de la configuracion TLS del servidor."))

    export_protos = [p for p, ciphers in weak_ciphers_by_proto.items()
                     if any("EXPORT" in c for c in ciphers)]
    if export_protos:
        findings.append((1, "CRITICO", "Ciphers EXPORT Detectados (FREAK)",
            f"Se encontraron cipher suites de exportacion (40-bit) en: {', '.join(export_protos)}. "
            "Son vulnerables al ataque FREAK (CVE-2015-0204) que permite descifrar conexiones.",
            "Eliminar todos los cipher suites EXPORT de la configuracion del servidor."))

    weak_protos = [p for p, ciphers in weak_ciphers_by_proto.items()
                   if any(kw in c for c in ciphers for kw in ["RC4", "DES", "3DES", "MD5"])]
    if weak_protos:
        findings.append((2, "ALTO", "Algoritmos de Cifrado Debiles",
            f"Se detectaron cipher suites con RC4, DES, 3DES o MD5 en: {', '.join(weak_protos)}. "
            "Estos algoritmos pueden romperse con herramientas modernas.",
            "Usar solo cipher suites AES-GCM o ChaCha20-Poly1305 (algoritmos AEAD modernos)."))

    # ── Certificado ─────────────────────────────────────────────────
    if cert_expired:
        findings.append((1, "CRITICO", "Certificado EXPIRADO",
            "El certificado de seguridad vencio. Los navegadores mostraran advertencia "
            "de error y la mayoria de los usuarios no podra acceder al sitio.",
            "Renovar el certificado inmediatamente. Es la accion mas urgente posible."))
    elif cert_days is not None and cert_days < 30:
        sev = "CRITICO" if cert_days < 7 else "ALTO"
        pri = 1 if cert_days < 7 else 2
        findings.append((pri, sev, f"Certificado Vence en {cert_days} Dia(s)",
            f"El certificado expirara en {cert_days} dia(s). Si no se renueva, "
            "los usuarios veran errores de seguridad y no podran conectarse.",
            "Renovar el certificado antes de que expire. Considerar Let's Encrypt para renovacion automatica."))

    if not cert_trusted:
        findings.append((1, "CRITICO", "Certificado No Reconocido (Autofirmado)",
            "El certificado no fue emitido por una entidad de confianza. Los navegadores "
            "mostraran advertencias de seguridad que ahuyentaran a los usuarios.",
            "Obtener un certificado de una CA reconocida. Let's Encrypt lo ofrece gratis y automatico."))

    # ── Imprimir ────────────────────────────────────────────────────
    if not findings:
        print("  [OK] Sin hallazgos de seguridad — configuracion correcta.\n")
        return

    findings.sort(key=lambda x: x[0])

    SEV_LABEL = {"CRITICO": "[!]", "ALTO": "[!]", "MEDIO": "[~]", "BAJO": "[-]"}
    SEV_ICON  = {"CRITICO": "🔴", "ALTO": "🟠", "MEDIO": "🟡", "BAJO": "🔵"}
    print(f"\n  {'─'*52}")
    print(f"  ANALISIS DE RIESGOS Y RECOMENDACIONES")
    print(f"  {'─'*52}")

    for _, sev, titulo, riesgo, recomendacion in findings:
        label = SEV_LABEL.get(sev, "[ ]")
        icon  = SEV_ICON.get(sev, "")
        print(f"\n  {icon} {label} {sev}: {titulo}")
        print(f"     Riesgo identificado: {riesgo}")
        # Ajuste de línea para recomendaciones largas
        palabras = recomendacion.split()
        linea    = "     Recomendacion: "
        for palabra in palabras:
            if len(linea) + len(palabra) > 80:
                print(linea)
                linea = "       " + palabra + " "
            else:
                linea += palabra + " "
        if linea.strip():
            print(linea)

    print(f"\n  {'─'*52}\n")

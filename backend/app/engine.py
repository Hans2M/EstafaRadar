import ipaddress
import re
import socket
import unicodedata
import os
from urllib.parse import urljoin, urlsplit, unquote
import httpx
from .schemas import ScanResult, Finding

# Señales ejemplares; NO es un motor de reputación ni una lista de dominios verificados.
SENSITIVE_TERMS = ("clave", "contraseña", "contrasena", "codigo", "código", "otp", "token", "verificar", "validar", "premio", "bloqueada", "suspendida")
BRANDS = ("yape", "plin", "bcp", "interbank", "sunat", "reniec", "banco")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd"}
MAX_PAGE_BYTES = 200_000
MAX_REDIRECTS = 3
MAX_BROWSER_TEXT = 20_000


def normalize_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _findings_to_verdict(kind: str, findings: list[Finding], score: int, uncertain: bool = False, **details) -> ScanResult:
    score = min(100, score)
    verdict = "alto" if score >= 65 else "moderado" if score >= 30 else ("no_concluyente" if uncertain else "bajo")
    if any(f.code in {"UNOFFICIAL_STREAMING", "PIRACY_SIGNALS", "DOWNLOAD_BAIT"} for f in findings):
        advice = "Evita hacer clic en botones de descarga o instalar reproductores y extensiones. Usa servicios oficiales; este tipo de páginas puede contener publicidad maliciosa, redirecciones o archivos no confiables."
    elif any(f.code == "ACCESS_RESTRICTED" for f in findings):
        advice = "El sitio no permitió verificar su contenido y mostró una protección anti-bot o acceso restringido. No lo consideres seguro: verifica el dominio desde un canal oficial y no introduzcas datos."
    elif verdict == "alto":
        advice = "No ingreses claves, códigos ni datos de pago. Comprueba la solicitud desde la app o web oficial abierta por ti mismo."
    elif verdict == "moderado":
        advice = "Hay señales de precaución. Verifica remitente y dominio por canales oficiales; no sigas enlaces recibidos inesperadamente."
    else:
        advice = "No se detectaron indicadores suficientes para concluir fraude. Evita compartir información sensible sin verificar por un canal oficial."
    return ScanResult(kind=kind, verdict=verdict, score=score, findings=findings, advice=advice,
                      limitations=["Análisis heurístico y lectura segura de metadatos; no es una consulta de reputación.",
                                   "La ausencia de alertas NO demuestra que el contenido sea seguro.",
                                   "La página se leyó sin JavaScript, descargas ni interacción; esto no es una sandbox de ejecución completa."],
                      **details)


def _public_host(host: str) -> bool:
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return True
    for address in {item[4][0] for item in addresses}:
        ip = ipaddress.ip_address(address)
        if any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast, ip.is_reserved, ip.is_unspecified)):
            return False
    return True


def _extract_page(html: str) -> tuple[str | None, str | None, str]:
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    description_match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
        html,
        re.I | re.S,
    )
    text = re.sub(r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<[^>]+>", " ", html, flags=re.I | re.S)
    text = re.sub(r"\s+", " ", unquote(text)).strip()
    return (
        re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else None,
        re.sub(r"\s+", " ", description_match.group(1)).strip()[:300] if description_match else None,
        text[:20_000],
    )


def _inspect_page(url: str) -> dict:
    current = url
    try:
        with httpx.Client(timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False, headers={"User-Agent": "EstafaRadar-SafeInspector/1.0"}) as client:
            for _ in range(MAX_REDIRECTS + 1):
                parsed = urlsplit(current)
                if parsed.scheme not in ("http", "https") or not parsed.hostname or not _public_host(parsed.hostname):
                    return {"blocked": True}
                with client.stream("GET", current) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            break
                        current = urljoin(current, location)
                        continue
                    if response.status_code >= 400 or "text/html" not in response.headers.get("content-type", "").lower():
                        return {"final_url": current, "status": response.status_code}
                    chunks = []
                    size = 0
                    for chunk in response.iter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        if size >= MAX_PAGE_BYTES:
                            break
                    html = b"".join(chunks)[:MAX_PAGE_BYTES].decode(response.encoding or "utf-8", errors="replace")
                    title, description, text = _extract_page(html)
                    return {"final_url": current, "title": title, "description": description, "text": text}
    except (httpx.HTTPError, UnicodeError, ValueError):
        return {"unavailable": True}


def _inspect_page_browser(url: str) -> dict:
    """Inspect one page in a fresh browser context with active content blocked."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"unavailable": True, "browser_unavailable": True}

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-sandbox"],
            )
            context = browser.new_context(
                java_script_enabled=False,
                accept_downloads=False,
                service_workers="block",
                user_agent="EstafaRadar-SafeBrowser/1.0",
            )

            def guard_request(route):
                request_url = route.request.url
                parsed = urlsplit(request_url)
                if (
                    parsed.scheme not in ("http", "https")
                    or not parsed.hostname
                    or not _public_host(parsed.hostname)
                ):
                    route.abort()
                elif route.request.resource_type != "document":
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", guard_request)
            page = context.new_page()
            parsed = urlsplit(url)
            if not parsed.hostname or not _public_host(parsed.hostname):
                return {"blocked": True}
            response = page.goto(url, wait_until="domcontentloaded", timeout=7_000)
            if response is None:
                return {"unavailable": True}
            final_url = page.url
            final_host = urlsplit(final_url).hostname
            if not final_host or not _public_host(final_host):
                return {"blocked": True}
            title = page.title()[:200] or None
            description_locator = page.locator('meta[name="description"]')
            description = (
                description_locator.first.get_attribute("content", timeout=1_000)
                if description_locator.count()
                else None
            )
            text = page.locator("body").inner_text(timeout=2_000)[:MAX_BROWSER_TEXT]
            return {
                "final_url": final_url,
                "status": response.status,
                "title": title,
                "description": description[:300] if description else None,
                "text": re.sub(r"\s+", " ", text).strip(),
                "browser_inspected": True,
            }
    except (PlaywrightError, OSError, UnicodeError, ValueError):
        return {"unavailable": True, "browser_unavailable": True}
    return {"unavailable": True}


def analyze_url(value: str, kind: str = "url") -> ScanResult:
    raw = normalize_text(value)
    findings = []
    points = 0
    if re.search(r"[\x00-\x1f\x7f]", raw):
        return _findings_to_verdict(kind, [Finding(code="CONTROL_CHARS", severity="warning", description="La dirección contiene caracteres de control.")], 40, True)
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port  # fuerza validación de puerto
    except ValueError:
        host, parsed = "", None
    if not parsed or parsed.scheme.lower() not in ("http", "https") or not host:
        return _findings_to_verdict(kind, [Finding(code="BAD_URL", severity="warning", description="URL inválida o esquema no admitido. Solo se aceptan HTTP/HTTPS.")], 40, True)
    if parsed.scheme.lower() == "http":
        points += 20
        findings.append(Finding(code="HTTP", severity="warning", description="El enlace usa HTTP sin cifrado de transporte."))
    if parsed.username or parsed.password:
        points += 35
        findings.append(Finding(code="USERINFO", severity="critical", description="Contiene usuario o contraseña incrustados en la dirección."))
    if _is_ip(host):
        points += 20
        findings.append(Finding(code="IP_HOST", severity="warning", description="Utiliza una dirección IP en vez de un dominio."))
    if host.startswith("xn--") or ".xn--" in host:
        points += 20
        findings.append(Finding(code="PUNYCODE", severity="warning", description="Dominio internacionalizado (punycode); puede requerir comprobación visual."))
    if host in SHORTENERS:
        points += 20
        findings.append(Finding(code="SHORT_URL", severity="warning", description="Acortador de URL: oculta el destino final, que NO se siguió."))
    if host.count(".") >= 4 or len(host) > 70:
        points += 15
        findings.append(Finding(code="ODD_HOST", severity="warning", description="Dominio inusualmente largo o con muchos subdominios."))
    if "@" in raw:
        points += 15
        findings.append(Finding(code="AT_SIGN", severity="warning", description="La dirección contiene @; revisa con cuidado su host efectivo."))
    decoded = unquote(parsed.path + "?" + parsed.query).lower()
    if any(term in decoded for term in SENSITIVE_TERMS):
        points += 15
        findings.append(Finding(code="SENSITIVE_QUERY", severity="warning", description="La ruta o parámetros mencionan verificación o datos sensibles."))
    if any(brand in host for brand in BRANDS) and ("-" in host or host.count(".") > 2):
        points += 20
        findings.append(Finding(code="BRAND_LIKE", severity="warning", description="Dominio con nombre semejante a una marca; NO se ha verificado su titularidad."))
    if port and port not in (80, 443):
        points += 10
        findings.append(Finding(code="PORT", severity="info", description="Puerto web no habitual."))
    page = _inspect_page_browser(raw) if os.getenv("BROWSER_INSPECTION", "true").lower() == "true" else _inspect_page(raw)
    inspection_mode = "playwright" if page.get("browser_inspected") else "http_fallback"
    if page.get("browser_unavailable"):
        page = _inspect_page(raw)
        inspection_mode = "http_fallback"
    page_title = page.get("title")
    page_description = page.get("description")
    page_text = page.get("text", "").casefold()
    page_content = f"{page_title or ''} {page_description or ''} {page_text}".casefold()
    category = "sitio web general"
    access_restricted = False
    page_checks = [
        ("LOGIN_PAGE", r"(iniciar sesi[oó]n|iniciar sesion|sign in|log in|contrase[nñ]a|password)", 20, "La página parece solicitar inicio de sesión o contraseña.", "inicio de sesión"),
        ("PAYMENT_PAGE", r"(pago|tarjeta|cvv|transferencia|yape|plin|checkout)", 25, "La página contiene lenguaje relacionado con pagos o datos financieros.", "pagos"),
        ("REWARD_PAGE", r"(premio|ganaste|bono|sorteo|regalo)", 20, "La página promete un premio o beneficio.", "premios"),
        ("URGENT_PAGE", r"(urgente|inmediatamente|cuenta suspendida|verifica ahora)", 20, "La página usa urgencia o amenaza para inducir una acción.", "verificación urgente"),
        ("UNOFFICIAL_STREAMING", r"(ver pel[ií]culas gratis|series gratis|anime gratis|pel[ií]culas online gratis|streaming gratis|hd online|watch free|free movies|free series)", 35, "La página promociona streaming gratuito no oficial; puede incluir anuncios agresivos, redirecciones o descargas maliciosas.", "streaming no oficial"),
        ("PIRACY_SIGNALS", r"(cuevana|pel[ií]culas gratis|series y anime|ver gratis|descargar pel[ií]culas|torrent|subt[ií]tulos gratis)", 25, "El contenido sugiere distribución no oficial de películas o series; extrema la precaución con botones, ventanas emergentes y descargas.", "entretenimiento no oficial"),
        ("DOWNLOAD_BAIT", r"(descarga ahora|download now|instala|actualiza tu reproductor|player|plugin)", 25, "La página puede intentar inducir una descarga o instalación para reproducir el contenido.", "descargas potencialmente riesgosas"),
    ]
    for code, pattern, extra, description, detected_category in page_checks:
        if re.search(pattern, page_content):
            points += extra
            category = detected_category
            findings.append(Finding(code=code, severity="critical" if code in {"DOWNLOAD_BAIT"} else "warning", description=description))
    if page.get("blocked"):
        findings.append(Finding(code="PRIVATE_DESTINATION_BLOCKED", severity="critical", description="Se bloqueó la consulta porque el destino apunta a una red privada o local."))
        points += 45
    elif page.get("unavailable"):
        findings.append(Finding(code="PAGE_UNAVAILABLE", severity="info", description="No fue posible consultar la página; el resultado se basa en la URL."))
    elif page.get("status", 200) >= 400:
        status = page["status"]
        challenge = re.search(
            r"(just a moment|checking your browser|verify you are human|"
            r"verifying you are human|cloudflare|attention required|captcha)",
            page_content,
        )
        if status in (401, 403) or challenge:
            access_restricted = True
            points += 25
            category = "acceso restringido / protección anti-bot"
            findings.append(Finding(
                code="ACCESS_RESTRICTED",
                severity="warning",
                description="El servidor no mostró el contenido real y respondió con una pantalla de acceso restringido o protección anti-bot.",
            ))
        else:
            findings.append(Finding(code="HTTP_ERROR", severity="warning", description=f"El servidor respondió con HTTP {status}; no se pudo verificar el contenido."))
    if not findings:
        findings.append(Finding(code="NO_HEURISTIC", severity="info", description="No se encontraron indicadores con las reglas locales disponibles."))
    return _findings_to_verdict(
        kind, findings, points, uncertain=(access_restricted or points == 0),
        visited_destination=bool(page.get("final_url")), category=category,
        page_title=page_title, page_description=page_description, final_url=page.get("final_url"),
        inspection_mode=inspection_mode,
    )


def analyze_message(value: str) -> ScanResult:
    v = normalize_text(value)
    low = v.casefold()
    findings = []
    points = 0
    checks = [
      ("OTP_REQUEST", r"(?:compart[ea]|env[ií]a|dame|escribe).{0,50}(?:c[oó]digo|otp|clave)", 45, "Solicita compartir un código o credencial."),
      ("URGENCY", r"(?:urgente|inmediato|24 horas|bloquead[ao]|suspendid[ao])", 20, "Emplea urgencia o amenaza de suspensión."),
      ("REWARD", r"(?:ganaste|premio|bono|regalo|sorteo)", 20, "Promete un premio o beneficio."),
      ("PAYMENT", r"(?:deposita|transfiere|paga para|comisi[oó]n de retiro)", 25, "Solicita efectuar un pago o transferencia."),
    ]
    for code, pattern, score, desc in checks:
        if re.search(pattern, low):
            points += score
            findings.append(Finding(code=code, severity="critical" if score >= 40 else "warning", description=desc))
    urls = re.findall(r"https?://[^\s<>\"']+", v, flags=re.I)
    if urls:
        points += 15
        findings.append(Finding(code="INCLUDED_URL", severity="warning", description="Contiene enlaces; revísalos también de forma independiente."))
    if not findings:
        findings.append(Finding(code="NOT_ENOUGH", severity="info", description="No hay señales reconocidas por las reglas actuales."))
    return _findings_to_verdict("message", findings, points, uncertain=(points == 0))


def analyze_qr(text: str) -> ScanResult:
    v = normalize_text(text)
    if v.lower().startswith(("http://", "https://")):
        return analyze_url(v, "qr")
    return _findings_to_verdict("qr", [Finding(code="QR_DATA", severity="info", description="QR decodificado como texto o contenido no web. No se ejecutó su contenido.")], 0, True)

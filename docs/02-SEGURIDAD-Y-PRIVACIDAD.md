# Modelo de amenazas y controles

**Amenazas:** URL SSRF, acceso a metadatos cloud, rebinding DNS, redirects a rangos internos, XSS, QR con acciones (tel:, sms:, wifi:, intent:), payloads de imagen maliciosos, archivo zip-bomb, fuga de mensajes privados, abuso de API, falsos negativos.

**Controles actuales:** no fetch remoto (reduce fuertemente SSRF), longitud máxima 6000, FastAPI/Pydantic, CORS explícito, decodificación en navegador, sin almacenamiento del contenido ni persistencia de resultados en el servidor. No hay botones de apertura de enlaces analizados.

**Controles obligatorios antes de producción:** autenticación, cuotas/rate limit, protección CSRF si se usan cookies, CSP, HSTS, HTTPS, revisión de dependencias, observabilidad sin datos personales, política de privacidad y eliminación, RLS en Supabase, consentimiento de análisis a proveedores de terceros y pruebas de pentesting.

**Al incorporar navegación dinámica:** máquinas virtuales efímeras endurecidas, red aislada y egress policy, prohibir tráfico a IP internas/localhost/metadata, DNS verificado en cada conexión, límites de redirección y descarga, no montar credenciales, asegurar limpieza. Docker o Playwright por sí solos no bastan para analizar material hostil.

**Análisis QR:** el permiso de cámara se pide únicamente al pulsar. No se sube vídeo ni imagen al servidor; solo se envía el texto decodificado cuando usuario pulsa 'Analizar'. Los formatos no HTTP/HTTPS se reportan como texto, sin ejecutar deep-links o instrucciones.

**Indicadores:** las reglas detectan señales de riesgo, no prueban fraude; no etiquetar personas ni comercios como delincuentes. Mostrar incertidumbre y canal de revisión.

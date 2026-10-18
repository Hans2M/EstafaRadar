# API y datos

## Endpoints funcionales
- `GET /api/v1/health`: salud y flags de operación.
- `POST /api/v1/analyze/url`: `{"value":"https://example.com"}`.
- `POST /api/v1/analyze/qr`: `{"value":"texto decodificado"}`.
- `POST /api/v1/analyze/message`: `{"value":"texto sospechoso"}`.

Responden `{kind, verdict, score, findings: [{code,severity,description}], advice, limitations, visited_destination, category, page_title, page_description, final_url, inspection_mode}`. Para enlaces HTTP/HTTPS, el backend usa un contexto Playwright efímero: bloquea JavaScript, descargas, recursos no documentales y destinos privados/locales, aplica timeout y extrae título, descripción y texto visible. Si Chromium no está disponible, usa el lector HTTP limitado como fallback (`inspection_mode=http_fallback`).

`visited_destination` indica que se pudo leer la respuesta del documento; no significa que el sitio sea seguro. `category`, `page_title` y `page_description` son una identificación orientativa del contenido. El score **no es una probabilidad** ni está calibrado con corpus de fraudes reales.

## Tablas (futuro habilitadas con consentimiento)
- `app_users`: identidad externa.
- `scan_jobs`: tipo, hash de contenido, veredicto, versión y retención; evitar valor bruto.
- `scan_findings`: indicadores individuales.
- `reputation_providers`: activación y verificación de licencia comercial.
- `audit_events`: acciones sin registrar secretos.

El esquema se inicia desde `database/schema.sql` en PostgreSQL al crear un volumen nuevo. Para cambios posteriores, crear migraciones con Alembic; no volver a ejecutar manualmente el init para alterar datos productivos.

## Contrato de seguridad
La API no abre la URL en un navegador ni ejecuta contenido activo. La inspección HTTP tiene timeout, límite de bytes, límite de redirecciones y bloqueo básico de IPs privadas para reducir SSRF. No valida comprobantes bancarios ni sustituye reputación externa. No colocar el texto enviado al usuario en enlaces `<a href>`. CORS no es autenticación.

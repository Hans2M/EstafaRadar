# EstafaRadar Perú — arquitectura profesional + MVP ejecutable

**Objetivo:** analizar enlaces, texto sospechoso y códigos QR (cámara o imagen) sin navegar automáticamente a la URL ni ejecutar contenido potencialmente peligroso. El resultado es **orientativo**, nunca un certificado de seguridad.

## Funciones incluidas en este paquete
- Frontend React/TypeScript/Vite con secciones **Enlaces, QR (cámara o imagen), Mensajes, Historial local**.
- Lector QR con cámara por `html5-qrcode` (requiere HTTPS o localhost y permiso explícito). También permite seleccionar una imagen QR. **Decodifica solamente**, nunca abre el destino.
- Backend FastAPI con validación de URLs, heurísticas deterministas y clasificación explicable; devuelve **bajo / moderado / alto / no concluyente**.
- Inspección opcional con Playwright/Chromium en contexto efímero: JavaScript, descargas y recursos no documentales bloqueados; extrae título, descripción y texto visible sin interactuar con la página.
- PostgreSQL: esquema SQL para usuarios, análisis, observaciones, proveedores de reputación, auditoría y políticas de retención. Guardado opcional por flag; por defecto **no persiste contenido**.
- Tests básicos y Docker Compose de entorno local; referencias de endpoints `/docs`.

### Inicio rápido
1. Instala Docker Desktop y Node.js 20+.
2. En la raíz: `docker compose up --build -d` (levanta PostgreSQL y API). Comprueba `http://localhost:8000/docs`.
3. `cd frontend && npm install && npm run dev`.
4. Abre `http://localhost:5173`. Autoriza la cámara para analizar un QR o carga una imagen.
5. Pruebas backend: `cd backend && pip install -r requirements.txt && pytest -q`.

> `http://localhost` permite cámara en la mayoría de navegadores. En un dominio remoto se necesita HTTPS y permisos. El acceso a cámara no funciona en todos los navegadores/dispositivos; se incluye alternativa de imagen.

## Seguridad: límites honestos
- Los enlaces se inspeccionan con un navegador controlado y efímero, sin ejecutar JavaScript ni cargar recursos activos. Se aplican timeouts, límites de contenido y bloqueo de destinos privados; esto no sustituye una sandbox ni un proveedor de reputación.
- El análisis de QR decodifica texto localmente y envía la cadena al backend **solo al pulsar Analizar**.
- Sin motores externos de reputación, los resultados solo reflejan **heurísticas**. Un enlace desconocido no es sinónimo de seguro.
- No se afirma verificar pagos de Yape/Plin con una captura ni identificar realmente al titular de un número.
- El MVP no analiza archivos ejecutables ni hace sandboxing. Estas funciones se definen como **fase posterior** en la documentación.
- Base de datos preparada, pero la persistencia de análisis está apagada (`STORE_ANALYSES=false`) hasta añadir autenticación, consentimiento, RLS y política de privacidad.

Consulta `docs/` para arquitectura, modelado, amenazas, pantallas, API, despliegue y roadmap.

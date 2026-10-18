# Despliegue responsable

**Desarrollo:** `docker compose up --build -d` y `cd frontend && npm install && npm run dev`.

**Producción:** frontend en hosting HTTPS estático; backend FastAPI sobre contenedores administrados con TLS, secretos en vault, workers sin privilegios, base PostgreSQL administrada con backups cifrados, política de red, rate limiting y métricas. En Supabase se puede adoptar PostgreSQL/Auth; no hay que introducir claves `service_role` en el navegador. No publicar el puerto de PostgreSQL.

**Aviso:** la configuración Docker incluida es solo para uso local. Cambia todas las credenciales y configura TLS, WAF, retención, autenticación y cuotas antes de exposición pública.

# Hoja de ruta

## Etapa 1 (incluida)
Enlaces, QR de cámara/imagen y mensajes. Motor heurístico estático, reportes explicables, tests y PostgreSQL modelado.

## Etapa 2
Integración con reputación comercial bajo contrato, caché con TTL, límites por usuario, versiones de motor, autenticación Supabase y RLS, consentimiento, borrado de datos, informes exportables.

## Etapa 3
Motor de comprobantes: OCR aislado y señales de alteración, pero confirmación bancaria únicamente por canales autorizados. Análisis estático de documentos bajo límites y sandbox profesional si se requiere ejecución.

## Etapa 4
Detección calibrada con datos legítimamente obtenidos, evaluaciones por modalidad de fraude en Perú, monitoreo de falsos positivos/negativos, mecanismos de apelación y analítica institucional.

## Criterios de aceptación
- Cámara no inicia sin gesto explícito y puede detenerse.
- QR se decodifica sin navegar automáticamente.
- La API nunca hace fetch a URLs ingresadas.
- `javascript:` no se acepta como URL navegable.
- URLs sin indicadores devuelven `no_concluyente`, no 'seguro'.
- Resultados siempre muestran límites y recomendaciones.
- En servidor no se retiene contenido de consultas en el MVP.

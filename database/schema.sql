-- Modelo de evolución: no almacenes contenidos sin consentimiento explícito.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS app_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_subject TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS scan_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES app_users(id) ON DELETE SET NULL,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('url','qr','message','file','receipt','phone')),
  input_hash TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('bajo','moderado','alto','no_concluyente')),
  score SMALLINT NOT NULL CHECK (score BETWEEN 0 AND 100),
  engine_version TEXT NOT NULL,
  consent_to_retain BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days')
);
CREATE INDEX IF NOT EXISTS ix_scan_jobs_user_created ON scan_jobs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_scan_jobs_expires ON scan_jobs(expires_at);
CREATE TABLE IF NOT EXISTS scan_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reputation_providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_key TEXT UNIQUE NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  commercial_license_confirmed BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID REFERENCES app_users(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- En producción: autenticar usuario, activar y probar RLS si se usa Supabase directamente.
-- No habilitar endpoints de lectura de estas tablas antes de aplicar políticas por usuario.

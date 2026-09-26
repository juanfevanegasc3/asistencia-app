-- Migración 002: permite que los estudiantes tengan su propia cuenta
-- Ejecutar UNA sola vez sobre una base de datos que ya existe:
-- wrangler d1 execute asistencia_db --remote --file=./migration_002_login_estudiantes.sql

ALTER TABLE students ADD COLUMN password_hash TEXT;
ALTER TABLE students ADD COLUMN salt TEXT;
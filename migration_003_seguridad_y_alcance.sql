-- Migración 003: seguridad, alcance por docente, auditoría y archivado lógico.
--
-- IMPORTANTE:
--   * Es una migración ADITIVA: no elimina ni modifica datos existentes.
--   * Se aplica UNA sola vez sobre bases de datos creadas con el esquema anterior.
--   * NO se debe aplicar a una base creada con el schema.sql actual.
--
-- Antes de ejecutarla, crea un respaldo:
--   wrangler d1 export asistencia_db --remote --output=backup-antes-003.sql
--
-- Ejecutar:
--   wrangler d1 execute asistencia_db --remote --file=./migration_003_seguridad_y_alcance.sql

-- Propiedad de cursos y estudiantes (NULL = institucional/compartido)
ALTER TABLE courses ADD COLUMN teacher_id INTEGER REFERENCES teachers(id) ON DELETE SET NULL;
ALTER TABLE courses ADD COLUMN activo INTEGER NOT NULL DEFAULT 1;

ALTER TABLE students ADD COLUMN teacher_id INTEGER REFERENCES teachers(id) ON DELETE SET NULL;
ALTER TABLE students ADD COLUMN activo INTEGER NOT NULL DEFAULT 1;

-- Versión de sesión para revocar tokens al cambiar o restablecer contraseñas
ALTER TABLE teachers ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE students ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1;

-- Metadatos de auditoría en la asistencia
ALTER TABLE attendance ADD COLUMN origen TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE attendance ADD COLUMN marcado_por_rol TEXT;
ALTER TABLE attendance ADD COLUMN marcado_por_id INTEGER;
ALTER TABLE attendance ADD COLUMN marcado_por_nombre TEXT;
ALTER TABLE attendance ADD COLUMN updated_at TEXT;

-- Historial de cambios de asistencia
CREATE TABLE IF NOT EXISTS attendance_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attendance_id INTEGER,
  enrollment_id INTEGER NOT NULL,
  course_id INTEGER,
  fecha TEXT NOT NULL,
  estado_anterior TEXT,
  estado_nuevo TEXT NOT NULL,
  origen TEXT NOT NULL,
  actor_rol TEXT,
  actor_id INTEGER,
  actor_nombre TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Límites de intentos para login y registro
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_courses_teacher ON courses(teacher_id);
CREATE INDEX IF NOT EXISTS idx_courses_activo ON courses(activo);
CREATE INDEX IF NOT EXISTS idx_students_teacher ON students(teacher_id);
CREATE INDEX IF NOT EXISTS idx_students_activo ON students(activo);
CREATE INDEX IF NOT EXISTS idx_audit_enrollment ON attendance_audit(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_audit_fecha ON attendance_audit(fecha);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);

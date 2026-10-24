-- Esquema de base de datos para el sistema de asistencia
-- Se ejecuta una sola vez al configurar una base D1 nueva.
-- Para bases de datos existentes usa las migraciones (migration_003_*.sql).

CREATE TABLE IF NOT EXISTS teachers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  session_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  descripcion TEXT,
  teacher_id INTEGER REFERENCES teachers(id) ON DELETE SET NULL,
  activo INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  documento TEXT UNIQUE,
  email TEXT,
  telefono TEXT,
  password_hash TEXT,
  salt TEXT,
  teacher_id INTEGER REFERENCES teachers(id) ON DELETE SET NULL,
  activo INTEGER NOT NULL DEFAULT 1,
  session_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(student_id, course_id)
);

CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  enrollment_id INTEGER NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
  fecha TEXT NOT NULL, -- formato YYYY-MM-DD
  estado TEXT NOT NULL CHECK(estado IN ('presente','ausente','tarde','justificado')),
  origen TEXT NOT NULL DEFAULT 'manual',
  marcado_por_rol TEXT,
  marcado_por_id INTEGER,
  marcado_por_nombre TEXT,
  updated_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(enrollment_id, fecha)
);

-- Historial de cambios de asistencia para auditoría
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

-- Límites de intentos para proteger el inicio de sesión y el registro
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_enrollments_course ON enrollments(course_id);
CREATE INDEX IF NOT EXISTS idx_enrollments_student ON enrollments(student_id);
CREATE INDEX IF NOT EXISTS idx_attendance_fecha ON attendance(fecha);
CREATE INDEX IF NOT EXISTS idx_attendance_enrollment ON attendance(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_courses_teacher ON courses(teacher_id);
CREATE INDEX IF NOT EXISTS idx_courses_activo ON courses(activo);
CREATE INDEX IF NOT EXISTS idx_students_teacher ON students(teacher_id);
CREATE INDEX IF NOT EXISTS idx_students_activo ON students(activo);
CREATE INDEX IF NOT EXISTS idx_audit_enrollment ON attendance_audit(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_audit_fecha ON attendance_audit(fecha);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);

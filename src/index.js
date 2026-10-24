// ==========================================================
// Sistema de Asistencia - Cloudflare Worker + D1  (v4)
// ==========================================================

import qrcode from "./qrcode.mjs";
import { stringToBytes } from "./qrcode_UTF8.mjs";

qrcode.stringToBytes = stringToBytes;

const ADMIN_COOKIE = "asistencia_admin";
const ADMIN_SESSION_MS = 12 * 60 * 60 * 1000;
const DIA = 24 * 60 * 60 * 1000;
const MAX_ATTENDANCE_BATCH = 300;
const MAX_HISTORY = 500;
const ESTADOS = new Set(["presente", "ausente", "tarde", "justificado"]);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

// ---------- Utilidades ----------
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function intId(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function isValidDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(value + "T00:00:00Z");
  if (Number.isNaN(date.getTime())) return false;
  return date.toISOString().slice(0, 10) === value;
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) return decodeURIComponent(part.slice(index + 1).trim());
  }
  return null;
}

function adminCookie(request, token) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${ADMIN_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${Math.floor(ADMIN_SESSION_MS / 1000)}${secure}`;
}

function clearAdminCookie() {
  return `${ADMIN_COOKIE}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`;
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try {
    const originUrl = new URL(origin);
    const requestUrl = new URL(request.url);
    return originUrl.protocol === requestUrl.protocol && originUrl.host === requestUrl.host;
  } catch (e) {
    return false;
  }
}

function actorFromSession(session) {
  return {
    rol: session.role,
    id: session.id || null,
    nombre: session.nombre || (session.role === "admin" ? "Administrador" : session.role),
  };
}

// ---------- Contraseñas (PBKDF2) ----------
function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}
function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bufToHex(arr);
}
function tempPassword() {
  const chars = "abcdefghjkmnpqrstuvwxyz23456789";
  const a = new Uint8Array(8);
  crypto.getRandomValues(a);
  return [...a].map((x) => chars[x % chars.length]).join("");
}
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBuf(saltHex), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufToHex(bits);
}

// ---------- Tokens firmados con HMAC ----------
function bytesToB64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(str) {
  const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
const b64url = (s) => bytesToB64url(new TextEncoder().encode(s));
const unb64url = (s) => new TextDecoder().decode(b64urlToBytes(s));

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function createToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return body + "." + bytesToB64url(new Uint8Array(sig));
}
async function verifyToken(token, secret) {
  try {
    if (!token || !secret || !token.includes(".")) return null;
    const [body, sig] = token.split(".");
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify("HMAC", key, b64urlToBytes(sig), new TextEncoder().encode(body));
    if (!valid) return null;
    const payload = JSON.parse(unb64url(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

async function validateSessionPayload(payload, env) {
  if (!payload || !payload.role) return null;
  if (payload.role === "docente" || payload.role === "estudiante") {
    const table = payload.role === "docente" ? "teachers" : "students";
    try {
      const row = await env.DB.prepare(
        `SELECT session_version${payload.role === "estudiante" ? ", activo" : ""} FROM ${table} WHERE id = ?`
      )
        .bind(payload.id)
        .first();
      if (!row) return null;
      if (payload.role === "estudiante" && row.activo === 0) return null;
      const current = row.session_version == null ? 1 : row.session_version;
      const tokenVersion = payload.sv == null ? 1 : payload.sv;
      if (current !== tokenVersion) return null;
    } catch (e) {
      // Compatibilidad temporal si la migración 003 aún no se aplicó.
      console.error("No se pudo verificar session_version", e);
    }
  }
  return payload;
}

async function getSession(request, env) {
  const apiKey = request.headers.get("X-API-Key");
  if (apiKey && env.API_KEY && safeEqual(apiKey, env.API_KEY)) return { role: "admin", nombre: "Administrador" };

  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ") && env.SESSION_SECRET) {
    const payload = await verifyToken(auth.slice(7), env.SESSION_SECRET);
    return validateSessionPayload(payload, env);
  }

  const cookieToken = getCookie(request, ADMIN_COOKIE);
  if (cookieToken && env.SESSION_SECRET) {
    const payload = await verifyToken(cookieToken, env.SESSION_SECRET);
    if (payload && payload.role === "admin") return payload;
  }
  return null;
}

// ---------- Rate limiting ----------
async function enforceRateLimit(request, env, bucket, limit, windowMs) {
  const ip =
    request.headers.get("CF-Connecting-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "local";
  const key = bucket + ":" + ip;
  const now = Date.now();
  const cutoff = now - windowMs;
  try {
    await env.DB.prepare(
      `INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN rate_limits.window_start <= ? THEN 1 ELSE rate_limits.count + 1 END,
         window_start = CASE WHEN rate_limits.window_start <= ? THEN ? ELSE rate_limits.window_start END`
    ).bind(key, now, cutoff, cutoff, now).run();

    const row = await env.DB.prepare("SELECT count, window_start FROM rate_limits WHERE key = ?").bind(key).first();
    if (row && row.count > limit) {
      return { ok: false, retry: Math.max(1, Math.ceil((row.window_start + windowMs - now) / 1000)) };
    }
    if (Math.random() < 0.02) {
      await env.DB.prepare("DELETE FROM rate_limits WHERE window_start < ?").bind(now - 7 * DIA).run();
    }
    return { ok: true };
  } catch (e) {
    // Si la migración 003 aún no se aplicó, no bloqueamos el acceso.
    console.error("No se pudo aplicar rate limiting", e);
    return { ok: true };
  }
}

function rateLimited(retry) {
  return json(
    { error: "Demasiados intentos. Espera unos minutos e inténtalo de nuevo." },
    429,
    { "Retry-After": String(retry) }
  );
}

// ---------- Alcance por rol ----------
function courseFilter(session, alias = "c") {
  if (session.role === "admin") return { sql: "1=1", binds: [] };
  return { sql: `(${alias}.teacher_id = ? OR ${alias}.teacher_id IS NULL)`, binds: [session.id] };
}

function studentFilter(session, alias = "s") {
  if (session.role === "admin") return { sql: "1=1", binds: [] };
  return {
    sql: `(${alias}.teacher_id = ? OR ${alias}.teacher_id IS NULL OR EXISTS (
      SELECT 1 FROM enrollments e2
      JOIN courses c2 ON c2.id = e2.course_id
      WHERE e2.student_id = ${alias}.id AND (c2.teacher_id = ? OR c2.teacher_id IS NULL)
    ))`,
    binds: [session.id, session.id],
  };
}

function canAccessCourse(session, course) {
  return !!course && (session.role === "admin" || course.teacher_id === session.id || course.teacher_id === null);
}

function canManageCourse(session, course) {
  return !!course && (session.role === "admin" || course.teacher_id === session.id);
}

function canManageStudent(session, student) {
  return !!student && (session.role === "admin" || student.teacher_id === session.id);
}

async function getVisibleCourse(env, session, courseId) {
  const filter = courseFilter(session);
  return env.DB.prepare(
    `SELECT c.*, t.nombre AS docente
     FROM courses c
     LEFT JOIN teachers t ON t.id = c.teacher_id
     WHERE c.id = ? AND ${filter.sql}`
  ).bind(courseId, ...filter.binds).first();
}

async function getVisibleStudent(env, session, studentId) {
  const filter = studentFilter(session);
  return env.DB.prepare(
    `SELECT s.*, t.nombre AS docente
     FROM students s
     LEFT JOIN teachers t ON t.id = s.teacher_id
     WHERE s.id = ? AND ${filter.sql}`
  ).bind(studentId, ...filter.binds).first();
}

async function teacherExists(env, teacherId) {
  if (!teacherId) return true;
  return !!(await env.DB.prepare("SELECT id FROM teachers WHERE id = ?").bind(teacherId).first());
}

// ---------- Handlers ----------
async function handleApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = request.method;

  if (!["GET", "HEAD", "OPTIONS"].includes(method) && !sameOrigin(request)) {
    return json({ error: "Origen no permitido" }, 403);
  }

  // ---------- RUTAS PÚBLICAS ----------

  if (path === "/logout" && method === "POST") {
    return json({ ok: true }, 200, { "Set-Cookie": clearAdminCookie() });
  }

  if (path === "/login" && method === "POST") {
    if (!env.SESSION_SECRET) return json({ error: "Falta configurar SESSION_SECRET en el servidor" }, 500);
    const rl = await enforceRateLimit(request, env, "login-admin", 10, 10 * 60 * 1000);
    if (!rl.ok) return rateLimited(rl.retry);

    const body = await request.json().catch(() => ({}));
    if (body.apiKey && env.API_KEY && safeEqual(String(body.apiKey), env.API_KEY)) {
      const token = await createToken(
        { role: "admin", nombre: "Administrador", exp: Date.now() + ADMIN_SESSION_MS },
        env.SESSION_SECRET
      );
      return json({ ok: true, role: "admin", nombre: "Administrador" }, 200, {
        "Set-Cookie": adminCookie(request, token),
      });
    }
    return json({ ok: false, error: "Clave incorrecta" }, 401);
  }

  if (path === "/login-docente" && method === "POST") {
    if (!env.SESSION_SECRET) return json({ error: "Falta configurar SESSION_SECRET en el servidor" }, 500);
    const rl = await enforceRateLimit(request, env, "login-docente", 15, 10 * 60 * 1000);
    if (!rl.ok) return rateLimited(rl.retry);

    const body = await request.json().catch(() => ({}));
    const { results } = await env.DB.prepare("SELECT * FROM teachers WHERE email = ?")
      .bind(String(body.email || "").toLowerCase().trim()).all();
    const t = results[0];
    if (!t) return json({ ok: false, error: "Email o contraseña incorrectos" }, 401);
    const hash = await hashPassword(String(body.password || ""), t.salt);
    if (!safeEqual(hash, t.password_hash)) return json({ ok: false, error: "Email o contraseña incorrectos" }, 401);
    const token = await createToken(
      {
        role: "docente",
        id: t.id,
        nombre: t.nombre,
        email: t.email,
        sv: t.session_version == null ? 1 : t.session_version,
        exp: Date.now() + 7 * DIA,
      },
      env.SESSION_SECRET
    );
    return json({ ok: true, role: "docente", token, nombre: t.nombre });
  }

  if (path === "/register-docente" && method === "POST") {
    if (!env.SESSION_SECRET) return json({ error: "Falta configurar SESSION_SECRET en el servidor" }, 500);
    const rl = await enforceRateLimit(request, env, "register-docente", 10, 10 * 60 * 1000);
    if (!rl.ok) return rateLimited(rl.retry);

    const b = await request.json().catch(() => ({}));
    if (!env.CODIGO_DOCENTE) {
      return json({ error: "El registro público de docentes está deshabilitado. Pide al administrador que cree tu cuenta." }, 403);
    }
    if (!b.codigo || !safeEqual(String(b.codigo), env.CODIGO_DOCENTE)) {
      return json({ error: "Código de invitación incorrecto" }, 403);
    }
    if (!b.nombre || !b.email || !b.password) return json({ error: "Faltan datos" }, 400);
    if (String(b.password).length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);

    const salt = randomHex();
    const hash = await hashPassword(String(b.password), salt);
    const email = String(b.email).toLowerCase().trim();
    try {
      const r = await env.DB.prepare(
        "INSERT INTO teachers (nombre, email, password_hash, salt) VALUES (?, ?, ?, ?)"
      ).bind(String(b.nombre).trim(), email, hash, salt).run();
      const token = await createToken(
        { role: "docente", id: r.meta.last_row_id, nombre: String(b.nombre).trim(), email, sv: 1, exp: Date.now() + 7 * DIA },
        env.SESSION_SECRET
      );
      return json({ ok: true, token, nombre: String(b.nombre).trim() });
    } catch (e) {
      return json({ error: "Ese email ya está registrado. Inicia sesión en vez de registrarte." }, 400);
    }
  }

  if (path === "/register-estudiante" && method === "POST") {
    if (!env.SESSION_SECRET) return json({ error: "Falta configurar SESSION_SECRET en el servidor" }, 500);
    const rl = await enforceRateLimit(request, env, "register-estudiante", 10, 10 * 60 * 1000);
    if (!rl.ok) return rateLimited(rl.retry);

    const b = await request.json().catch(() => ({}));
    const documento = String(b.documento || "").trim();
    if (!b.nombre || !documento || !b.password) return json({ error: "Faltan datos (nombre, documento y contraseña)" }, 400);
    if (String(b.password).length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);

    const salt = randomHex();
    const hash = await hashPassword(String(b.password), salt);
    const { results } = await env.DB.prepare("SELECT * FROM students WHERE documento = ?").bind(documento).all();
    const existente = results[0];
    let studentId;
    let sessionVersion = 1;

    if (existente) {
      if (existente.password_hash) {
        return json({ error: "Ya existe una cuenta con ese documento. Inicia sesión; si olvidaste la contraseña, pide a tu docente que la restablezca." }, 400);
      }
      if (existente.activo === 0) {
        return json({ error: "Esta cuenta está archivada. Pide a tu docente que la reactive antes de registrarte." }, 403);
      }
      sessionVersion = existente.session_version == null ? 1 : existente.session_version;
      await env.DB.prepare(
        "UPDATE students SET password_hash = ?, salt = ?, nombre = ?, email = COALESCE(?, email), session_version = ? WHERE id = ?"
      ).bind(hash, salt, String(b.nombre).trim(), b.email || null, sessionVersion, existente.id).run();
      studentId = existente.id;
    } else {
      const r = await env.DB.prepare(
        "INSERT INTO students (nombre, documento, email, telefono, password_hash, salt) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(String(b.nombre).trim(), documento, b.email || null, b.telefono || null, hash, salt).run();
      studentId = r.meta.last_row_id;
    }
    const token = await createToken(
      { role: "estudiante", id: studentId, nombre: String(b.nombre).trim(), sv: sessionVersion, exp: Date.now() + 30 * DIA },
      env.SESSION_SECRET
    );
    return json({ ok: true, token, nombre: String(b.nombre).trim() });
  }

  if (path === "/login-estudiante" && method === "POST") {
    if (!env.SESSION_SECRET) return json({ error: "Falta configurar SESSION_SECRET en el servidor" }, 500);
    const rl = await enforceRateLimit(request, env, "login-estudiante", 15, 10 * 60 * 1000);
    if (!rl.ok) return rateLimited(rl.retry);

    const body = await request.json().catch(() => ({}));
    const { results } = await env.DB.prepare("SELECT * FROM students WHERE documento = ?")
      .bind(String(body.documento || "").trim()).all();
    const s = results[0];
    if (!s || !s.password_hash || s.activo === 0) return json({ ok: false, error: "Documento o contraseña incorrectos" }, 401);
    const hash = await hashPassword(String(body.password || ""), s.salt);
    if (!safeEqual(hash, s.password_hash)) return json({ ok: false, error: "Documento o contraseña incorrectos" }, 401);
    const token = await createToken(
      {
        role: "estudiante",
        id: s.id,
        nombre: s.nombre,
        sv: s.session_version == null ? 1 : s.session_version,
        exp: Date.now() + 30 * DIA,
      },
      env.SESSION_SECRET
    );
    return json({ ok: true, role: "estudiante", token, nombre: s.nombre });
  }

  if (path === "/public/token-info" && method === "GET") {
    const p = await verifyToken(url.searchParams.get("token") || "", env.SESSION_SECRET);
    if (!p || !p.course_id) return json({ ok: false });
    const c = await env.DB.prepare("SELECT nombre FROM courses WHERE id = ?").bind(p.course_id).first();
    return json({ ok: true, type: p.type, curso: c ? c.nombre : "el curso", fecha: p.fecha || null });
  }

  // ---------- DESDE AQUÍ SE REQUIERE SESIÓN ----------
  const session = await getSession(request, env);
  if (!session) return json({ error: "No autorizado" }, 401);

  if (path === "/session" && method === "GET") {
    return json({ ok: true, role: session.role, nombre: session.nombre || null, id: session.id || null });
  }

  // ---------- QR PROPIO ----------
  if (path === "/qr" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const data = typeof b.data === "string" ? b.data : "";
    if (!data || data.length > 2048) return json({ error: "Datos del QR inválidos" }, 400);
    try {
      const qr = qrcode(0, "M");
      qr.addData(data);
      qr.make();
      const svg = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
      return json({ svg });
    } catch (e) {
      console.error("Error generando QR", e);
      return json({ error: "No se pudo generar el código QR" }, 400);
    }
  }

  // QR de asistencia: lo genera admin/docente para un curso + fecha (válido 3 horas)
  if (path === "/attendance/session" && method === "POST") {
    if (session.role === "estudiante") return json({ error: "No autorizado" }, 403);
    const b = await request.json().catch(() => ({}));
    const courseId = intId(b.course_id);
    if (!courseId || !isValidDate(b.fecha)) return json({ error: "Curso o fecha inválidos" }, 400);
    const course = await getVisibleCourse(env, session, courseId);
    if (!course || !course.activo) return json({ error: "Curso no disponible" }, 404);
    const token = await createToken(
      { type: "checkin", course_id: courseId, fecha: b.fecha, exp: Date.now() + 3 * 60 * 60 * 1000 },
      env.SESSION_SECRET
    );
    return json({ token });
  }

  // QR de registro + inscripción a un curso (válido 7 días)
  if (path === "/enroll/session" && method === "POST") {
    if (session.role === "estudiante") return json({ error: "No autorizado" }, 403);
    const b = await request.json().catch(() => ({}));
    const courseId = intId(b.course_id);
    if (!courseId) return json({ error: "Falta course_id" }, 400);
    const course = await getVisibleCourse(env, session, courseId);
    if (!course || !course.activo) return json({ error: "Curso no disponible" }, 404);
    const token = await createToken(
      { type: "enroll", course_id: courseId, exp: Date.now() + 7 * DIA },
      env.SESSION_SECRET
    );
    return json({ token });
  }

  // ---------- RUTAS DEL ESTUDIANTE ----------
  if (path === "/attendance/self" && method === "POST") {
    if (session.role !== "estudiante") return json({ error: "Solo un estudiante puede marcar su asistencia aquí" }, 403);
    const b = await request.json().catch(() => ({}));
    const payload = await verifyToken(b.token || "", env.SESSION_SECRET);
    if (!payload || payload.type !== "checkin" || !isValidDate(payload.fecha)) {
      return json({ error: "El código es inválido o ya venció. Pide uno nuevo a tu docente." }, 400);
    }
    const enr = await env.DB.prepare(
      `SELECT e.id, e.course_id, c.nombre AS curso, c.activo
       FROM enrollments e JOIN courses c ON c.id = e.course_id
       WHERE e.student_id = ? AND e.course_id = ?`
    ).bind(session.id, payload.course_id).first();
    if (!enr) return json({ error: "No estás inscrito en este curso. Pide a tu docente que te inscriba." }, 403);
    if (!enr.activo) return json({ error: "Este curso ya no está disponible." }, 403);

    const actor = actorFromSession(session);
    const res = await env.DB.prepare(
      `INSERT INTO attendance (enrollment_id, fecha, estado, origen, marcado_por_rol, marcado_por_id, marcado_por_nombre, updated_at)
       VALUES (?, ?, 'presente', 'qr', ?, ?, ?, datetime('now'))
       ON CONFLICT(enrollment_id, fecha) DO NOTHING`
    ).bind(enr.id, payload.fecha, actor.rol, actor.id, actor.nombre).run();

    const inserted = res.meta && res.meta.changes > 0;
    if (inserted) {
      await env.DB.prepare(
        `INSERT INTO attendance_audit
         (attendance_id, enrollment_id, course_id, fecha, estado_anterior, estado_nuevo, origen, actor_rol, actor_id, actor_nombre)
         VALUES (NULL, ?, ?, ?, NULL, 'presente', 'qr', ?, ?, ?)`
      ).bind(enr.id, enr.course_id, payload.fecha, actor.rol, actor.id, actor.nombre).run();
    }
    const actual = await env.DB.prepare(
      "SELECT estado FROM attendance WHERE enrollment_id = ? AND fecha = ?"
    ).bind(enr.id, payload.fecha).first();

    return json({
      ok: true,
      ya: !inserted,
      estado: actual ? actual.estado : "presente",
      curso: enr.curso,
      fecha: payload.fecha,
    });
  }

  if (path === "/enroll/self" && method === "POST") {
    if (session.role !== "estudiante") return json({ error: "Solo un estudiante puede inscribirse aquí" }, 403);
    const b = await request.json().catch(() => ({}));
    const payload = await verifyToken(b.token || "", env.SESSION_SECRET);
    if (!payload || payload.type !== "enroll") {
      return json({ error: "El código es inválido o ya venció. Pide uno nuevo a tu docente." }, 400);
    }
    const curso = await env.DB.prepare("SELECT id, nombre, activo FROM courses WHERE id = ?").bind(payload.course_id).first();
    if (!curso) return json({ error: "Ese curso ya no existe" }, 404);
    if (!curso.activo) return json({ error: "Ese curso ya no está disponible" }, 403);
    const ya = await env.DB.prepare("SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?")
      .bind(session.id, payload.course_id).first();
    if (!ya) {
      await env.DB.prepare("INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)")
        .bind(session.id, payload.course_id).run();
    }
    return json({ ok: true, curso: curso.nombre, ya: !!ya });
  }

  if (path === "/me" && method === "GET") {
    if (session.role !== "estudiante") return json({ error: "No autorizado" }, 403);
    const { results } = await env.DB.prepare(
      `SELECT c.id, c.nombre, c.activo,
         SUM(CASE WHEN a.estado = 'presente' THEN 1 ELSE 0 END) AS presente,
         SUM(CASE WHEN a.estado = 'ausente' THEN 1 ELSE 0 END) AS ausente,
         SUM(CASE WHEN a.estado = 'tarde' THEN 1 ELSE 0 END) AS tarde,
         SUM(CASE WHEN a.estado = 'justificado' THEN 1 ELSE 0 END) AS justificado,
         COUNT(a.id) AS total
       FROM enrollments e
       JOIN courses c ON c.id = e.course_id
       LEFT JOIN attendance a ON a.enrollment_id = e.id
       WHERE e.student_id = ?
       GROUP BY c.id ORDER BY c.nombre`
    ).bind(session.id).all();
    return json({ nombre: session.nombre, cursos: results });
  }

  if (path === "/me/password" && method === "POST") {
    if (session.role !== "estudiante") return json({ error: "No autorizado" }, 403);
    const b = await request.json().catch(() => ({}));
    if (!b.nueva || String(b.nueva).length < 6) return json({ error: "La nueva contraseña debe tener al menos 6 caracteres" }, 400);
    const s = await env.DB.prepare("SELECT * FROM students WHERE id = ?").bind(session.id).first();
    if (!s || !s.password_hash) return json({ error: "Cuenta no encontrada" }, 404);
    const actual = await hashPassword(String(b.actual || ""), s.salt);
    if (!safeEqual(actual, s.password_hash)) return json({ error: "La contraseña actual no es correcta" }, 400);

    const salt = randomHex();
    const hash = await hashPassword(String(b.nueva), salt);
    const newVersion = (s.session_version == null ? 1 : s.session_version) + 1;
    await env.DB.prepare(
      "UPDATE students SET password_hash = ?, salt = ?, session_version = ? WHERE id = ?"
    ).bind(hash, salt, newVersion, s.id).run();
    const token = await createToken(
      { role: "estudiante", id: s.id, nombre: s.nombre, sv: newVersion, exp: Date.now() + 30 * DIA },
      env.SESSION_SECRET
    );
    return json({ ok: true, token });
  }

  // Todo lo que sigue es solo para admin/docente
  if (session.role === "estudiante") return json({ error: "No autorizado" }, 403);

  // ---------- DOCENTES (solo administrador) ----------
  if (path === "/teachers" && method === "GET") {
    if (session.role !== "admin") return json({ error: "Solo el administrador puede ver esto" }, 403);
    const { results } = await env.DB.prepare(
      "SELECT id, nombre, email, created_at FROM teachers ORDER BY nombre"
    ).all();
    return json(results);
  }
  const teacherDeleteMatch = path.match(/^\/teachers\/(\d+)$/);
  if (teacherDeleteMatch && method === "DELETE") {
    if (session.role !== "admin") return json({ error: "Solo el administrador puede eliminar docentes" }, 403);
    await env.DB.prepare("DELETE FROM teachers WHERE id = ?").bind(teacherDeleteMatch[1]).run();
    return json({ ok: true });
  }
  const teacherResetMatch = path.match(/^\/teachers\/(\d+)\/reset-password$/);
  if (teacherResetMatch && method === "POST") {
    if (session.role !== "admin") return json({ error: "Solo el administrador puede restablecer claves de docentes" }, 403);
    const pass = tempPassword();
    const salt = randomHex();
    const hash = await hashPassword(pass, salt);
    await env.DB.prepare(
      "UPDATE teachers SET password_hash = ?, salt = ?, session_version = COALESCE(session_version, 1) + 1 WHERE id = ?"
    ).bind(hash, salt, teacherResetMatch[1]).run();
    return json({ ok: true, password: pass });
  }
  if (path === "/teachers" && method === "POST") {
    if (session.role !== "admin") return json({ error: "Solo el administrador puede crear docentes así" }, 403);
    const b = await request.json().catch(() => ({}));
    if (!b.nombre || !b.email || !b.password) return json({ error: "Faltan datos" }, 400);
    if (String(b.password).length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    const salt = randomHex();
    const hash = await hashPassword(String(b.password), salt);
    try {
      const r = await env.DB.prepare(
        "INSERT INTO teachers (nombre, email, password_hash, salt) VALUES (?, ?, ?, ?)"
      ).bind(String(b.nombre).trim(), String(b.email).toLowerCase().trim(), hash, salt).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "Ese email ya está registrado" }, 400);
    }
  }

  // ---------- CURSOS ----------
  if (path === "/courses" && method === "GET") {
    const filter = courseFilter(session);
    const { results } = await env.DB.prepare(
      `SELECT c.id, c.nombre, c.descripcion, c.teacher_id, c.activo, c.created_at, t.nombre AS docente
       FROM courses c
       LEFT JOIN teachers t ON t.id = c.teacher_id
       WHERE ${filter.sql}
       ORDER BY c.activo DESC, c.nombre`
    ).bind(...filter.binds).all();
    return json(results);
  }
  if (path === "/courses" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const nombre = String(b.nombre || "").trim();
    if (!nombre) return json({ error: "Falta el nombre del curso" }, 400);

    let teacherId = session.role === "admin" ? null : session.id;
    if (session.role === "admin" && b.teacher_id !== undefined && b.teacher_id !== null && b.teacher_id !== "") {
      teacherId = intId(b.teacher_id);
      if (!teacherId) return json({ error: "Docente inválido" }, 400);
      if (!(await teacherExists(env, teacherId))) return json({ error: "El docente no existe" }, 400);
    }
    const r = await env.DB.prepare("INSERT INTO courses (nombre, descripcion, teacher_id) VALUES (?, ?, ?)")
      .bind(nombre, b.descripcion ? String(b.descripcion).trim() : null, teacherId).run();
    return json({ id: r.meta.last_row_id });
  }
  const courseIdMatch = path.match(/^\/courses\/(\d+)$/);
  if (courseIdMatch && method === "PATCH") {
    const course = await getVisibleCourse(env, session, Number(courseIdMatch[1]));
    if (!course) return json({ error: "Curso no encontrado" }, 404);
    if (!canManageCourse(session, course)) return json({ error: "No autorizado para modificar este curso" }, 403);

    const b = await request.json().catch(() => ({}));
    const sets = [];
    const binds = [];
    if ("nombre" in b) {
      const nombre = String(b.nombre || "").trim();
      if (!nombre) return json({ error: "El nombre no puede estar vacío" }, 400);
      sets.push("nombre = ?");
      binds.push(nombre);
    }
    if ("descripcion" in b) {
      sets.push("descripcion = ?");
      binds.push(b.descripcion ? String(b.descripcion).trim() : null);
    }
    if (session.role === "admin" && "teacher_id" in b) {
      let teacherId = null;
      if (b.teacher_id !== null && b.teacher_id !== "" && b.teacher_id !== undefined) {
        teacherId = intId(b.teacher_id);
        if (!teacherId || !(await teacherExists(env, teacherId))) return json({ error: "Docente inválido" }, 400);
      }
      sets.push("teacher_id = ?");
      binds.push(teacherId);
    }
    if ("activo" in b) {
      sets.push("activo = ?");
      binds.push(b.activo ? 1 : 0);
    }
    if (!sets.length) return json({ error: "No hay cambios para guardar" }, 400);
    binds.push(course.id);
    await env.DB.prepare(`UPDATE courses SET ${sets.join(", ")} WHERE id = ?`).bind(...binds).run();
    return json({ ok: true });
  }
  if (courseIdMatch && method === "DELETE") {
    const course = await getVisibleCourse(env, session, Number(courseIdMatch[1]));
    if (!course) return json({ error: "Curso no encontrado" }, 404);
    if (!canManageCourse(session, course)) return json({ error: "No autorizado para archivar este curso" }, 403);
    await env.DB.prepare("UPDATE courses SET activo = 0 WHERE id = ?").bind(course.id).run();
    return json({ ok: true, archivado: true });
  }

  // ---------- ESTUDIANTES ----------
  if (path === "/students" && method === "GET") {
    const filter = studentFilter(session);
    const { results } = await env.DB.prepare(
      `SELECT s.id, s.nombre, s.documento, s.email, s.telefono, s.teacher_id, s.activo,
              (s.password_hash IS NOT NULL) AS tiene_cuenta, t.nombre AS docente
       FROM students s
       LEFT JOIN teachers t ON t.id = s.teacher_id
       WHERE ${filter.sql}
       ORDER BY s.activo DESC, s.nombre`
    ).bind(...filter.binds).all();
    return json(results);
  }
  if (path === "/students" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const nombre = String(b.nombre || "").trim();
    if (!nombre) return json({ error: "Falta el nombre del estudiante" }, 400);

    let teacherId = session.role === "admin" ? null : session.id;
    if (session.role === "admin" && b.teacher_id !== undefined && b.teacher_id !== null && b.teacher_id !== "") {
      teacherId = intId(b.teacher_id);
      if (!teacherId) return json({ error: "Docente inválido" }, 400);
      if (!(await teacherExists(env, teacherId))) return json({ error: "El docente no existe" }, 400);
    }
    try {
      const r = await env.DB.prepare(
        "INSERT INTO students (nombre, documento, email, telefono, teacher_id) VALUES (?, ?, ?, ?, ?)"
      ).bind(
        nombre,
        String(b.documento || "").trim() || null,
        b.email ? String(b.email).trim() : null,
        b.telefono ? String(b.telefono).trim() : null,
        teacherId
      ).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "Ese documento ya está registrado" }, 400);
    }
  }
  const studentIdMatch = path.match(/^\/students\/(\d+)$/);
  if (studentIdMatch && method === "PATCH") {
    const student = await getVisibleStudent(env, session, Number(studentIdMatch[1]));
    if (!student) return json({ error: "Estudiante no encontrado" }, 404);
    if (!canManageStudent(session, student)) return json({ error: "No autorizado para modificar este estudiante" }, 403);

    const b = await request.json().catch(() => ({}));
    const sets = [];
    const binds = [];
    if ("nombre" in b) {
      const nombre = String(b.nombre || "").trim();
      if (!nombre) return json({ error: "El nombre no puede estar vacío" }, 400);
      sets.push("nombre = ?");
      binds.push(nombre);
    }
    if ("documento" in b) {
      sets.push("documento = ?");
      binds.push(String(b.documento || "").trim() || null);
    }
    if ("email" in b) {
      sets.push("email = ?");
      binds.push(b.email ? String(b.email).trim() : null);
    }
    if ("telefono" in b) {
      sets.push("telefono = ?");
      binds.push(b.telefono ? String(b.telefono).trim() : null);
    }
    if (session.role === "admin" && "teacher_id" in b) {
      let teacherId = null;
      if (b.teacher_id !== null && b.teacher_id !== "" && b.teacher_id !== undefined) {
        teacherId = intId(b.teacher_id);
        if (!teacherId || !(await teacherExists(env, teacherId))) return json({ error: "Docente inválido" }, 400);
      }
      sets.push("teacher_id = ?");
      binds.push(teacherId);
    }
    if ("activo" in b) {
      sets.push("activo = ?");
      binds.push(b.activo ? 1 : 0);
    }
    if (!sets.length) return json({ error: "No hay cambios para guardar" }, 400);
    binds.push(student.id);
    try {
      await env.DB.prepare(`UPDATE students SET ${sets.join(", ")} WHERE id = ?`).bind(...binds).run();
      return json({ ok: true });
    } catch (e) {
      return json({ error: "Ese documento ya está registrado" }, 400);
    }
  }
  if (studentIdMatch && method === "DELETE") {
    const student = await getVisibleStudent(env, session, Number(studentIdMatch[1]));
    if (!student) return json({ error: "Estudiante no encontrado" }, 404);
    if (!canManageStudent(session, student)) return json({ error: "No autorizado para archivar este estudiante" }, 403);
    await env.DB.prepare("UPDATE students SET activo = 0 WHERE id = ?").bind(student.id).run();
    return json({ ok: true, archivado: true });
  }
  // Restablecer contraseña de un estudiante: genera una clave temporal
  const studentResetMatch = path.match(/^\/students\/(\d+)\/reset-password$/);
  if (studentResetMatch && method === "POST") {
    const student = await getVisibleStudent(env, session, Number(studentResetMatch[1]));
    if (!student) return json({ error: "Estudiante no encontrado" }, 404);
    if (!canManageStudent(session, student)) return json({ error: "No autorizado para restablecer este estudiante" }, 403);
    const pass = tempPassword();
    const salt = randomHex();
    const hash = await hashPassword(pass, salt);
    await env.DB.prepare(
      "UPDATE students SET password_hash = ?, salt = ?, session_version = COALESCE(session_version, 1) + 1 WHERE id = ?"
    ).bind(hash, salt, student.id).run();
    return json({ ok: true, password: pass });
  }

  // ---------- INSCRIPCIONES ----------
  if (path === "/enrollments" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const courseId = intId(b.course_id);
    const studentId = intId(b.student_id);
    if (!courseId || !studentId) return json({ error: "Curso o estudiante inválido" }, 400);
    const course = await getVisibleCourse(env, session, courseId);
    if (!course) return json({ error: "Curso no encontrado" }, 404);
    if (!canManageCourse(session, course)) return json({ error: "No autorizado para inscribir en este curso" }, 403);
    if (!course.activo) return json({ error: "No se puede inscribir en un curso archivado" }, 400);
    const student = await getVisibleStudent(env, session, studentId);
    if (!student) return json({ error: "Estudiante no encontrado" }, 404);
    if (!student.activo) return json({ error: "No se puede inscribir a un estudiante archivado" }, 400);
    try {
      const r = await env.DB.prepare("INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)")
        .bind(studentId, courseId).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "El estudiante ya está inscrito en ese curso" }, 400);
    }
  }
  const enrollDeleteMatch = path.match(/^\/enrollments\/(\d+)$/);
  if (enrollDeleteMatch && method === "DELETE") {
    const enrollment = await env.DB.prepare(
      "SELECT e.id, e.course_id FROM enrollments e WHERE e.id = ?"
    ).bind(enrollDeleteMatch[1]).first();
    if (!enrollment) return json({ error: "Inscripción no encontrada" }, 404);
    const course = await getVisibleCourse(env, session, enrollment.course_id);
    if (!course) return json({ error: "No autorizado" }, 403);
    if (!canManageCourse(session, course)) return json({ error: "No autorizado para modificar este curso" }, 403);
    await env.DB.prepare("DELETE FROM enrollments WHERE id = ?").bind(enrollment.id).run();
    return json({ ok: true });
  }
  const courseStudentsMatch = path.match(/^\/courses\/(\d+)\/students$/);
  if (courseStudentsMatch && method === "GET") {
    const course = await getVisibleCourse(env, session, Number(courseStudentsMatch[1]));
    if (!course) return json({ error: "Curso no encontrado" }, 404);
    const { results } = await env.DB.prepare(
      `SELECT e.id AS enrollment_id, s.id AS student_id, s.nombre, s.documento, s.activo
       FROM enrollments e JOIN students s ON s.id = e.student_id
       WHERE e.course_id = ? AND s.activo = 1 ORDER BY s.nombre`
    ).bind(course.id).all();
    return json(results);
  }

  // ---------- ASISTENCIA ----------
  if (path === "/attendance" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!isValidDate(b.fecha) || !Array.isArray(b.registros) || !b.registros.length) {
      return json({ error: "Datos incompletos o fecha inválida" }, 400);
    }
    if (b.registros.length > MAX_ATTENDANCE_BATCH) {
      return json({ error: `No se pueden guardar más de ${MAX_ATTENDANCE_BATCH} registros a la vez` }, 400);
    }

    const registros = [];
    const seen = new Set();
    for (const item of b.registros) {
      const enrollmentId = intId(item.enrollment_id);
      const estado = String(item.estado || "");
      if (!enrollmentId || !ESTADOS.has(estado)) return json({ error: "Registro de asistencia inválido" }, 400);
      if (seen.has(enrollmentId)) return json({ error: "Hay inscripciones duplicadas en la solicitud" }, 400);
      seen.add(enrollmentId);
      registros.push({ enrollmentId, estado });
    }

    const placeholders = registros.map(() => "?").join(",");
    const ids = registros.map((r) => r.enrollmentId);
    const { results: enrollments } = await env.DB.prepare(
      `SELECT e.id, e.course_id, c.teacher_id, c.activo
       FROM enrollments e JOIN courses c ON c.id = e.course_id
       WHERE e.id IN (${placeholders})`
    ).bind(...ids).all();
    if (enrollments.length !== registros.length) return json({ error: "Una inscripción no existe" }, 400);

    const enrollmentMap = new Map(enrollments.map((e) => [e.id, e]));
    for (const e of enrollments) {
      if (!canAccessCourse(session, e)) return json({ error: "No autorizado para modificar uno de los cursos" }, 403);
      if (!e.activo) return json({ error: "No se puede modificar la asistencia de un curso archivado" }, 400);
    }

    const { results: existing } = await env.DB.prepare(
      `SELECT enrollment_id, estado FROM attendance
       WHERE fecha = ? AND enrollment_id IN (${placeholders})`
    ).bind(b.fecha, ...ids).all();
    const previous = new Map(existing.map((r) => [r.enrollment_id, r.estado]));

    const actor = actorFromSession(session);
    const statements = [];
    let cambios = 0;
    for (const r of registros) {
      const enrollment = enrollmentMap.get(r.enrollmentId);
      const oldState = previous.has(r.enrollmentId) ? previous.get(r.enrollmentId) : null;
      if (oldState !== r.estado) {
        cambios++;
        statements.push(
          env.DB.prepare(
            `INSERT INTO attendance_audit
             (attendance_id, enrollment_id, course_id, fecha, estado_anterior, estado_nuevo, origen, actor_rol, actor_id, actor_nombre)
             VALUES (NULL, ?, ?, ?, ?, ?, 'manual', ?, ?, ?)`
          ).bind(r.enrollmentId, enrollment.course_id, b.fecha, oldState, r.estado, actor.rol, actor.id, actor.nombre)
        );
      }
      statements.push(
        env.DB.prepare(
          `INSERT INTO attendance
             (enrollment_id, fecha, estado, origen, marcado_por_rol, marcado_por_id, marcado_por_nombre, updated_at)
           VALUES (?, ?, ?, 'manual', ?, ?, ?, datetime('now'))
           ON CONFLICT(enrollment_id, fecha) DO UPDATE SET
             estado = excluded.estado,
             origen = excluded.origen,
             marcado_por_rol = excluded.marcado_por_rol,
             marcado_por_id = excluded.marcado_por_id,
             marcado_por_nombre = excluded.marcado_por_nombre,
             updated_at = excluded.updated_at`
        ).bind(r.enrollmentId, b.fecha, r.estado, actor.rol, actor.id, actor.nombre)
      );
    }
    await env.DB.batch(statements);
    return json({ ok: true, guardados: registros.length, cambios });
  }

  if (path === "/attendance" && method === "GET") {
    const courseId = intId(url.searchParams.get("course_id"));
    const fecha = url.searchParams.get("fecha");
    if (!courseId || !isValidDate(fecha)) return json({ error: "Curso o fecha inválidos" }, 400);
    const course = await getVisibleCourse(env, session, courseId);
    if (!course) return json({ error: "Curso no encontrado" }, 404);
    const { results } = await env.DB.prepare(
      `SELECT e.id AS enrollment_id, s.nombre, s.documento, a.estado,
              a.origen, a.marcado_por_nombre, a.updated_at
       FROM enrollments e
       JOIN students s ON s.id = e.student_id
       LEFT JOIN attendance a ON a.enrollment_id = e.id AND a.fecha = ?
       WHERE e.course_id = ? AND s.activo = 1 ORDER BY s.nombre`
    ).bind(fecha, course.id).all();
    return json(results);
  }

  const historyMatch = path.match(/^\/courses\/(\d+)\/history$/);
  if (historyMatch && method === "GET") {
    const course = await getVisibleCourse(env, session, Number(historyMatch[1]));
    if (!course) return json({ error: "Curso no encontrado" }, 404);

    const desde = url.searchParams.get("desde");
    const hasta = url.searchParams.get("hasta");
    if (desde && !isValidDate(desde)) return json({ error: "Fecha inicial inválida" }, 400);
    if (hasta && !isValidDate(hasta)) return json({ error: "Fecha final inválida" }, 400);
    if (desde && hasta && desde > hasta) return json({ error: "El rango de fechas es inválido" }, 400);

    const limitRaw = Number(url.searchParams.get("limit"));
    const offsetRaw = Number(url.searchParams.get("offset"));
    const limit = Number.isInteger(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, MAX_HISTORY) : 100;
    const offset = Number.isInteger(offsetRaw) && offsetRaw > 0 ? offsetRaw : 0;

    const conditions = ["e.course_id = ?"];
    const binds = [course.id];
    if (desde) { conditions.push("a.fecha >= ?"); binds.push(desde); }
    if (hasta) { conditions.push("a.fecha <= ?"); binds.push(hasta); }
    const where = conditions.join(" AND ");

    const countRow = await env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM attendance a
       JOIN enrollments e ON e.id = a.enrollment_id
       WHERE ${where}`
    ).bind(...binds).first();

    const { results } = await env.DB.prepare(
      `SELECT s.nombre, a.fecha, a.estado, a.origen, a.marcado_por_nombre, a.updated_at
       FROM attendance a
       JOIN enrollments e ON e.id = a.enrollment_id
       JOIN students s ON s.id = e.student_id
       WHERE ${where}
       ORDER BY a.fecha DESC, s.nombre
       LIMIT ? OFFSET ?`
    ).bind(...binds, limit, offset).all();

    return json({ items: results, total: countRow ? countRow.total : 0, limit, offset });
  }

  return json({ error: "Ruta no encontrada" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        console.error("Error interno en la API", err);
        return json({ error: "Error interno del servidor" }, 500);
      }
    }
    return new Response(HTML_PAGE, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  },
};

// ==========================================================
// FRONTEND (HTML + CSS + JS embebido)
// ==========================================================
const HTML_PAGE = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0b1220">
<title>Asistencia · Panel académico</title>
<style>
  :root{
    --bg:#f4f6fa; --surface:#fff; --surface-soft:#f8fafc;
    --ink:#0f172a; --ink-2:#334155; --muted:#64748b;
    --line:#e5eaf1; --line-strong:#cbd5e1;
    --brand:#0f766e; --brand-2:#0d9488; --brand-ink:#134e4a; --brand-soft:#e6fffa;
    --sidebar:#0b1220; --sidebar-2:#111c2e;
    --ok:#15803d; --ok-bg:#e8f7ee; --bad:#b91c1c; --bad-bg:#fee2e2;
    --warn:#b45309; --warn-bg:#fef3c7; --info:#1d4ed8; --info-bg:#e0e7ff;
    --radius:16px; --radius-sm:10px;
    --shadow-sm:0 1px 2px rgba(15,23,42,.06);
    --shadow:0 10px 34px rgba(15,23,42,.09);
  }
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{margin:0;font:15px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,"Helvetica Neue",Arial,sans-serif;background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}
  h1,h2,h3{margin:0;font-weight:700;letter-spacing:-.02em;line-height:1.2}
  h2{font-size:16.5px}
  p{margin:0}
  a{color:var(--brand);text-decoration:none}
  a:hover{text-decoration:underline}
  .hidden{display:none!important}
  .muted{color:var(--muted);font-size:13.5px}
  :focus-visible{outline:3px solid rgba(13,148,136,.35);outline-offset:2px}

  /* ---------- Marca ---------- */
  .brand{display:flex;align-items:center;gap:11px}
  .brand-mark{width:38px;height:38px;flex:none;border-radius:11px;display:grid;place-items:center;background:linear-gradient(145deg,var(--brand-2),var(--brand));color:#fff;box-shadow:0 6px 16px rgba(13,148,136,.25)}
  .brand-mark svg{width:20px;height:20px}
  .brand-text{display:flex;flex-direction:column;line-height:1.2}
  .brand-text strong{font-size:15.5px;letter-spacing:-.01em}
  .brand-text small{font-size:11px;letter-spacing:.08em;text-transform:uppercase;opacity:.65}
  .brand-light{color:#fff}
  .brand-light small{color:#94a3b8;opacity:1}
  .brand-dark{color:var(--ink)}
  .brand-dark small{color:var(--muted);opacity:1}

  /* ---------- Formularios ---------- */
  .field{margin-bottom:15px}
  label{display:block;font-size:12.5px;font-weight:600;margin-bottom:6px;color:var(--ink-2)}
  input,select{width:100%;padding:10px 12px;border:1px solid var(--line-strong);border-radius:9px;font:inherit;font-size:14px;background:#fff;color:var(--ink);transition:border-color .15s,box-shadow .15s}
  input::placeholder{color:#94a3b8}
  input:focus,select:focus{outline:none;border-color:var(--brand-2);box-shadow:0 0 0 3px rgba(13,148,136,.14)}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:640px){.row{grid-template-columns:1fr}}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;border:1px solid transparent;border-radius:9px;padding:10px 17px;font:inherit;font-size:14px;font-weight:600;cursor:pointer;background:var(--brand);color:#fff;box-shadow:0 1px 2px rgba(15,118,110,.2);transition:background .15s,transform .15s,box-shadow .15s;white-space:nowrap}
  .btn:hover{background:var(--brand-ink);box-shadow:0 4px 12px rgba(15,118,110,.22)}
  .btn:active{transform:translateY(1px)}
  .btn svg{width:16px;height:16px}
  .btn.block{width:100%}
  .btn.ghost{background:#fff;color:var(--ink-2);border-color:var(--line-strong);box-shadow:none}
  .btn.ghost:hover{background:var(--surface-soft);color:var(--ink);box-shadow:none}
  .btn.light{background:rgba(255,255,255,.1);color:#fff;border-color:rgba(255,255,255,.18);box-shadow:none}
  .btn.light:hover{background:rgba(255,255,255,.18)}
  .btn.sm{padding:7px 11px;font-size:12.5px;border-radius:8px}
  .btn.danger{background:#fff;color:var(--bad);border-color:#fecaca;box-shadow:none}
  .btn.danger:hover{background:var(--bad-bg)}
  .msg{font-size:13px;margin-top:12px;min-height:18px}
  .msg.ok{color:var(--ok)} .msg.bad{color:var(--bad)}
  .banner{background:var(--info-bg);color:#1e3a8a;border:1px solid #c7d2fe;border-radius:10px;padding:11px 13px;font-size:13.5px;margin-bottom:18px;line-height:1.5}
  .banner.warn{background:var(--warn-bg);color:#92400e;border-color:#fde68a}
  .flash{border:1px solid transparent;border-radius:12px;padding:13px 15px;margin-bottom:18px;font-weight:600;font-size:14px}
  .flash.ok{background:var(--ok-bg);color:var(--ok);border-color:#bbf7d0}
  .flash.bad{background:var(--bad-bg);color:var(--bad);border-color:#fecaca}

  /* ---------- Acceso ---------- */
  .auth{min-height:100vh;display:grid;grid-template-columns:minmax(0,5fr) minmax(0,6fr)}
  .auth-brand{position:relative;overflow:hidden;background:radial-gradient(1000px 500px at 10% 0%,rgba(13,148,136,.32),transparent 60%),linear-gradient(160deg,#0b1220 0%,#0c1b25 55%,#0f3a38 100%);color:#cbd5e1;padding:46px 54px;display:flex;flex-direction:column;justify-content:space-between;gap:36px}
  .auth-brand::after{content:"";position:absolute;width:420px;height:420px;right:-160px;bottom:-200px;border-radius:50%;border:1px solid rgba(45,212,191,.22);box-shadow:0 0 0 70px rgba(45,212,191,.05),0 0 0 140px rgba(45,212,191,.03)}
  .auth-copy{position:relative;z-index:1;max-width:480px}
  .eyebrow{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
  .eyebrow-light{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#5eead4;margin-bottom:18px}
  .auth-copy h1{font-size:clamp(32px,3.4vw,46px);color:#fff;line-height:1.08;margin-bottom:20px}
  .auth-copy > p{font-size:16px;color:#a8b8c4;max-width:34em;margin-bottom:30px}
  .feature-list{list-style:none;padding:0;margin:0;display:grid;gap:15px}
  .feature-list li{display:flex;gap:13px;align-items:flex-start}
  .feature-list .check{width:24px;height:24px;flex:none;border-radius:50%;background:rgba(45,212,191,.14);color:#5eead4;display:grid;place-items:center}
  .feature-list .check svg{width:13px;height:13px}
  .feature-list b{display:block;color:#e2e8f0;font-size:14px;font-weight:600}
  .feature-list small{display:block;color:#8798a8;font-size:12.5px;margin-top:2px}
  .auth-foot{position:relative;z-index:1;display:flex;align-items:center;gap:9px;font-size:12.5px;color:#8798a8}
  .auth-foot .dot{width:7px;height:7px;border-radius:50%;background:#2dd4bf;box-shadow:0 0 0 4px rgba(45,212,191,.12)}
  .auth-main{background:var(--surface);display:grid;place-items:center;padding:40px 22px}
  .auth-card{width:100%;max-width:420px}
  .auth-head{margin-bottom:22px}
  .auth-icon{width:44px;height:44px;border-radius:12px;background:var(--brand-soft);color:var(--brand);display:grid;place-items:center;margin-bottom:16px}
  .auth-icon svg{width:22px;height:22px}
  .auth-head h2{font-size:24px;margin-bottom:5px}
  .seg{display:grid;grid-template-columns:1fr 1fr;background:var(--surface-soft);border:1px solid var(--line);padding:4px;border-radius:11px;margin:0 0 22px}
  .seg button{border:0;background:none;padding:9px;border-radius:8px;font:inherit;font-size:13.5px;font-weight:600;color:var(--muted);cursor:pointer;transition:background .15s,color .15s,box-shadow .15s}
  .seg button.on{background:#fff;color:var(--brand-ink);box-shadow:var(--shadow-sm)}
  .switch{margin-top:17px;font-size:13px;color:var(--muted);line-height:1.7}
  .admin-link{margin-top:32px;padding-top:18px;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted);text-align:center}
  @media(max-width:900px){
    .auth{grid-template-columns:1fr}
    .auth-brand{padding:24px 22px;gap:20px}
    .auth-copy h1{font-size:27px;margin-bottom:10px}
    .auth-copy > p,.feature-list{display:none}
    .eyebrow-light{margin-bottom:10px}
    .auth-brand::after{display:none}
    .auth-foot{display:none}
    .auth-main{padding:30px 20px 46px}
  }

  /* ---------- Estructura del panel ---------- */
  .app-shell{display:flex;min-height:100vh}
  .sidebar{width:264px;flex:none;background:linear-gradient(180deg,var(--sidebar) 0%,var(--sidebar-2) 100%);color:#94a3b8;display:flex;flex-direction:column;padding:22px 16px;position:sticky;top:0;height:100vh;z-index:40}
  .sidebar-brand{padding:2px 6px 22px}
  .side-nav{display:flex;flex-direction:column;gap:3px;overflow-y:auto}
  .nav-label{font-size:10.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#5b6b7f;padding:14px 10px 7px}
  .nav-btn{display:flex;align-items:center;gap:11px;width:100%;padding:10px 12px;border:0;border-radius:9px;background:transparent;color:#94a3b8;font:inherit;font-size:13.5px;font-weight:600;cursor:pointer;text-align:left;transition:background .15s,color .15s}
  .nav-btn:hover{background:rgba(255,255,255,.06);color:#fff}
  .nav-btn.on{background:rgba(13,148,136,.18);color:#5eead4;box-shadow:inset 3px 0 0 #2dd4bf}
  .nav-btn svg{width:18px;height:18px;flex:none;opacity:.9}
  .sidebar-foot{margin-top:auto;padding:16px 6px 0;border-top:1px solid rgba(255,255,255,.08);display:flex;align-items:flex-end;justify-content:space-between;gap:10px}
  .foot-card{display:flex;flex-direction:column;gap:2px}
  .foot-card span{font-size:11.5px;font-weight:600;color:#cbd5e1}
  .foot-card small{font-size:10.5px;color:#5b6b7f}
  .version{font-size:10.5px;color:#5b6b7f;font-family:ui-monospace,Menlo,Consolas,monospace}
  .main{flex:1;min-width:0;display:flex;flex-direction:column}
  .topbar{display:flex;align-items:center;gap:18px;padding:16px 30px;background:rgba(255,255,255,.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:25}
  .page-head{min-width:0;flex:1}
  .page-head h1{font-size:19px;margin-top:2px}
  .page-head .muted{margin-top:2px;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .topbar-right{display:flex;align-items:center;gap:14px;flex:none}
  .date-pill{font-size:12.5px;color:var(--muted);background:var(--surface-soft);border:1px solid var(--line);border-radius:99px;padding:6px 12px;white-space:nowrap}
  .user{display:flex;align-items:center;gap:9px;min-width:0}
  .avatar{width:36px;height:36px;flex:none;border-radius:50%;background:linear-gradient(145deg,var(--brand-2),var(--brand));color:#fff;display:grid;place-items:center;font-size:13px;font-weight:700;letter-spacing:.02em}
  .user-meta{display:flex;flex-direction:column;line-height:1.25;min-width:0}
  .user-meta b{font-size:12.5px;font-weight:600;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px}
  .user-meta small{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
  .icon-btn{display:none;border:1px solid var(--line-strong);background:#fff;color:var(--ink-2);border-radius:9px;width:38px;height:38px;cursor:pointer;place-items:center}
  .icon-btn svg{width:18px;height:18px}
  .sidebar-scrim{display:none}
  .content{width:100%;max-width:1180px;margin:0 auto;padding:28px 30px 60px}
  .content.narrow{max-width:800px}

  /* ---------- Tarjetas y tablas ---------- */
  .card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:22px;margin-bottom:18px;box-shadow:var(--shadow-sm)}
  .card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px;flex-wrap:wrap}
  .card-head h2{margin-bottom:3px}
  .card-head .muted{max-width:70ch}
  .card > h2{margin-bottom:5px}
  .card > h2 + .muted{margin-bottom:16px}
  .card p.muted{margin:0 0 14px}
  .tw{overflow-x:auto;margin:0 -4px;padding:0 4px}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--line);font-size:13.5px;vertical-align:middle}
  th{color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;background:var(--surface-soft)}
  th:first-child{border-top-left-radius:8px;border-bottom-left-radius:8px}
  th:last-child{border-top-right-radius:8px;border-bottom-right-radius:8px}
  tr:last-child td{border-bottom:0}
  tbody tr:hover{background:#fbfcfe}
  td.acc{text-align:right;white-space:nowrap}
  td.acc .btn{margin-left:6px}
  .badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:99px;font-size:11.5px;font-weight:600;line-height:1.4;white-space:nowrap}
  .b-presente,.b-si{background:var(--ok-bg);color:var(--ok)}
  .b-ausente{background:var(--bad-bg);color:var(--bad)}
  .b-tarde{background:var(--warn-bg);color:var(--warn)}
  .b-justificado{background:var(--info-bg);color:var(--info)}
  .b-no{background:var(--surface-soft);color:var(--muted);border:1px solid var(--line)}
  .estado-btns{display:flex;gap:5px;flex-wrap:wrap}
  .estado-btns button{flex:1;min-width:76px;padding:7px 6px;font-size:12px;border-radius:7px;border:1px solid var(--line-strong);background:#fff;color:var(--ink-2);cursor:pointer;font-family:inherit;font-weight:500;text-transform:capitalize;transition:background .12s,border-color .12s,color .12s}
  .estado-btns button:hover{border-color:var(--brand-2);color:var(--brand)}
  .estado-btns button.sel-presente{background:var(--ok-bg);border-color:var(--ok);color:var(--ok);font-weight:700}
  .estado-btns button.sel-ausente{background:var(--bad-bg);border-color:var(--bad);color:var(--bad);font-weight:700}
  .estado-btns button.sel-tarde{background:var(--warn-bg);border-color:var(--warn);color:var(--warn);font-weight:700}
  .estado-btns button.sel-justificado{background:var(--info-bg);border-color:var(--info);color:var(--info);font-weight:700}
  .actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin-bottom:18px}
  .stat{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px;display:flex;align-items:center;gap:14px;box-shadow:var(--shadow-sm)}
  .stat-icon{width:42px;height:42px;flex:none;border-radius:11px;display:grid;place-items:center;background:var(--brand-soft);color:var(--brand)}
  .stat-icon svg{width:20px;height:20px}
  .stat-label{display:block;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
  .stat-value{font-size:25px;font-weight:700;letter-spacing:-.03em;color:var(--ink)}
  .split{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:start}
  .split .card{margin-bottom:0}
  @media(max-width:980px){.split{grid-template-columns:1fr}}
  .qrbox{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap;margin-top:16px;padding:16px;background:var(--surface-soft);border:1px solid var(--line);border-radius:12px}
  .qrbox img{border:1px solid var(--line);border-radius:10px;padding:8px;background:#fff;width:200px;height:200px}
  .qrbox .side{flex:1;min-width:220px}
  .qrbox .side p{margin-bottom:10px}
  .qrbox input{font-size:12px;color:var(--muted);background:#fff}
  .qrbox .qrimg{border:1px solid var(--line);border-radius:10px;padding:8px;background:#fff;line-height:0}
  .qrbox .qrimg svg{width:200px;height:200px;display:block}
  tr.archivado td{opacity:.55}
  .filtro-check{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;color:var(--muted);font-weight:500;cursor:pointer}
  .filtro-check input{width:15px;height:15px;accent-color:var(--brand)}
  dialog.wide{max-width:520px}
  .curso-est{padding:15px 0;border-bottom:1px solid var(--line)}
  .curso-est:last-child{border-bottom:0;padding-bottom:0}
  .curso-est .head{display:flex;justify-content:space-between;gap:10px;margin-bottom:9px;font-weight:600;font-size:14px}
  .bar{height:8px;background:#eef2f7;border-radius:99px;overflow:hidden;margin-bottom:10px}
  .bar i{display:block;height:100%;background:linear-gradient(90deg,var(--brand-2),var(--brand));border-radius:99px}
  .chips{display:flex;gap:6px;flex-wrap:wrap}
  dialog{border:0;border-radius:16px;padding:26px;max-width:390px;width:calc(100% - 32px);box-shadow:var(--shadow)}
  dialog::backdrop{background:rgba(8,17,28,.58);backdrop-filter:blur(2px)}
  .clave{font:700 25px/1 ui-monospace,Menlo,Consolas,monospace;background:var(--surface-soft);border:1px dashed var(--line-strong);padding:15px;border-radius:10px;text-align:center;margin:15px 0;letter-spacing:3px;user-select:all;color:var(--brand-ink)}
  #studentScreen .topbar{justify-content:space-between}
  .student-hero{background:radial-gradient(700px 240px at 90% 0%,rgba(13,148,136,.16),transparent 65%),linear-gradient(140deg,#0b1220,#0e2b2b);border-radius:var(--radius);padding:26px 28px;color:#fff;display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:18px;flex-wrap:wrap;border:1px solid #1e3a3a}
  .student-hero h1{font-size:25px;margin:5px 0 6px;color:#fff}
  .student-hero p{color:#a8b8c4;font-size:13.5px;max-width:46ch}
  .student-hero .eyebrow{color:#5eead4}
  .hero-chip{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);border-radius:999px;padding:9px 14px;font-size:12.5px;color:#dbe7e4;white-space:nowrap}
  .hero-chip svg{width:15px;height:15px;color:#5eead4}
  @media(max-width:1024px){
    .sidebar{position:fixed;left:0;top:0;transform:translateX(-100%);transition:transform .2s ease}
    .sidebar.open{transform:translateX(0)}
    .sidebar-scrim{display:block;position:fixed;inset:0;background:rgba(8,17,28,.5);z-index:35;opacity:0;pointer-events:none;transition:opacity .2s}
    .sidebar-scrim.open{opacity:1;pointer-events:auto}
    .icon-btn{display:grid}
    .topbar{padding:13px 18px}
    .date-pill{display:none}
    .content{padding:20px 18px 50px}
  }
  @media(max-width:640px){
    .user-meta{display:none}
    .btn.hide-sm{display:none}
    .page-head .muted{display:none}
    .card{padding:18px}
    .auth-head h2{font-size:22px}
  }
  @media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>

<!-- ============ ACCESO ============ -->
<div id="authScreen" class="auth hidden">
  <aside class="auth-brand">
    <div class="brand brand-light">
      <span class="brand-mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
      <span class="brand-text"><strong>Asistencia</strong><small>Panel académico</small></span>
    </div>

    <div class="auth-copy">
      <span class="eyebrow-light">Control de asistencia</span>
      <h1>Asistencia clara,<br>en segundos.</h1>
      <p>Un sistema simple para registrar cursos, estudiantes y asistencia con códigos QR. Sin planillas, sin fricción y con el historial siempre a mano.</p>
      <ul class="feature-list">
        <li>
          <span class="check"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
          <div><b>Escaneo con QR</b><small>Los estudiantes marcan su asistencia desde su celular.</small></div>
        </li>
        <li>
          <span class="check"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
          <div><b>Control por curso</b><small>Cursos, inscripciones e historial en un mismo lugar.</small></div>
        </li>
        <li>
          <span class="check"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
          <div><b>Acceso por rol</b><small>Administrador, docentes y estudiantes con permisos claros.</small></div>
        </li>
      </ul>
    </div>

    <div class="auth-foot"><span class="dot"></span> Cloudflare Workers + D1 · Conexión segura</div>
  </aside>

  <main class="auth-main">
    <div class="auth-card">
      <div class="auth-head">
        <div class="auth-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 4v5c0 4.4-3 8.4-7 9-4-.6-7-4.6-7-9V7l7-4z"/><path d="m9 12 2 2 4-4"/></svg></div>
        <h2 id="authTitle">Bienvenido</h2>
        <p class="muted" id="authSub">Ingresa para continuar.</p>
      </div>
      <div id="authBanner" class="banner hidden"></div>

      <div class="seg" id="segWrap">
        <button type="button" id="tabEstudiante" class="on" onclick="setTab('estudiante')">Estudiante</button>
        <button type="button" id="tabDocente" onclick="setTab('docente')">Docente</button>
      </div>

      <!-- ESTUDIANTE -->
      <div id="paneEstudiante">
        <form id="estLogin" onsubmit="loginEstudiante();return false">
          <div class="field"><label for="estLoginDoc">Documento</label><input id="estLoginDoc" autocomplete="username" inputmode="numeric" placeholder="Tu número de documento"></div>
          <div class="field"><label for="estLoginPass">Contraseña</label><input id="estLoginPass" type="password" autocomplete="current-password" placeholder="••••••••"></div>
          <button class="btn block" type="submit">Entrar</button>
          <p class="switch">¿Primera vez? <a href="#" onclick="estForm('registro');return false">Crea tu cuenta</a><br>
          ¿Olvidaste tu contraseña? <a href="#" onclick="olvide();return false">Qué hacer</a></p>
        </form>
        <form id="estRegistro" class="hidden" onsubmit="registrarEstudiante();return false">
          <div class="field"><label for="estRegNombre">Nombre completo</label><input id="estRegNombre" autocomplete="name" placeholder="Nombre y apellidos"></div>
          <div class="field"><label for="estRegDoc">Documento</label><input id="estRegDoc" inputmode="numeric" placeholder="Sin puntos ni espacios"></div>
          <div class="field"><label for="estRegEmail">Email (opcional)</label><input id="estRegEmail" type="email" autocomplete="email" placeholder="tu@correo.com"></div>
          <div class="field"><label for="estRegPass">Contraseña (mínimo 6 caracteres)</label><input id="estRegPass" type="password" autocomplete="new-password"></div>
          <div class="field"><label for="estRegPass2">Repite la contraseña</label><input id="estRegPass2" type="password" autocomplete="new-password"></div>
          <button class="btn block" type="submit">Crear cuenta</button>
          <p class="switch">¿Ya tienes cuenta? <a href="#" onclick="estForm('login');return false">Inicia sesión</a></p>
        </form>
      </div>

      <!-- DOCENTE -->
      <div id="paneDocente" class="hidden">
        <form id="docLogin" onsubmit="loginDocente();return false">
          <div class="field"><label for="docenteEmail">Email</label><input id="docenteEmail" type="email" autocomplete="username" placeholder="tu@correo.com"></div>
          <div class="field"><label for="docentePass">Contraseña</label><input id="docentePass" type="password" autocomplete="current-password" placeholder="••••••••"></div>
          <button class="btn block" type="submit">Entrar</button>
          <p class="switch">¿No tienes cuenta? <a href="#" onclick="docForm('registro');return false">Regístrate</a><br>
          ¿Olvidaste tu contraseña? Pídele al administrador que la restablezca.</p>
        </form>
        <form id="docRegistro" class="hidden" onsubmit="registrarDocente();return false">
          <div class="field"><label for="docRegNombre">Nombre completo</label><input id="docRegNombre" autocomplete="name"></div>
          <div class="field"><label for="docRegEmail">Email</label><input id="docRegEmail" type="email" autocomplete="email" placeholder="tu@correo.com"></div>
          <div class="field"><label for="docRegPass">Contraseña (mínimo 6 caracteres)</label><input id="docRegPass" type="password" autocomplete="new-password"></div>
          <div class="field"><label for="docRegCodigo">Código de invitación (si tu institución lo entregó)</label><input id="docRegCodigo"></div>
          <button class="btn block" type="submit">Crear cuenta</button>
          <p class="switch">¿Ya tienes cuenta? <a href="#" onclick="docForm('login');return false">Inicia sesión</a></p>
        </form>
      </div>

      <!-- ADMIN (separado) -->
      <div id="paneAdmin" class="hidden">
        <form onsubmit="login();return false">
          <div class="field"><label for="apiKeyInput">Clave de administrador</label><input id="apiKeyInput" type="password" autocomplete="current-password" placeholder="Tu clave de acceso"></div>
          <button class="btn block" type="submit">Entrar como administrador</button>
          <p class="switch"><a href="#" onclick="setTab('estudiante');return false">Volver al acceso</a></p>
        </form>
      </div>

      <div id="authMsg" class="msg" role="alert"></div>
      <div class="admin-link" id="adminLinkWrap"><a href="#" onclick="mostrarAdmin();return false">Acceso administrativo</a></div>
    </div>
  </main>
</div>

<!-- ============ ESTUDIANTE ============ -->
<div id="studentScreen" class="hidden">
  <header class="topbar">
    <div class="brand brand-dark">
      <span class="brand-mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
      <span class="brand-text"><strong>Asistencia</strong><small>Portal del estudiante</small></span>
    </div>
    <div class="topbar-right">
      <div class="user">
        <span class="avatar" id="stAvatar">E</span>
        <span class="user-meta"><b id="stNombre"></b><small>Estudiante</small></span>
      </div>
      <button class="btn ghost sm" onclick="cerrarSesion()">Salir</button>
    </div>
  </header>
  <main class="content narrow">
    <div id="stFlash" class="flash hidden" role="status"></div>
    <section class="student-hero">
      <div>
        <span class="eyebrow">Mi panel</span>
        <h1>Hola, <span id="stNombreHero">estudiante</span></h1>
        <p>Consulta tus cursos y tu porcentaje de asistencia. Para marcar tu presencia en clase, escanea el código QR que muestre tu docente.</p>
      </div>
      <div class="hero-chip">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20v.01M20 20v.01"/></svg>
        Escanea el QR de tu docente
      </div>
    </section>
    <section class="card">
      <div class="card-head"><div><h2>Mis cursos</h2><p class="muted">Resumen de asistencia por curso en el que estás inscrito.</p></div></div>
      <div id="stCursos" class="muted">Cargando...</div>
    </section>
    <section class="card">
      <div class="card-head"><div><h2>Cambiar contraseña</h2><p class="muted">Actualiza la clave con la que ingresas a tu cuenta.</p></div></div>
      <form onsubmit="cambiarClave();return false">
        <div class="field"><label for="pwActual">Contraseña actual</label><input id="pwActual" type="password" autocomplete="current-password"></div>
        <div class="row">
          <div class="field"><label for="pwNueva">Nueva contraseña</label><input id="pwNueva" type="password" autocomplete="new-password"></div>
          <div class="field"><label for="pwNueva2">Repite la nueva</label><input id="pwNueva2" type="password" autocomplete="new-password"></div>
        </div>
        <button class="btn" type="submit">Guardar contraseña</button>
        <div id="pwMsg" class="msg"></div>
      </form>
    </section>
  </main>
</div>

<!-- ============ ADMIN / DOCENTE ============ -->
<div id="app" class="hidden">
  <div class="app-shell">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-brand">
        <div class="brand brand-light">
          <span class="brand-mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg></span>
          <span class="brand-text"><strong>Asistencia</strong><small>Panel académico</small></span>
        </div>
      </div>

      <nav class="side-nav" id="tabsNav">
        <span class="nav-label">Gestión</span>
        <button type="button" data-tab="cursos" class="nav-btn on">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
          Cursos
        </button>
        <button type="button" data-tab="estudiantes" class="nav-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13A4 4 0 0 1 16 11"/></svg>
          Estudiantes
        </button>
        <button type="button" data-tab="inscripciones" class="nav-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
          Inscripciones
        </button>
        <button type="button" data-tab="asistencia" class="nav-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="m8 12 3 3 5-6"/></svg>
          Tomar asistencia
        </button>
        <button type="button" data-tab="historial" class="nav-btn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
          Historial
        </button>
        <button type="button" data-tab="docentes" id="tabBtnDocentes" class="nav-btn hidden">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 4v5c0 4.4-3 8.4-7 9-4-.6-7-4.6-7-9V7l7-4z"/><circle cx="12" cy="10" r="2.2"/><path d="M8.8 16a3.4 3.4 0 0 1 6.4 0"/></svg>
          Docentes
        </button>
      </nav>

      <div class="sidebar-foot">
        <div class="foot-card"><span>Plan gratuito</span><small>Cloudflare Workers · D1</small></div>
        <span class="version">v4.0</span>
      </div>
    </aside>
    <div class="sidebar-scrim" id="sidebarScrim" onclick="closeMenu()"></div>

    <main class="main">
      <header class="topbar">
        <button type="button" class="icon-btn" onclick="toggleMenu()" aria-label="Abrir menú">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
        </button>
        <div class="page-head">
          <span class="eyebrow" id="pageEyebrow">Panel</span>
          <h1 id="pageTitle">Cursos</h1>
          <p class="muted" id="pageSub">Gestiona la oferta académica y su información general.</p>
        </div>
        <div class="topbar-right">
          <span class="date-pill" id="todayLabel"></span>
          <div class="user">
            <span class="avatar" id="avatar">A</span>
            <span class="user-meta"><b id="quien">Administrador</b><small id="quienRol">Administrador</small></span>
          </div>
          <button type="button" class="btn ghost sm" onclick="cerrarSesion()">Salir</button>
        </div>
      </header>

      <div class="content">
        <section id="tab-cursos" class="tab-panel">
          <div class="stats">
            <article class="stat">
              <span class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg></span>
              <div><span class="stat-label">Cursos activos</span><strong class="stat-value" id="statCursos">0</strong></div>
            </article>
            <article class="stat">
              <span class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13A4 4 0 0 1 16 11"/></svg></span>
              <div><span class="stat-label">Estudiantes</span><strong class="stat-value" id="statEstudiantes">0</strong></div>
            </article>
            <article class="stat hidden" id="statDocentesCard">
              <span class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 4v5c0 4.4-3 8.4-7 9-4-.6-7-4.6-7-9V7l7-4z"/><circle cx="12" cy="10" r="2.2"/><path d="M8.8 16a3.4 3.4 0 0 1 6.4 0"/></svg></span>
              <div><span class="stat-label">Docentes</span><strong class="stat-value" id="statDocentes">0</strong></div>
            </article>
          </div>

          <section class="card">
            <div class="card-head"><div><h2>Nuevo curso</h2><p class="muted">Crea un curso para empezar a inscribir estudiantes y tomar asistencia.</p></div></div>
            <div class="row">
              <div class="field"><label for="cursoNombre">Nombre</label><input id="cursoNombre" placeholder="Ej. Matemáticas 10A"></div>
              <div class="field"><label for="cursoDesc">Descripción (opcional)</label><input id="cursoDesc" placeholder="Ej. Grupo de la mañana"></div>
            </div>
            <div class="field hidden" id="cursoDocenteWrap"><label for="cursoDocente">Docente responsable (opcional)</label><select id="cursoDocente"></select></div>
            <button type="button" class="btn" onclick="crearCurso()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Agregar curso</button>
          </section>

          <section class="card">
            <div class="card-head"><div><h2>Cursos registrados</h2><p class="muted">Listado de cursos disponibles en el sistema.</p></div>
              <label class="filtro-check"><input type="checkbox" id="verCursosArchivados" onchange="cargarCursos()"> Mostrar archivados</label>
            </div>
            <div class="tw"><table><thead><tr><th>Nombre</th><th>Descripción</th><th>Docente</th><th></th></tr></thead><tbody id="listaCursos"></tbody></table></div>
          </section>
        </section>

        <section id="tab-estudiantes" class="tab-panel hidden">
          <section class="card">
            <div class="card-head"><div><h2>Nuevo estudiante</h2><p class="muted">Registra al estudiante. Luego podrás inscribirlo en uno o varios cursos.</p></div></div>
            <div class="row">
              <div class="field"><label for="estNombre">Nombre completo</label><input id="estNombre" placeholder="Nombre y apellidos"></div>
              <div class="field"><label for="estDoc">Documento</label><input id="estDoc" placeholder="Número de documento"></div>
            </div>
            <div class="row">
              <div class="field"><label for="estEmail">Email (opcional)</label><input id="estEmail" type="email" placeholder="estudiante@correo.com"></div>
              <div class="field"><label for="estTel">Teléfono (opcional)</label><input id="estTel" placeholder="Número de contacto"></div>
            </div>
            <div class="field hidden" id="estDocenteWrap"><label for="estDocente">Docente responsable (opcional)</label><select id="estDocente"></select></div>
            <button type="button" class="btn" onclick="crearEstudiante()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Agregar estudiante</button>
          </section>

          <section class="card">
            <div class="card-head"><div><h2>Estudiantes registrados</h2><p class="muted">Si un estudiante olvidó su contraseña, usa "Restablecer clave": se genera una clave temporal que debes entregarle y luego él la cambia desde su perfil.</p></div>
              <label class="filtro-check"><input type="checkbox" id="verEstudiantesArchivados" onchange="cargarEstudiantes()"> Mostrar archivados</label>
            </div>
            <div class="tw"><table><thead><tr><th>Nombre</th><th>Documento</th><th>Docente</th><th>Cuenta</th><th></th></tr></thead><tbody id="listaEstudiantes"></tbody></table></div>
          </section>
        </section>

        <section id="tab-inscripciones" class="tab-panel hidden">
          <div class="split">
            <section class="card">
              <div class="card-head"><div><h2>Inscribir estudiante</h2><p class="muted">Vincula un estudiante a un curso existente.</p></div></div>
              <div class="field"><label for="inscCurso">Curso</label><select id="inscCurso"></select></div>
              <div class="field"><label for="inscEstudiante">Estudiante</label><select id="inscEstudiante"></select></div>
              <button type="button" class="btn" onclick="inscribir()">Inscribir</button>
              <div id="inscMsg" class="msg"></div>
            </section>

            <section class="card">
              <div class="card-head"><div><h2>QR de registro</h2><p class="muted">El estudiante lo escanea, crea su cuenta y queda inscrito automáticamente en el curso. Válido por 7 días.</p></div></div>
              <div class="field"><label for="verCurso">Curso</label><select id="verCurso" onchange="cargarInscritos()"></select></div>
              <div class="actions" style="margin-top:0">
                <button type="button" class="btn" onclick="generarQRRegistro(true)">QR de registro e inscripción</button>
                <button type="button" class="btn ghost" onclick="generarQRRegistro(false)">QR de registro general</button>
              </div>
              <div id="qrRegistro"></div>
            </section>
          </div>

          <section class="card" style="margin-top:18px">
            <div class="card-head"><div><h2>Estudiantes del curso</h2><p class="muted">Personas inscritas actualmente en el curso seleccionado.</p></div></div>
            <div class="tw"><table><thead><tr><th>Nombre</th><th>Documento</th><th></th></tr></thead><tbody id="listaInscritos"></tbody></table></div>
          </section>
        </section>

        <section id="tab-asistencia" class="tab-panel hidden">
          <section class="card">
            <div class="card-head"><div><h2>Tomar asistencia</h2><p class="muted">Elige el curso y la fecha, marca el estado de cada estudiante y guarda los cambios.</p></div></div>
            <div class="row">
              <div class="field"><label for="asisCurso">Curso</label><select id="asisCurso" onchange="cargarAsistencia()"></select></div>
              <div class="field"><label for="asisFecha">Fecha</label><input type="date" id="asisFecha" onchange="cargarAsistencia()"></div>
            </div>
            <div class="tw"><table><thead><tr><th>Estudiante</th><th style="min-width:320px">Estado</th></tr></thead><tbody id="listaAsistencia"></tbody></table></div>
            <div class="actions">
              <button type="button" class="btn" onclick="guardarAsistencia()">Guardar asistencia</button>
              <button type="button" class="btn ghost" onclick="todosPresentes()">Marcar todos presentes</button>
              <button type="button" class="btn ghost" onclick="cargarAsistencia()">Actualizar lista</button>
            </div>
            <div id="asisMsg" class="msg"></div>
          </section>

          <section class="card">
            <div class="card-head"><div><h2>QR para marcar asistencia</h2><p class="muted">Se genera para el curso y la fecha elegidos arriba y vale 3 horas. Quien tenga cuenta e inscripción queda marcado como presente al escanearlo. Después pulsa "Actualizar lista" para verlo aquí.</p></div></div>
            <button type="button" class="btn" onclick="generarQR()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20v.01M20 20v.01"/></svg>Generar QR de asistencia</button>
            <div id="qrResultado"></div>
          </section>
        </section>

        <section id="tab-historial" class="tab-panel hidden">
          <section class="card">
            <div class="card-head"><div><h2>Historial de asistencia</h2><p class="muted">Consulta los registros guardados por curso, con filtros por fecha y datos de auditoría.</p></div></div>
            <div class="row">
              <div class="field"><label for="histCurso">Curso</label><select id="histCurso" onchange="cargarHistorial()"></select></div>
              <div class="field"><label for="histDesde">Desde (opcional)</label><input type="date" id="histDesde"></div>
              <div class="field"><label for="histHasta">Hasta (opcional)</label><input type="date" id="histHasta"></div>
              <div class="field" style="flex:0 0 auto;align-self:flex-end"><button type="button" class="btn" onclick="cargarHistorial()">Filtrar</button></div>
            </div>
            <div class="tw"><table><thead><tr><th>Estudiante</th><th>Fecha</th><th>Estado</th><th>Origen</th><th>Registrado por</th></tr></thead><tbody id="listaHistorial"></tbody></table></div>
            <div class="actions">
              <button type="button" class="btn ghost" id="btnMasHistorial" onclick="masHistorial()">Cargar más</button>
              <span class="muted" id="histTotal"></span>
            </div>
          </section>
        </section>

        <section id="tab-docentes" class="tab-panel hidden">
          <section class="card">
              <div class="card-head"><div><h2>Registrar docente</h2><p class="muted">Los docentes entran con su email y contraseña, sin la clave maestra.</p></div></div>
              <div class="row">
                <div class="field"><label for="docNombre">Nombre</label><input id="docNombre"></div>
                <div class="field"><label for="docEmail">Email</label><input id="docEmail" type="email"></div>
              </div>
              <div class="field"><label for="docPass">Contraseña (mínimo 6 caracteres)</label><input id="docPass" type="password"></div>
              <button type="button" class="btn" onclick="crearDocente()">Registrar docente</button>
              <div id="docMsg" class="msg"></div>
            </section>
          <section class="card">
            <div class="card-head"><div><h2>Docentes registrados</h2><p class="muted">Cuentas con acceso al panel de gestión.</p></div></div>
            <div class="tw"><table><thead><tr><th>Nombre</th><th>Email</th><th></th></tr></thead><tbody id="listaDocentes"></tbody></table></div>
          </section>
        </section>
      </div>
    </main>
  </div>
</div>

<dialog id="dlg">
  <h2>Clave temporal</h2>
  <div id="dlgTexto" class="muted"></div>
  <div class="clave" id="dlgClave"></div>
  <p class="muted">Entrégasela a la persona. Esta clave no se vuelve a mostrar.</p>
  <button type="button" class="btn block" onclick="document.getElementById('dlg').close()">Entendido</button>
</dialog>

<dialog id="dlgEditar" class="wide">
  <h2 id="editTitulo">Editar</h2>
  <form onsubmit="guardarEdicion();return false">
    <div id="editCampos"></div>
    <div id="editMsg" class="msg"></div>
    <div class="actions">
      <button type="submit" class="btn">Guardar cambios</button>
      <button type="button" class="btn ghost" onclick="document.getElementById('dlgEditar').close()">Cancelar</button>
    </div>
  </form>
</dialog>

<script>
var ROLE = localStorage.getItem('asistencia_role') || '';
var TOKEN = localStorage.getItem('asistencia_token') || '';
var NOMBRE = localStorage.getItem('asistencia_nombre') || '';
var MY_ID = null;
var courses = [], students = [], docentes = [];
var histOffset = 0;
var EDIT = null;
var estados = ['presente','ausente','tarde','justificado'];
var P = new URLSearchParams(location.search);
var CHECKIN = P.get('checkin');
var REGISTRO = P.get('registro');
var TAB_META = {
  cursos: ['Cursos', 'Gestiona la oferta académica y su información general.'],
  estudiantes: ['Estudiantes', 'Registra y administra las cuentas de tus estudiantes.'],
  inscripciones: ['Inscripciones', 'Vincula estudiantes a cursos y comparte códigos QR.'],
  asistencia: ['Tomar asistencia', 'Registra la asistencia por curso y fecha.'],
  historial: ['Historial', 'Consulta los registros de asistencia por curso.'],
  docentes: ['Docentes', 'Administra las cuentas con acceso al panel.']
};

function $(id){ return document.getElementById(id); }
function esc(s){
  return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function inicial(nombre){
  var n = String(nombre || '').trim();
  if (!n) return '?';
  var partes = n.split(/\\s+/);
  return (partes[0].charAt(0) + (partes[1] ? partes[1].charAt(0) : '')).toUpperCase();
}
function hoyLocal(){
  var d = new Date();
  var m = String(d.getMonth() + 1).padStart(2, '0');
  var dia = String(d.getDate()).padStart(2, '0');
  return d.getFullYear() + '-' + m + '-' + dia;
}
function fechaLarga(){
  try {
    var t = new Date().toLocaleDateString('es-ES', { weekday:'long', day:'numeric', month:'long' });
    return t.charAt(0).toUpperCase() + t.slice(1);
  } catch (e) { return ''; }
}
function ver(id){
  ['authScreen','studentScreen','app'].forEach(function(x){ $(x).classList.toggle('hidden', x !== id); });
}
function toggleMenu(){
  $('sidebar').classList.toggle('open');
  $('sidebarScrim').classList.toggle('open');
}
function closeMenu(){
  $('sidebar').classList.remove('open');
  $('sidebarScrim').classList.remove('open');
}
function authHeaders(){
  if (ROLE === 'docente' || ROLE === 'estudiante') return { 'Authorization': 'Bearer ' + TOKEN };
  return {};
}
async function api(path, opts){
  opts = opts || {};
  var headers = Object.assign({ 'Content-Type': 'application/json' }, authHeaders(), opts.headers || {});
  var res = await fetch('/api' + path, Object.assign({}, opts, { headers: headers }));
  if (res.status === 401) {
    limpiarSesion(); mostrarAuth(); msg('Tu sesión venció. Ingresa de nuevo.', 'bad');
    throw new Error('Sesión vencida');
  }
  var data = await res.json().catch(function(){ return {}; });
  if (!res.ok) throw new Error(data.error || 'Ocurrió un error');
  return data;
}
async function post(path, body){
  var res = await fetch('/api' + path, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  return res.json().catch(function(){ return {}; });
}

// ---------- Sesión ----------
function limpiarSesion(){
  ['asistencia_role','asistencia_key','asistencia_token','asistencia_nombre'].forEach(function(k){ localStorage.removeItem(k); });
  ROLE = ''; TOKEN = ''; NOMBRE = ''; MY_ID = null;
}
async function cerrarSesion(){
  try { await fetch('/api/logout', { method:'POST' }); } catch (e) {}
  limpiarSesion(); location.href = location.pathname;
}
function guardarSesion(role, token, nombre){
  ROLE = role; TOKEN = token || ''; NOMBRE = nombre || '';
  localStorage.setItem('asistencia_role', role);
  if (token) localStorage.setItem('asistencia_token', token); else localStorage.removeItem('asistencia_token');
  if (nombre) localStorage.setItem('asistencia_nombre', nombre); else localStorage.removeItem('asistencia_nombre');
  localStorage.removeItem('asistencia_key');
}

// ---------- Pantalla de acceso ----------
function msg(t, tipo){ var m = $('authMsg'); m.textContent = t || ''; m.className = 'msg ' + (tipo || 'bad'); }
function setTab(t){
  $('tabEstudiante').classList.toggle('on', t === 'estudiante');
  $('tabDocente').classList.toggle('on', t === 'docente');
  $('paneEstudiante').classList.toggle('hidden', t !== 'estudiante');
  $('paneDocente').classList.toggle('hidden', t !== 'docente');
  $('paneAdmin').classList.add('hidden');
  $('segWrap').classList.remove('hidden');
  $('adminLinkWrap').classList.remove('hidden');
  $('authTitle').textContent = 'Bienvenido';
  $('authSub').textContent = 'Ingresa para continuar.';
  msg('');
}
function mostrarAdmin(){
  ['paneEstudiante','paneDocente','segWrap','adminLinkWrap'].forEach(function(x){ $(x).classList.add('hidden'); });
  $('paneAdmin').classList.remove('hidden');
  $('authTitle').textContent = 'Acceso administrativo';
  $('authSub').textContent = 'Ingresa con la clave maestra del sistema.';
  msg('');
}
function estForm(c){ $('estLogin').classList.toggle('hidden', c !== 'login'); $('estRegistro').classList.toggle('hidden', c !== 'registro'); msg(''); }
function docForm(c){ $('docLogin').classList.toggle('hidden', c !== 'login'); $('docRegistro').classList.toggle('hidden', c !== 'registro'); msg(''); }
function olvide(){
  msg('Pídele a tu docente que restablezca tu contraseña. Te dará una clave temporal para entrar y cambiarla.', 'ok');
}

async function mostrarAuth(){
  ver('authScreen');
  if (CHECKIN || REGISTRO) setTab('estudiante');
  if (REGISTRO) estForm('registro');
  var tok = CHECKIN || (REGISTRO && REGISTRO !== '1' ? REGISTRO : null);
  var b = $('authBanner');
  if (tok) {
    try {
      var r = await fetch('/api/public/token-info?token=' + encodeURIComponent(tok));
      var d = await r.json();
      if (d.ok) {
        b.textContent = CHECKIN
          ? 'Inicia sesión para marcar tu asistencia en ' + d.curso + '. Si es tu primera vez, crea tu cuenta.'
          : 'Crea tu cuenta para inscribirte en ' + d.curso + '. Si ya tienes cuenta, inicia sesión.';
        b.className = 'banner';
      } else {
        b.textContent = 'Este código venció. Pide uno nuevo a tu docente.';
        b.className = 'banner warn';
      }
    } catch (e) {}
  } else if (REGISTRO === '1') {
    b.textContent = 'Crea tu cuenta de estudiante.';
    b.className = 'banner';
  }
}

async function entrarComo(role, id){
  if (role === 'estudiante') return mostrarEstudiante();
  if (id) MY_ID = id;
  ver('app');
  $('tabBtnDocentes').classList.toggle('hidden', role !== 'admin');
  ['cursoDocenteWrap','estDocenteWrap'].forEach(function(x){ $(x).classList.toggle('hidden', role !== 'admin'); });
  var display = role === 'admin' ? 'Administrador' : (NOMBRE || 'Docente');
  $('quien').textContent = display;
  $('quienRol').textContent = role === 'admin' ? 'Administrador' : 'Docente';
  $('avatar').textContent = role === 'admin' ? 'A' : inicial(display);
  $('todayLabel').textContent = fechaLarga();
  if (role === 'docente' && !MY_ID) {
    try { var s = await api('/session'); MY_ID = s.id; } catch (e) {}
  }
  initApp();
}

async function login(){
  var key = $('apiKeyInput').value;
  var d = await post('/login', { apiKey: key });
  if (d.ok) { guardarSesion('admin', '', 'Administrador'); entrarComo('admin'); }
  else msg(d.error || 'Clave incorrecta', 'bad');
}
async function loginDocente(){
  var d = await post('/login-docente', { email: $('docenteEmail').value, password: $('docentePass').value });
  if (d.ok) { guardarSesion('docente', d.token, d.nombre); entrarComo('docente'); }
  else msg(d.error || 'No se pudo iniciar sesión', 'bad');
}
async function registrarDocente(){
  var d = await post('/register-docente', {
    nombre: $('docRegNombre').value.trim(), email: $('docRegEmail').value.trim(),
    password: $('docRegPass').value, codigo: $('docRegCodigo').value.trim()
  });
  if (d.ok) { guardarSesion('docente', d.token, d.nombre); entrarComo('docente'); }
  else msg(d.error || 'No se pudo registrar', 'bad');
}
async function loginEstudiante(){
  var d = await post('/login-estudiante', { documento: $('estLoginDoc').value.trim(), password: $('estLoginPass').value });
  if (d.ok) { guardarSesion('estudiante', d.token, d.nombre); entrarComo('estudiante'); }
  else msg(d.error || 'No se pudo iniciar sesión', 'bad');
}
async function registrarEstudiante(){
  var p1 = $('estRegPass').value, p2 = $('estRegPass2').value;
  if (p1 !== p2) return msg('Las contraseñas no coinciden', 'bad');
  var d = await post('/register-estudiante', {
    nombre: $('estRegNombre').value.trim(), documento: $('estRegDoc').value.trim(),
    email: $('estRegEmail').value.trim(), password: p1
  });
  if (d.ok) { guardarSesion('estudiante', d.token, d.nombre); entrarComo('estudiante'); }
  else msg(d.error || 'No se pudo registrar', 'bad');
}

// ---------- Vista del estudiante ----------
async function mostrarEstudiante(){
  ver('studentScreen');
  var f = $('stFlash');
  f.className = 'flash hidden';
  function flash(t, tipo){ f.textContent = t; f.className = 'flash ' + tipo; }
  try {
    if (CHECKIN) {
      var d = await api('/attendance/self', { method:'POST', body: JSON.stringify({ token: CHECKIN }) });
      flash(d.ya
        ? 'Tu asistencia ya estaba registrada como ' + d.estado + ' en ' + d.curso + ' el ' + d.fecha + '.'
        : 'Asistencia registrada: quedaste presente en ' + d.curso + ' el ' + d.fecha + '.', 'ok');
    } else if (REGISTRO && REGISTRO !== '1') {
      var e = await api('/enroll/self', { method:'POST', body: JSON.stringify({ token: REGISTRO }) });
      flash(e.ya ? 'Ya estabas inscrito en ' + e.curso + '.' : 'Listo: quedaste inscrito en ' + e.curso + '.', 'ok');
    } else if (REGISTRO === '1') {
      flash('Tu cuenta está creada. Tu docente te inscribirá en tus cursos.', 'ok');
    }
  } catch (err) {
    if (err.message === 'Sesión vencida') return;
    flash(err.message, 'bad');
  }
  if (CHECKIN || REGISTRO) history.replaceState(null, '', location.pathname);
  cargarMisCursos();
}
async function cargarMisCursos(){
  try {
    var d = await api('/me');
    $('stNombre').textContent = d.nombre || '';
    $('stNombreHero').textContent = (d.nombre || 'estudiante').split(/\\s+/)[0];
    $('stAvatar').textContent = inicial(d.nombre || 'Estudiante');
    if (!d.cursos.length) { $('stCursos').textContent = 'Todavía no estás inscrito en ningún curso.'; return; }
    $('stCursos').innerHTML = d.cursos.map(function(c){
      var asistio = (c.presente || 0) + (c.tarde || 0);
      var pct = c.total ? Math.round(asistio / c.total * 100) : 0;
      return '<div class="curso-est"><div class="head"><span>' + esc(c.nombre) + '</span><span>' + (c.total ? pct + '%' : 'Sin registros') + '</span></div>' +
        '<div class="bar"><i style="width:' + pct + '%"></i></div>' +
        '<div class="chips">' +
        '<span class="badge b-presente">Presente ' + (c.presente || 0) + '</span>' +
        '<span class="badge b-tarde">Tarde ' + (c.tarde || 0) + '</span>' +
        '<span class="badge b-justificado">Justificado ' + (c.justificado || 0) + '</span>' +
        '<span class="badge b-ausente">Ausente ' + (c.ausente || 0) + '</span></div></div>';
    }).join('');
  } catch (e) {}
}
async function cambiarClave(){
  var m = $('pwMsg');
  var n1 = $('pwNueva').value, n2 = $('pwNueva2').value;
  if (n1 !== n2) { m.textContent = 'Las contraseñas nuevas no coinciden'; m.className = 'msg bad'; return; }
  try {
    var d = await api('/me/password', { method:'POST', body: JSON.stringify({ actual: $('pwActual').value, nueva: n1 }) });
    if (d.token) guardarSesion('estudiante', d.token, NOMBRE);
    m.textContent = 'Contraseña actualizada'; m.className = 'msg ok';
    ['pwActual','pwNueva','pwNueva2'].forEach(function(id){ $(id).value = ''; });
  } catch (e) { m.textContent = e.message; m.className = 'msg bad'; }
}

// ---------- Navegación admin/docente ----------
document.querySelectorAll('#tabsNav button').forEach(function(btn){
  btn.onclick = function(){
    document.querySelectorAll('#tabsNav button').forEach(function(b){ b.classList.remove('on'); });
    btn.classList.add('on');
    document.querySelectorAll('#app .tab-panel').forEach(function(s){ s.classList.add('hidden'); });
    $('tab-' + btn.dataset.tab).classList.remove('hidden');
    var meta = TAB_META[btn.dataset.tab] || ['Panel', ''];
    $('pageTitle').textContent = meta[0];
    $('pageSub').textContent = meta[1];
    closeMenu();
  };
});
async function initApp(){
  $('asisFecha').value = hoyLocal();
  if (ROLE === 'admin') await cargarDocentes();
  await Promise.all([cargarCursos(), cargarEstudiantes()]);
}
function mostrarClave(texto, clave){
  $('dlgTexto').textContent = texto; $('dlgClave').textContent = clave; $('dlg').showModal();
}

// ---------- QR ----------
async function mostrarQR(id, url, nota){
  var cont = $(id);
  cont.innerHTML = '<div class="qrbox"><div class="qrimg muted">Generando QR…</div>' +
    '<div class="side"><p class="muted">' + esc(nota) + '</p>' +
    '<input readonly value="' + esc(url) + '" onclick="this.select()">' +
    '<div class="actions"><button class="btn ghost sm" data-url="' + esc(url) + '" onclick="copiar(this)">Copiar enlace</button></div></div></div>';
  try {
    var d = await api('/qr', { method:'POST', body: JSON.stringify({ data: url }) });
    var img = cont.querySelector('.qrimg');
    if (img) { img.classList.remove('muted'); img.innerHTML = d.svg; }
  } catch (e) {
    var fallo = cont.querySelector('.qrimg');
    if (fallo) { fallo.classList.remove('muted'); fallo.textContent = e.message; }
  }
}
function copiar(btn){
  if (navigator.clipboard) navigator.clipboard.writeText(btn.dataset.url);
  btn.textContent = 'Copiado';
}
async function generarQR(){
  var course_id = $('asisCurso').value, fecha = $('asisFecha').value;
  if (!course_id || !fecha) { $('qrResultado').innerHTML = '<p class="msg bad">Elige un curso y una fecha primero</p>'; return; }
  try {
    var d = await api('/attendance/session', { method:'POST', body: JSON.stringify({ course_id: course_id, fecha: fecha }) });
    mostrarQR('qrResultado', location.origin + '/?checkin=' + encodeURIComponent(d.token), 'Los estudiantes ya inscritos quedan presentes al escanearlo. Válido por 3 horas.');
  } catch (e) { $('qrResultado').innerHTML = '<p class="msg bad">' + esc(e.message) + '</p>'; }
}
async function generarQRRegistro(conCurso){
  try {
    if (conCurso) {
      var course_id = $('verCurso').value;
      if (!course_id) { $('qrRegistro').innerHTML = '<p class="msg bad">Crea un curso primero</p>'; return; }
      var d = await api('/enroll/session', { method:'POST', body: JSON.stringify({ course_id: course_id }) });
      mostrarQR('qrRegistro', location.origin + '/?registro=' + encodeURIComponent(d.token), 'Registra al estudiante y lo inscribe en el curso. Válido por 7 días.');
    } else {
      mostrarQR('qrRegistro', location.origin + '/?registro=1', 'Abre directamente el formulario de registro. No inscribe en ningún curso.');
    }
  } catch (e) { $('qrRegistro').innerHTML = '<p class="msg bad">' + esc(e.message) + '</p>'; }
}

// ---------- Cursos ----------
function puedeCurso(c){ return ROLE === 'admin' || (c.teacher_id != null && Number(c.teacher_id) === Number(MY_ID)); }
function puedeEstudiante(s){ return ROLE === 'admin' || (s.teacher_id != null && Number(s.teacher_id) === Number(MY_ID)); }
function llenarSelectDocentes(){
  var opts = '<option value="">Institucional (visible para todos)</option>' + docentes.map(function(d){
    return '<option value="' + d.id + '">' + esc(d.nombre) + '</option>';
  }).join('');
  ['cursoDocente','estDocente'].forEach(function(id){ if ($(id)) $(id).innerHTML = opts; });
}
function opcionesDocentes(actual){
  return '<option value="">Institucional (visible para todos)</option>' + docentes.map(function(d){
    return '<option value="' + d.id + '"' + (Number(actual) === Number(d.id) ? ' selected' : '') + '>' + esc(d.nombre) + '</option>';
  }).join('');
}
async function cargarCursos(){
  courses = await api('/courses');
  var verArch = $('verCursosArchivados').checked;
  var visibles = courses.filter(function(c){ return verArch || c.activo; });
  $('statCursos').textContent = courses.filter(function(c){ return c.activo; }).length;
  $('listaCursos').innerHTML = visibles.map(function(c){
    var acciones = '';
    if (puedeCurso(c)) {
      acciones = '<button class="btn ghost sm" onclick="abrirEditarCurso(' + c.id + ')">Editar</button>' +
        (c.activo
          ? '<button class="btn danger sm" onclick="archivarCurso(' + c.id + ')">Archivar</button>'
          : '<button class="btn sm" onclick="restaurarCurso(' + c.id + ')">Restaurar</button>');
    }
    return '<tr class="' + (c.activo ? '' : 'archivado') + '"><td><strong>' + esc(c.nombre) + '</strong>' +
      (c.activo ? '' : ' <span class="badge b-no">Archivado</span>') + '</td>' +
      '<td class="muted">' + esc(c.descripcion || '—') + '</td>' +
      '<td class="muted">' + esc(c.docente || 'Institucional') + '</td>' +
      '<td class="acc">' + acciones + '</td></tr>';
  }).join('') || '<tr><td class="muted" colspan="4">Aún no hay cursos. Crea el primero arriba.</td></tr>';
  var activos = courses.filter(function(c){ return c.activo; });
  var opts = activos.map(function(c){ return '<option value="' + c.id + '">' + esc(c.nombre) + '</option>'; }).join('');
  ['inscCurso','verCurso','asisCurso','histCurso'].forEach(function(id){ $(id).innerHTML = opts; });
  if (activos.length) { cargarInscritos(); cargarAsistencia(); cargarHistorial(); }
  else {
    ['listaInscritos','listaAsistencia','listaHistorial'].forEach(function(id){ if ($(id)) $(id).innerHTML = ''; });
    if ($('histTotal')) $('histTotal').textContent = '';
  }
}
async function crearCurso(){
  var nombre = $('cursoNombre').value.trim();
  if (!nombre) return alert('Escribe un nombre de curso');
  var body = { nombre: nombre, descripcion: $('cursoDesc').value };
  if (ROLE === 'admin' && $('cursoDocente').value) body.teacher_id = $('cursoDocente').value;
  await api('/courses', { method:'POST', body: JSON.stringify(body) });
  $('cursoNombre').value = ''; $('cursoDesc').value = ''; $('cursoDocente').value = '';
  await cargarCursos();
}
async function archivarCurso(id){
  if (!confirm('¿Archivar este curso? Dejará de estar disponible para inscripciones y asistencia, pero su historial se conserva.')) return;
  await api('/courses/' + id, { method:'DELETE' }); await cargarCursos();
}
async function restaurarCurso(id){
  await api('/courses/' + id, { method:'PATCH', body: JSON.stringify({ activo: true }) }); await cargarCursos();
}

// ---------- Estudiantes ----------
async function cargarEstudiantes(){
  students = await api('/students');
  var verArch = $('verEstudiantesArchivados').checked;
  var visibles = students.filter(function(s){ return verArch || s.activo; });
  $('statEstudiantes').textContent = students.filter(function(s){ return s.activo; }).length;
  $('listaEstudiantes').innerHTML = visibles.map(function(s){
    var cuenta = s.tiene_cuenta ? '<span class="badge b-si">Con cuenta</span>' : '<span class="badge b-no">Sin cuenta</span>';
    var acciones = '';
    if (puedeEstudiante(s)) {
      acciones = '<button class="btn ghost sm" data-id="' + s.id + '" data-nombre="' + esc(s.nombre) + '" onclick="resetEst(this)">Restablecer clave</button>' +
        '<button class="btn ghost sm" onclick="abrirEditarEstudiante(' + s.id + ')">Editar</button>' +
        (s.activo
          ? '<button class="btn danger sm" onclick="archivarEstudiante(' + s.id + ')">Archivar</button>'
          : '<button class="btn sm" onclick="restaurarEstudiante(' + s.id + ')">Restaurar</button>');
    }
    return '<tr class="' + (s.activo ? '' : 'archivado') + '"><td><strong>' + esc(s.nombre) + '</strong>' +
      (s.activo ? '' : ' <span class="badge b-no">Archivado</span>') + '</td>' +
      '<td class="muted">' + esc(s.documento || '—') + '</td>' +
      '<td class="muted">' + esc(s.docente || 'Institucional') + '</td><td>' + cuenta + '</td>' +
      '<td class="acc">' + acciones + '</td></tr>';
  }).join('') || '<tr><td class="muted" colspan="5">Aún no hay estudiantes.</td></tr>';
  var activos = students.filter(function(s){ return s.activo; });
  $('inscEstudiante').innerHTML = activos.map(function(s){ return '<option value="' + s.id + '">' + esc(s.nombre) + '</option>'; }).join('');
}
async function crearEstudiante(){
  var nombre = $('estNombre').value.trim();
  if (!nombre) return alert('Escribe el nombre del estudiante');
  var body = { nombre: nombre, documento: $('estDoc').value, email: $('estEmail').value, telefono: $('estTel').value };
  if (ROLE === 'admin' && $('estDocente').value) body.teacher_id = $('estDocente').value;
  try {
    await api('/students', { method:'POST', body: JSON.stringify(body) });
    ['estNombre','estDoc','estEmail','estTel'].forEach(function(id){ $(id).value = ''; });
    $('estDocente').value = '';
    await cargarEstudiantes();
  } catch (e) { alert(e.message); }
}
async function archivarEstudiante(id){
  if (!confirm('¿Archivar este estudiante? No aparecerá en las listas, pero su asistencia se conserva.')) return;
  await api('/students/' + id, { method:'DELETE' }); await cargarEstudiantes();
}
async function restaurarEstudiante(id){
  await api('/students/' + id, { method:'PATCH', body: JSON.stringify({ activo: true }) }); await cargarEstudiantes();
}

// ---------- Edición de cursos y estudiantes ----------
function abrirEditarCurso(id){
  var c = courses.filter(function(x){ return Number(x.id) === Number(id); })[0];
  if (!c) return;
  EDIT = { tipo:'curso', id: c.id };
  $('editTitulo').textContent = 'Editar curso';
  var html = '<div class="field"><label for="editNombre">Nombre</label><input id="editNombre" value="' + esc(c.nombre) + '"></div>' +
    '<div class="field"><label for="editDescripcion">Descripción</label><input id="editDescripcion" value="' + esc(c.descripcion || '') + '"></div>';
  if (ROLE === 'admin') html += '<div class="field"><label for="editDocente">Docente responsable</label><select id="editDocente">' + opcionesDocentes(c.teacher_id) + '</select></div>';
  html += '<label class="filtro-check"><input type="checkbox" id="editActivo"' + (c.activo ? ' checked' : '') + '> Curso activo</label>';
  $('editCampos').innerHTML = html;
  $('editMsg').textContent = '';
  $('dlgEditar').showModal();
}
function abrirEditarEstudiante(id){
  var s = students.filter(function(x){ return Number(x.id) === Number(id); })[0];
  if (!s) return;
  EDIT = { tipo:'estudiante', id: s.id };
  $('editTitulo').textContent = 'Editar estudiante';
  var html = '<div class="field"><label for="editNombre">Nombre completo</label><input id="editNombre" value="' + esc(s.nombre) + '"></div>' +
    '<div class="row"><div class="field"><label for="editDocumento">Documento</label><input id="editDocumento" value="' + esc(s.documento || '') + '"></div>' +
    '<div class="field"><label for="editTelefono">Teléfono</label><input id="editTelefono" value="' + esc(s.telefono || '') + '"></div></div>' +
    '<div class="field"><label for="editEmail">Email</label><input id="editEmail" type="email" value="' + esc(s.email || '') + '"></div>';
  if (ROLE === 'admin') html += '<div class="field"><label for="editDocente">Docente responsable</label><select id="editDocente">' + opcionesDocentes(s.teacher_id) + '</select></div>';
  html += '<label class="filtro-check"><input type="checkbox" id="editActivo"' + (s.activo ? ' checked' : '') + '> Estudiante activo</label>';
  $('editCampos').innerHTML = html;
  $('editMsg').textContent = '';
  $('dlgEditar').showModal();
}
async function guardarEdicion(){
  var m = $('editMsg');
  if (!EDIT) return;
  try {
    if (EDIT.tipo === 'curso') {
      var bodyC = { nombre: $('editNombre').value.trim(), descripcion: $('editDescripcion').value, activo: $('editActivo').checked };
      if (ROLE === 'admin') bodyC.teacher_id = $('editDocente').value || null;
      await api('/courses/' + EDIT.id, { method:'PATCH', body: JSON.stringify(bodyC) });
      $('dlgEditar').close();
      await cargarCursos();
    } else {
      var bodyE = {
        nombre: $('editNombre').value.trim(), documento: $('editDocumento').value,
        email: $('editEmail').value, telefono: $('editTelefono').value, activo: $('editActivo').checked
      };
      if (ROLE === 'admin') bodyE.teacher_id = $('editDocente').value || null;
      await api('/students/' + EDIT.id, { method:'PATCH', body: JSON.stringify(bodyE) });
      $('dlgEditar').close();
      await cargarEstudiantes();
    }
  } catch (e) { m.textContent = e.message; m.className = 'msg bad'; }
}
async function resetEst(btn){
  var nombre = btn.dataset.nombre;
  if (!confirm('¿Restablecer la contraseña de ' + nombre + '? La anterior dejará de funcionar.')) return;
  try {
    var d = await api('/students/' + btn.dataset.id + '/reset-password', { method:'POST' });
    mostrarClave('Clave temporal para ' + nombre + ':', d.password);
    cargarEstudiantes();
  } catch (e) { alert(e.message); }
}

// ---------- Inscripciones ----------
async function inscribir(){
  var course_id = $('inscCurso').value, student_id = $('inscEstudiante').value, m = $('inscMsg');
  if (!course_id || !student_id) { m.textContent = 'Registra al menos un curso y un estudiante primero'; m.className = 'msg bad'; return; }
  try {
    await api('/enrollments', { method:'POST', body: JSON.stringify({ course_id: course_id, student_id: student_id }) });
    m.textContent = 'Estudiante inscrito'; m.className = 'msg ok';
    $('verCurso').value = course_id;
    await cargarInscritos();
  } catch (e) { m.textContent = e.message; m.className = 'msg bad'; }
}
async function cargarInscritos(){
  var courseId = $('verCurso').value;
  if (!courseId) return;
  var list = await api('/courses/' + courseId + '/students');
  $('listaInscritos').innerHTML = list.map(function(s){
    return '<tr><td><strong>' + esc(s.nombre) + '</strong></td><td class="muted">' + esc(s.documento || '—') + '</td>' +
      '<td class="acc"><button class="btn danger sm" onclick="quitarInscripcion(' + s.enrollment_id + ')">Quitar</button></td></tr>';
  }).join('') || '<tr><td class="muted" colspan="3">Nadie inscrito todavía.</td></tr>';
}
async function quitarInscripcion(id){
  await api('/enrollments/' + id, { method:'DELETE' }); await cargarInscritos();
}

// ---------- Asistencia ----------
async function cargarAsistencia(){
  var courseId = $('asisCurso').value, fecha = $('asisFecha').value;
  if (!courseId || !fecha) return;
  var list = await api('/attendance?course_id=' + courseId + '&fecha=' + fecha);
  $('listaAsistencia').innerHTML = list.map(function(r){
    return '<tr data-enrollment="' + r.enrollment_id + '"><td>' + esc(r.nombre) + '</td><td><div class="estado-btns">' +
      estados.map(function(e){
        return '<button type="button" class="' + (r.estado === e ? 'sel-' + e : '') + '" onclick="marcar(this,&quot;' + e + '&quot;)">' + e + '</button>';
      }).join('') + '</div></td></tr>';
  }).join('') || '<tr><td class="muted" colspan="2">Este curso no tiene estudiantes inscritos.</td></tr>';
}
function marcar(btn, estado){
  var row = btn.closest('tr');
  row.querySelectorAll('button').forEach(function(b){ b.className = ''; });
  btn.className = 'sel-' + estado;
  row.dataset.estado = estado;
}
function todosPresentes(){
  document.querySelectorAll('#listaAsistencia tr[data-enrollment]').forEach(function(r){ r.querySelector('button').click(); });
}
async function guardarAsistencia(){
  var fecha = $('asisFecha').value;
  var rows = Array.from(document.querySelectorAll('#listaAsistencia tr[data-enrollment]'));
  var registros = rows.filter(function(r){ return r.dataset.estado; }).map(function(r){ return { enrollment_id: r.dataset.enrollment, estado: r.dataset.estado }; });
  var m = $('asisMsg');
  if (!registros.length) { m.textContent = 'Marca al menos un estado'; m.className = 'msg bad'; return; }
  try {
    await api('/attendance', { method:'POST', body: JSON.stringify({ fecha: fecha, registros: registros }) });
    m.textContent = 'Asistencia guardada'; m.className = 'msg ok';
  } catch (e) { m.textContent = e.message; m.className = 'msg bad'; }
}

// ---------- Historial ----------
var ORIGEN_TEXTO = { qr:'QR', manual:'Manual' };
async function cargarHistorial(reset){
  var courseId = $('histCurso').value;
  if (!courseId) return;
  if (reset !== false) histOffset = 0;
  var q = '/courses/' + courseId + '/history?limit=100&offset=' + histOffset;
  var desde = $('histDesde').value, hasta = $('histHasta').value;
  if (desde) q += '&desde=' + encodeURIComponent(desde);
  if (hasta) q += '&hasta=' + encodeURIComponent(hasta);
  var d;
  try { d = await api(q); }
  catch (e) { $('histTotal').textContent = e.message; $('btnMasHistorial').classList.add('hidden'); return; }
  var filas = d.items.map(function(r){
    return '<tr><td><strong>' + esc(r.nombre) + '</strong></td><td class="muted">' + esc(r.fecha) + '</td>' +
      '<td><span class="badge b-' + esc(r.estado) + '">' + esc(r.estado) + '</span></td>' +
      '<td class="muted">' + esc(ORIGEN_TEXTO[r.origen] || r.origen || '—') + '</td>' +
      '<td class="muted">' + esc(r.marcado_por_nombre || '—') + '</td></tr>';
  }).join('');
  if (histOffset === 0) $('listaHistorial').innerHTML = filas || '<tr><td class="muted" colspan="5">Sin registros para los filtros elegidos.</td></tr>';
  else $('listaHistorial').insertAdjacentHTML('beforeend', filas);
  histOffset += d.items.length;
  $('histTotal').textContent = d.total ? ('Mostrando ' + histOffset + ' de ' + d.total) : 'Sin registros';
  $('btnMasHistorial').classList.toggle('hidden', histOffset >= d.total);
}
function masHistorial(){ cargarHistorial(false); }

// ---------- Docentes (solo administrador) ----------
async function cargarDocentes(){
  if (ROLE !== 'admin') return;
  docentes = await api('/teachers');
  llenarSelectDocentes();
  $('statDocentesCard').classList.remove('hidden');
  $('statDocentes').textContent = docentes.length;
  $('listaDocentes').innerHTML = docentes.map(function(d){
    return '<tr><td><strong>' + esc(d.nombre) + '</strong></td><td class="muted">' + esc(d.email) + '</td>' +
      '<td class="acc"><button class="btn ghost sm" data-id="' + d.id + '" data-nombre="' + esc(d.nombre) + '" onclick="resetDoc(this)">Restablecer clave</button>' +
      '<button class="btn danger sm" onclick="borrarDocente(' + d.id + ')">Eliminar</button></td></tr>';
  }).join('') || '<tr><td class="muted" colspan="3">Aún no hay docentes registrados.</td></tr>';
}
async function crearDocente(){
  var nombre = $('docNombre').value.trim(), email = $('docEmail').value.trim(), password = $('docPass').value, m = $('docMsg');
  if (!nombre || !email || !password) { m.textContent = 'Completa todos los campos'; m.className = 'msg bad'; return; }
  try {
    await api('/teachers', { method:'POST', body: JSON.stringify({ nombre: nombre, email: email, password: password }) });
    m.textContent = 'Docente registrado'; m.className = 'msg ok';
    ['docNombre','docEmail','docPass'].forEach(function(id){ $(id).value = ''; });
    await cargarDocentes();
  } catch (e) { m.textContent = e.message; m.className = 'msg bad'; }
}
async function borrarDocente(id){
  if (!confirm('¿Eliminar este docente? Sus cursos y estudiantes pasarán a ser institucionales.')) return;
  await api('/teachers/' + id, { method:'DELETE' }); await cargarDocentes(); await cargarCursos(); await cargarEstudiantes();
}
async function resetDoc(btn){
  var nombre = btn.dataset.nombre;
  if (!confirm('¿Restablecer la contraseña de ' + nombre + '?')) return;
  try {
    var d = await api('/teachers/' + btn.dataset.id + '/reset-password', { method:'POST' });
    mostrarClave('Clave temporal para ' + nombre + ':', d.password);
  } catch (e) { alert(e.message); }
}

// ---------- Arranque ----------
(async function init(){
  localStorage.removeItem('asistencia_key');
  if (CHECKIN || REGISTRO) return mostrarAuth();
  if (ROLE && (ROLE === 'admin' || TOKEN)) {
    try {
      var r = await fetch('/api/session', { headers: authHeaders() });
      if (r.ok) {
        var d = await r.json();
        if (d.role === ROLE) {
          MY_ID = d.id || null;
          if (d.nombre) { NOMBRE = d.nombre; localStorage.setItem('asistencia_nombre', NOMBRE); }
          if (ROLE === 'estudiante') return mostrarEstudiante();
          return entrarComo(ROLE, MY_ID);
        }
      }
    } catch (e) {}
    limpiarSesion();
  }
  mostrarAuth();
})();
</script>
</body>
</html>`;

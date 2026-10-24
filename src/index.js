// ==========================================================
// Sistema de Asistencia - Cloudflare Worker + D1  (v3)
// ==========================================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
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
// Clave temporal legible (sin letras que se confunden: 0/O, 1/l/I)
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
    keyMaterial, 256
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

// Devuelve { role: 'admin' } o { role: 'docente'|'estudiante', id, nombre, ... } o null
async function getSession(request, env) {
  const apiKey = request.headers.get("X-API-Key");
  if (apiKey && env.API_KEY && apiKey === env.API_KEY) return { role: "admin" };
  const auth = request.headers.get("Authorization");
  if (auth && auth.startsWith("Bearer ") && env.SESSION_SECRET) {
    const payload = await verifyToken(auth.slice(7), env.SESSION_SECRET);
    if (payload && payload.role) return payload;
  }
  return null;
}

const DIA = 24 * 60 * 60 * 1000;

async function handleApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = request.method;

  // ---------- RUTAS PÚBLICAS ----------

  // Login administrador (clave maestra)
  if (path === "/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (body.apiKey && body.apiKey === env.API_KEY) return json({ ok: true, role: "admin" });
    return json({ ok: false, error: "Clave incorrecta" }, 401);
  }

  // Login docente
  if (path === "/login-docente" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const { results } = await env.DB.prepare("SELECT * FROM teachers WHERE email = ?")
      .bind((body.email || "").toLowerCase().trim()).all();
    const t = results[0];
    if (!t) return json({ ok: false, error: "Email o contraseña incorrectos" }, 401);
    const hash = await hashPassword(body.password || "", t.salt);
    if (hash !== t.password_hash) return json({ ok: false, error: "Email o contraseña incorrectos" }, 401);
    const token = await createToken(
      { role: "docente", id: t.id, nombre: t.nombre, email: t.email, exp: Date.now() + 7 * DIA },
      env.SESSION_SECRET
    );
    return json({ ok: true, role: "docente", token, nombre: t.nombre });
  }

  // Registro de docentes. Si configuras el secreto CODIGO_DOCENTE, se exige como código de invitación.
  if (path === "/register-docente" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (env.CODIGO_DOCENTE && b.codigo !== env.CODIGO_DOCENTE) {
      return json({ error: "Código de invitación incorrecto" }, 403);
    }
    if (!b.nombre || !b.email || !b.password) return json({ error: "Faltan datos" }, 400);
    if (b.password.length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    const salt = randomHex();
    const hash = await hashPassword(b.password, salt);
    const email = b.email.toLowerCase().trim();
    try {
      const r = await env.DB.prepare(
        "INSERT INTO teachers (nombre, email, password_hash, salt) VALUES (?, ?, ?, ?)"
      ).bind(b.nombre, email, hash, salt).run();
      const token = await createToken(
        { role: "docente", id: r.meta.last_row_id, nombre: b.nombre, email, exp: Date.now() + 7 * DIA },
        env.SESSION_SECRET
      );
      return json({ ok: true, token, nombre: b.nombre });
    } catch (e) {
      return json({ error: "Ese email ya está registrado. Inicia sesión en vez de registrarte." }, 400);
    }
  }

  // Registro de estudiantes. Si el documento ya existe sin contraseña (lo creó un docente), lo "reclama".
  if (path === "/register-estudiante" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const documento = (b.documento || "").trim();
    if (!b.nombre || !documento || !b.password) return json({ error: "Faltan datos (nombre, documento y contraseña)" }, 400);
    if (b.password.length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    const salt = randomHex();
    const hash = await hashPassword(b.password, salt);
    const { results } = await env.DB.prepare("SELECT * FROM students WHERE documento = ?").bind(documento).all();
    const existente = results[0];
    let studentId;
    if (existente) {
      if (existente.password_hash) {
        return json({ error: "Ya existe una cuenta con ese documento. Inicia sesión; si olvidaste la contraseña, pide a tu docente que la restablezca." }, 400);
      }
      await env.DB.prepare(
        "UPDATE students SET password_hash = ?, salt = ?, nombre = ?, email = COALESCE(?, email) WHERE id = ?"
      ).bind(hash, salt, b.nombre, b.email || null, existente.id).run();
      studentId = existente.id;
    } else {
      const r = await env.DB.prepare(
        "INSERT INTO students (nombre, documento, email, telefono, password_hash, salt) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(b.nombre, documento, b.email || null, b.telefono || null, hash, salt).run();
      studentId = r.meta.last_row_id;
    }
    const token = await createToken(
      { role: "estudiante", id: studentId, nombre: b.nombre, exp: Date.now() + 30 * DIA },
      env.SESSION_SECRET
    );
    return json({ ok: true, token, nombre: b.nombre });
  }

  // Login estudiante (documento + contraseña)
  if (path === "/login-estudiante" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const { results } = await env.DB.prepare("SELECT * FROM students WHERE documento = ?")
      .bind((body.documento || "").trim()).all();
    const s = results[0];
    if (!s || !s.password_hash) return json({ ok: false, error: "Documento o contraseña incorrectos" }, 401);
    const hash = await hashPassword(body.password || "", s.salt);
    if (hash !== s.password_hash) return json({ ok: false, error: "Documento o contraseña incorrectos" }, 401);
    const token = await createToken(
      { role: "estudiante", id: s.id, nombre: s.nombre, exp: Date.now() + 30 * DIA },
      env.SESSION_SECRET
    );
    return json({ ok: true, role: "estudiante", token, nombre: s.nombre });
  }

  // Info pública de un código QR (para mostrar el nombre del curso antes de iniciar sesión)
  if (path === "/public/token-info" && method === "GET") {
    const p = await verifyToken(url.searchParams.get("token") || "", env.SESSION_SECRET);
    if (!p || !p.course_id) return json({ ok: false });
    const c = await env.DB.prepare("SELECT nombre FROM courses WHERE id = ?").bind(p.course_id).first();
    return json({ ok: true, type: p.type, curso: c ? c.nombre : "el curso", fecha: p.fecha || null });
  }

  // ---------- DESDE AQUÍ SE REQUIERE SESIÓN ----------
  const session = await getSession(request, env);
  if (!session) return json({ error: "No autorizado" }, 401);

  // QR de asistencia: lo genera admin/docente para un curso + fecha (válido 3 horas)
  if (path === "/attendance/session" && method === "POST") {
    if (session.role === "estudiante") return json({ error: "No autorizado" }, 403);
    const b = await request.json().catch(() => ({}));
    if (!b.course_id || !b.fecha) return json({ error: "Falta course_id o fecha" }, 400);
    const token = await createToken(
      { type: "checkin", course_id: Number(b.course_id), fecha: b.fecha, exp: Date.now() + 3 * 60 * 60 * 1000 },
      env.SESSION_SECRET
    );
    return json({ token });
  }

  // QR de registro + inscripción a un curso (válido 7 días)
  if (path === "/enroll/session" && method === "POST") {
    if (session.role === "estudiante") return json({ error: "No autorizado" }, 403);
    const b = await request.json().catch(() => ({}));
    if (!b.course_id) return json({ error: "Falta course_id" }, 400);
    const token = await createToken(
      { type: "enroll", course_id: Number(b.course_id), exp: Date.now() + 7 * DIA },
      env.SESSION_SECRET
    );
    return json({ token });
  }

  // ---------- RUTAS DEL ESTUDIANTE ----------
  if (path === "/attendance/self" && method === "POST") {
    if (session.role !== "estudiante") return json({ error: "Solo un estudiante puede marcar su asistencia aquí" }, 403);
    const b = await request.json().catch(() => ({}));
    const payload = await verifyToken(b.token || "", env.SESSION_SECRET);
    if (!payload || payload.type !== "checkin") return json({ error: "El código es inválido o ya venció. Pide uno nuevo a tu docente." }, 400);
    const enr = await env.DB.prepare(
      "SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?"
    ).bind(session.id, payload.course_id).first();
    if (!enr) return json({ error: "No estás inscrito en este curso. Pide a tu docente que te inscriba." }, 403);
    await env.DB.prepare(
      `INSERT INTO attendance (enrollment_id, fecha, estado) VALUES (?, ?, 'presente')
       ON CONFLICT(enrollment_id, fecha) DO UPDATE SET estado = 'presente'`
    ).bind(enr.id, payload.fecha).run();
    const curso = await env.DB.prepare("SELECT nombre FROM courses WHERE id = ?").bind(payload.course_id).first();
    return json({ ok: true, curso: curso ? curso.nombre : "el curso", fecha: payload.fecha });
  }

  if (path === "/enroll/self" && method === "POST") {
    if (session.role !== "estudiante") return json({ error: "Solo un estudiante puede inscribirse aquí" }, 403);
    const b = await request.json().catch(() => ({}));
    const payload = await verifyToken(b.token || "", env.SESSION_SECRET);
    if (!payload || payload.type !== "enroll") return json({ error: "El código es inválido o ya venció. Pide uno nuevo a tu docente." }, 400);
    const curso = await env.DB.prepare("SELECT nombre FROM courses WHERE id = ?").bind(payload.course_id).first();
    if (!curso) return json({ error: "Ese curso ya no existe" }, 404);
    const ya = await env.DB.prepare("SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?")
      .bind(session.id, payload.course_id).first();
    if (!ya) {
      await env.DB.prepare("INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)")
        .bind(session.id, payload.course_id).run();
    }
    return json({ ok: true, curso: curso.nombre, ya: !!ya });
  }

  // Resumen del propio estudiante: sus cursos y su asistencia
  if (path === "/me" && method === "GET") {
    if (session.role !== "estudiante") return json({ error: "No autorizado" }, 403);
    const { results } = await env.DB.prepare(
      `SELECT c.id, c.nombre,
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

  // El estudiante cambia su propia contraseña
  if (path === "/me/password" && method === "POST") {
    if (session.role !== "estudiante") return json({ error: "No autorizado" }, 403);
    const b = await request.json().catch(() => ({}));
    if (!b.nueva || b.nueva.length < 6) return json({ error: "La nueva contraseña debe tener al menos 6 caracteres" }, 400);
    const s = await env.DB.prepare("SELECT * FROM students WHERE id = ?").bind(session.id).first();
    if (!s || !s.password_hash) return json({ error: "Cuenta no encontrada" }, 404);
    const actual = await hashPassword(b.actual || "", s.salt);
    if (actual !== s.password_hash) return json({ error: "La contraseña actual no es correcta" }, 400);
    const salt = randomHex();
    const hash = await hashPassword(b.nueva, salt);
    await env.DB.prepare("UPDATE students SET password_hash = ?, salt = ? WHERE id = ?").bind(hash, salt, s.id).run();
    return json({ ok: true });
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
    await env.DB.prepare("UPDATE teachers SET password_hash = ?, salt = ? WHERE id = ?")
      .bind(hash, salt, teacherResetMatch[1]).run();
    return json({ ok: true, password: pass });
  }
  if (path === "/teachers" && method === "POST") {
    if (session.role !== "admin") return json({ error: "Solo el administrador puede crear docentes así" }, 403);
    const b = await request.json().catch(() => ({}));
    if (!b.nombre || !b.email || !b.password) return json({ error: "Faltan datos" }, 400);
    if (b.password.length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    const salt = randomHex();
    const hash = await hashPassword(b.password, salt);
    try {
      const r = await env.DB.prepare(
        "INSERT INTO teachers (nombre, email, password_hash, salt) VALUES (?, ?, ?, ?)"
      ).bind(b.nombre, b.email.toLowerCase().trim(), hash, salt).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "Ese email ya está registrado" }, 400);
    }
  }

  // ---------- CURSOS ----------
  if (path === "/courses" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM courses ORDER BY nombre").all();
    return json(results);
  }
  if (path === "/courses" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.nombre) return json({ error: "Falta el nombre del curso" }, 400);
    const r = await env.DB.prepare("INSERT INTO courses (nombre, descripcion) VALUES (?, ?)")
      .bind(b.nombre, b.descripcion || null).run();
    return json({ id: r.meta.last_row_id });
  }
  const courseIdMatch = path.match(/^\/courses\/(\d+)$/);
  if (courseIdMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM courses WHERE id = ?").bind(courseIdMatch[1]).run();
    return json({ ok: true });
  }

  // ---------- ESTUDIANTES ----------
  if (path === "/students" && method === "GET") {
    // Ya no se envían password_hash ni salt al navegador
    const { results } = await env.DB.prepare(
      `SELECT id, nombre, documento, email, telefono,
              (password_hash IS NOT NULL) AS tiene_cuenta
       FROM students ORDER BY nombre`
    ).all();
    return json(results);
  }
  if (path === "/students" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.nombre) return json({ error: "Falta el nombre del estudiante" }, 400);
    try {
      const r = await env.DB.prepare(
        "INSERT INTO students (nombre, documento, email, telefono) VALUES (?, ?, ?, ?)"
      ).bind(b.nombre, (b.documento || "").trim() || null, b.email || null, b.telefono || null).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "Ese documento ya está registrado" }, 400);
    }
  }
  const studentIdMatch = path.match(/^\/students\/(\d+)$/);
  if (studentIdMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM students WHERE id = ?").bind(studentIdMatch[1]).run();
    return json({ ok: true });
  }
  // Restablecer contraseña de un estudiante: genera una clave temporal
  const studentResetMatch = path.match(/^\/students\/(\d+)\/reset-password$/);
  if (studentResetMatch && method === "POST") {
    const pass = tempPassword();
    const salt = randomHex();
    const hash = await hashPassword(pass, salt);
    await env.DB.prepare("UPDATE students SET password_hash = ?, salt = ? WHERE id = ?")
      .bind(hash, salt, studentResetMatch[1]).run();
    return json({ ok: true, password: pass });
  }

  // ---------- INSCRIPCIONES ----------
  if (path === "/enrollments" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    try {
      const r = await env.DB.prepare("INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)")
        .bind(b.student_id, b.course_id).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "El estudiante ya está inscrito en ese curso" }, 400);
    }
  }
  const enrollDeleteMatch = path.match(/^\/enrollments\/(\d+)$/);
  if (enrollDeleteMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM enrollments WHERE id = ?").bind(enrollDeleteMatch[1]).run();
    return json({ ok: true });
  }
  const courseStudentsMatch = path.match(/^\/courses\/(\d+)\/students$/);
  if (courseStudentsMatch && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT e.id AS enrollment_id, s.id AS student_id, s.nombre, s.documento
       FROM enrollments e JOIN students s ON s.id = e.student_id
       WHERE e.course_id = ? ORDER BY s.nombre`
    ).bind(courseStudentsMatch[1]).all();
    return json(results);
  }

  // ---------- ASISTENCIA ----------
  if (path === "/attendance" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.fecha || !Array.isArray(b.registros)) return json({ error: "Datos incompletos" }, 400);
    const stmts = b.registros.map((r) =>
      env.DB.prepare(
        `INSERT INTO attendance (enrollment_id, fecha, estado) VALUES (?, ?, ?)
         ON CONFLICT(enrollment_id, fecha) DO UPDATE SET estado = excluded.estado`
      ).bind(r.enrollment_id, b.fecha, r.estado)
    );
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true, guardados: stmts.length });
  }
  if (path === "/attendance" && method === "GET") {
    const courseId = url.searchParams.get("course_id");
    const fecha = url.searchParams.get("fecha");
    if (!courseId || !fecha) return json({ error: "Falta course_id o fecha" }, 400);
    const { results } = await env.DB.prepare(
      `SELECT e.id AS enrollment_id, s.nombre, s.documento, a.estado
       FROM enrollments e
       JOIN students s ON s.id = e.student_id
       LEFT JOIN attendance a ON a.enrollment_id = e.id AND a.fecha = ?
       WHERE e.course_id = ? ORDER BY s.nombre`
    ).bind(fecha, courseId).all();
    return json(results);
  }
  const historyMatch = path.match(/^\/courses\/(\d+)\/history$/);
  if (historyMatch && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT s.nombre, a.fecha, a.estado
       FROM attendance a
       JOIN enrollments e ON e.id = a.enrollment_id
       JOIN students s ON s.id = e.student_id
       WHERE e.course_id = ?
       ORDER BY a.fecha DESC, s.nombre`
    ).bind(historyMatch[1]).all();
    return json(results);
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
        return json({ error: "Error interno", detalle: String(err) }, 500);
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
        <span class="version">v3.0</span>
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
            <button type="button" class="btn" onclick="crearCurso()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Agregar curso</button>
          </section>

          <section class="card">
            <div class="card-head"><div><h2>Cursos registrados</h2><p class="muted">Listado de cursos disponibles en el sistema.</p></div></div>
            <div class="tw"><table><thead><tr><th>Nombre</th><th>Descripción</th><th></th></tr></thead><tbody id="listaCursos"></tbody></table></div>
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
            <button type="button" class="btn" onclick="crearEstudiante()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Agregar estudiante</button>
          </section>

          <section class="card">
            <div class="card-head"><div><h2>Estudiantes registrados</h2><p class="muted">Si un estudiante olvidó su contraseña, usa "Restablecer clave": se genera una clave temporal que debes entregarle y luego él la cambia desde su perfil.</p></div></div>
            <div class="tw"><table><thead><tr><th>Nombre</th><th>Documento</th><th>Cuenta</th><th></th></tr></thead><tbody id="listaEstudiantes"></tbody></table></div>
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
            <div class="card-head"><div><h2>Historial de asistencia</h2><p class="muted">Consulta los registros guardados por curso, ordenados por fecha.</p></div></div>
            <div class="field"><label for="histCurso">Curso</label><select id="histCurso" onchange="cargarHistorial()"></select></div>
            <div class="tw"><table><thead><tr><th>Estudiante</th><th>Fecha</th><th>Estado</th></tr></thead><tbody id="listaHistorial"></tbody></table></div>
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

<script>
var ROLE = localStorage.getItem('asistencia_role') || '';
var API_KEY = localStorage.getItem('asistencia_key') || '';
var TOKEN = localStorage.getItem('asistencia_token') || '';
var NOMBRE = localStorage.getItem('asistencia_nombre') || '';
var courses = [], students = [];
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
  if (ROLE === 'admin') return { 'X-API-Key': API_KEY };
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
  ROLE = ''; API_KEY = ''; TOKEN = ''; NOMBRE = '';
}
function cerrarSesion(){ limpiarSesion(); location.href = location.pathname; }
function guardarSesion(role, token, key, nombre){
  ROLE = role; TOKEN = token || ''; API_KEY = key || ''; NOMBRE = nombre || '';
  localStorage.setItem('asistencia_role', role);
  if (token) localStorage.setItem('asistencia_token', token); else localStorage.removeItem('asistencia_token');
  if (key) localStorage.setItem('asistencia_key', key); else localStorage.removeItem('asistencia_key');
  if (nombre) localStorage.setItem('asistencia_nombre', nombre); else localStorage.removeItem('asistencia_nombre');
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

async function entrarComo(role){
  if (role === 'estudiante') return mostrarEstudiante();
  ver('app');
  $('tabBtnDocentes').classList.toggle('hidden', role !== 'admin');
  var display = role === 'admin' ? 'Administrador' : (NOMBRE || 'Docente');
  $('quien').textContent = display;
  $('quienRol').textContent = role === 'admin' ? 'Administrador' : 'Docente';
  $('avatar').textContent = role === 'admin' ? 'A' : inicial(display);
  $('todayLabel').textContent = fechaLarga();
  initApp();
}

async function login(){
  var key = $('apiKeyInput').value;
  var d = await post('/login', { apiKey: key });
  if (d.ok) { guardarSesion('admin', '', key, 'Administrador'); entrarComo('admin'); }
  else msg('Clave incorrecta', 'bad');
}
async function loginDocente(){
  var d = await post('/login-docente', { email: $('docenteEmail').value, password: $('docentePass').value });
  if (d.ok) { guardarSesion('docente', d.token, '', d.nombre); entrarComo('docente'); }
  else msg(d.error || 'No se pudo iniciar sesión', 'bad');
}
async function registrarDocente(){
  var d = await post('/register-docente', {
    nombre: $('docRegNombre').value.trim(), email: $('docRegEmail').value.trim(),
    password: $('docRegPass').value, codigo: $('docRegCodigo').value.trim()
  });
  if (d.ok) { guardarSesion('docente', d.token, '', d.nombre); entrarComo('docente'); }
  else msg(d.error || 'No se pudo registrar', 'bad');
}
async function loginEstudiante(){
  var d = await post('/login-estudiante', { documento: $('estLoginDoc').value.trim(), password: $('estLoginPass').value });
  if (d.ok) { guardarSesion('estudiante', d.token, '', d.nombre); entrarComo('estudiante'); }
  else msg(d.error || 'No se pudo iniciar sesión', 'bad');
}
async function registrarEstudiante(){
  var p1 = $('estRegPass').value, p2 = $('estRegPass2').value;
  if (p1 !== p2) return msg('Las contraseñas no coinciden', 'bad');
  var d = await post('/register-estudiante', {
    nombre: $('estRegNombre').value.trim(), documento: $('estRegDoc').value.trim(),
    email: $('estRegEmail').value.trim(), password: p1
  });
  if (d.ok) { guardarSesion('estudiante', d.token, '', d.nombre); entrarComo('estudiante'); }
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
      flash('Asistencia registrada: quedaste presente en ' + d.curso + ' el ' + d.fecha + '.', 'ok');
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
    await api('/me/password', { method:'POST', body: JSON.stringify({ actual: $('pwActual').value, nueva: n1 }) });
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
  await Promise.all([cargarCursos(), cargarEstudiantes()]);
  if (ROLE === 'admin') cargarDocentes();
}
function mostrarClave(texto, clave){
  $('dlgTexto').textContent = texto; $('dlgClave').textContent = clave; $('dlg').showModal();
}

// ---------- QR ----------
function mostrarQR(id, url, nota){
  var img = 'https://api.qrserver.com/v1/create-qr-code/?size=240x240&margin=4&data=' + encodeURIComponent(url);
  $(id).innerHTML = '<div class="qrbox"><img src="' + img + '" width="200" height="200" alt="Código QR">' +
    '<div class="side"><p class="muted">' + esc(nota) + '</p>' +
    '<input readonly value="' + esc(url) + '" onclick="this.select()">' +
    '<div class="actions"><button class="btn ghost sm" data-url="' + esc(url) + '" onclick="copiar(this)">Copiar enlace</button></div></div></div>';
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
async function cargarCursos(){
  courses = await api('/courses');
  $('statCursos').textContent = courses.length;
  $('listaCursos').innerHTML = courses.map(function(c){
    return '<tr><td><strong>' + esc(c.nombre) + '</strong></td><td class="muted">' + esc(c.descripcion || '—') + '</td>' +
      '<td class="acc"><button class="btn danger sm" onclick="borrarCurso(' + c.id + ')">Eliminar</button></td></tr>';
  }).join('') || '<tr><td class="muted" colspan="3">Aún no hay cursos. Crea el primero arriba.</td></tr>';
  var opts = courses.map(function(c){ return '<option value="' + c.id + '">' + esc(c.nombre) + '</option>'; }).join('');
  ['inscCurso','verCurso','asisCurso','histCurso'].forEach(function(id){ $(id).innerHTML = opts; });
  if (courses.length) { cargarInscritos(); cargarAsistencia(); cargarHistorial(); }
}
async function crearCurso(){
  var nombre = $('cursoNombre').value.trim();
  if (!nombre) return alert('Escribe un nombre de curso');
  await api('/courses', { method:'POST', body: JSON.stringify({ nombre: nombre, descripcion: $('cursoDesc').value }) });
  $('cursoNombre').value = ''; $('cursoDesc').value = '';
  await cargarCursos();
}
async function borrarCurso(id){
  if (!confirm('¿Eliminar este curso junto con sus inscripciones y asistencia?')) return;
  await api('/courses/' + id, { method:'DELETE' }); await cargarCursos();
}

// ---------- Estudiantes ----------
async function cargarEstudiantes(){
  students = await api('/students');
  $('statEstudiantes').textContent = students.length;
  $('listaEstudiantes').innerHTML = students.map(function(s){
    return '<tr><td><strong>' + esc(s.nombre) + '</strong></td><td class="muted">' + esc(s.documento || '—') + '</td>' +
      '<td>' + (s.tiene_cuenta ? '<span class="badge b-si">Con cuenta</span>' : '<span class="badge b-no">Sin cuenta</span>') + '</td>' +
      '<td class="acc"><button class="btn ghost sm" data-id="' + s.id + '" data-nombre="' + esc(s.nombre) + '" onclick="resetEst(this)">Restablecer clave</button>' +
      '<button class="btn danger sm" onclick="borrarEstudiante(' + s.id + ')">Eliminar</button></td></tr>';
  }).join('') || '<tr><td class="muted" colspan="4">Aún no hay estudiantes.</td></tr>';
  $('inscEstudiante').innerHTML = students.map(function(s){ return '<option value="' + s.id + '">' + esc(s.nombre) + '</option>'; }).join('');
}
async function crearEstudiante(){
  var nombre = $('estNombre').value.trim();
  if (!nombre) return alert('Escribe el nombre del estudiante');
  try {
    await api('/students', { method:'POST', body: JSON.stringify({
      nombre: nombre, documento: $('estDoc').value, email: $('estEmail').value, telefono: $('estTel').value }) });
    ['estNombre','estDoc','estEmail','estTel'].forEach(function(id){ $(id).value = ''; });
    await cargarEstudiantes();
  } catch (e) { alert(e.message); }
}
async function borrarEstudiante(id){
  if (!confirm('¿Eliminar este estudiante? También se borra su asistencia.')) return;
  await api('/students/' + id, { method:'DELETE' }); await cargarEstudiantes();
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
async function cargarHistorial(){
  var courseId = $('histCurso').value;
  if (!courseId) return;
  var list = await api('/courses/' + courseId + '/history');
  $('listaHistorial').innerHTML = list.map(function(r){
    return '<tr><td><strong>' + esc(r.nombre) + '</strong></td><td class="muted">' + esc(r.fecha) + '</td><td><span class="badge b-' + esc(r.estado) + '">' + esc(r.estado) + '</span></td></tr>';
  }).join('') || '<tr><td class="muted" colspan="3">Sin registros todavía.</td></tr>';
}

// ---------- Docentes (solo administrador) ----------
async function cargarDocentes(){
  if (ROLE !== 'admin') return;
  var list = await api('/teachers');
  $('statDocentesCard').classList.remove('hidden');
  $('statDocentes').textContent = list.length;
  $('listaDocentes').innerHTML = list.map(function(d){
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
  if (!confirm('¿Eliminar este docente?')) return;
  await api('/teachers/' + id, { method:'DELETE' }); await cargarDocentes();
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
  if (ROLE === 'estudiante' && TOKEN) return mostrarEstudiante();
  // Si llegan por un QR, siempre mostramos el acceso de estudiante
  if (CHECKIN || REGISTRO) return mostrarAuth();
  if (ROLE === 'admin' && API_KEY) {
    var d = await post('/login', { apiKey: API_KEY });
    if (d.ok) return entrarComo('admin');
  } else if (ROLE === 'docente' && TOKEN) {
    var r = await fetch('/api/courses', { headers: { 'Authorization': 'Bearer ' + TOKEN } });
    if (r.ok) return entrarComo('docente');
  }
  limpiarSesion();
  mostrarAuth();
})();
</script>
</body>
</html>`;

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
<title>Asistencia de cursos</title>
<style>
  :root{
    --pizarra:#14332b; --pizarra2:#1d4a3d; --verde:#1f7a5c; --verde2:#17634a; --tiza:#f2c75c;
    --fondo:#edf1ef; --card:#fff; --texto:#16231f; --muted:#5e6d67; --borde:#d9e1dd;
    --ok:#1b7f4f; --okbg:#dff3e8; --bad:#b42318; --badbg:#fde4e1;
    --warn:#8a5a00; --warnbg:#fff1cc; --info:#2a5db0; --infobg:#e1ebfb;
  }
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:var(--fondo);color:var(--texto)}
  h1,h2,h3{font-family:Georgia,"Iowan Old Style","Times New Roman",serif;font-weight:700;margin:0}
  h2{font-size:19px;margin-bottom:14px}
  a{color:var(--verde2)}
  .hidden{display:none!important}
  .muted{color:var(--muted);font-size:13px}
  :focus-visible{outline:3px solid var(--tiza);outline-offset:2px}

  /* Formularios */
  .field{margin-bottom:14px}
  label{display:block;font-size:13px;font-weight:600;margin-bottom:5px;color:#33423c}
  input,select{width:100%;padding:10px 12px;border:1px solid #c5d0cb;border-radius:8px;font:inherit;background:#fff;color:var(--texto)}
  input:focus,select:focus{outline:none;border-color:var(--verde);box-shadow:0 0 0 3px rgba(31,122,92,.18)}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:600px){.row{grid-template-columns:1fr}}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid transparent;border-radius:8px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer;background:var(--verde);color:#fff}
  .btn:hover{background:var(--verde2)}
  .btn.block{width:100%}
  .btn.ghost{background:#fff;color:var(--pizarra);border-color:#c5d0cb}
  .btn.ghost:hover{background:var(--fondo)}
  .btn.light{background:rgba(255,255,255,.12);color:#fff;padding:7px 14px;font-size:13px}
  .btn.light:hover{background:rgba(255,255,255,.22)}
  .btn.sm{padding:6px 10px;font-size:12.5px}
  .btn.danger{background:#fff;color:var(--bad);border-color:#efb5af}
  .btn.danger:hover{background:var(--badbg)}
  .msg{font-size:13.5px;margin-top:12px;min-height:18px}
  .msg.ok{color:var(--ok)} .msg.bad{color:var(--bad)}
  .banner{background:var(--infobg);color:#1d3f7a;border-radius:8px;padding:10px 12px;font-size:14px;margin:16px 0 0}
  .banner.warn{background:var(--warnbg);color:var(--warn)}
  .flash{border-radius:10px;padding:14px 16px;margin-bottom:18px;font-weight:600}
  .flash.ok{background:var(--okbg);color:var(--ok)}
  .flash.bad{background:var(--badbg);color:var(--bad)}

  /* Pantalla de acceso */
  .auth{min-height:100vh;display:grid;grid-template-columns:minmax(0,5fr) minmax(0,6fr)}
  .auth-brand{background:var(--pizarra);color:#c9d9d2;padding:56px;display:flex;flex-direction:column;justify-content:space-between;gap:40px}
  .wordmark{font-family:Georgia,serif;font-size:22px;color:#fff;font-weight:700}
  .chalk{width:52px;height:4px;background:var(--tiza);border-radius:2px;margin-bottom:22px}
  .auth-brand h1{font-size:44px;line-height:1.1;color:#fff;max-width:11em}
  .auth-brand p{font-size:16px;max-width:30em;margin:18px 0 0}
  .pasos{list-style:none;padding:0;margin:0;display:grid;gap:14px}
  .pasos li{display:flex;gap:14px;align-items:flex-start}
  .pasos b{flex:none;width:28px;height:28px;border-radius:50%;border:1.5px solid var(--tiza);color:var(--tiza);display:grid;place-items:center;font-size:13px}
  .auth-main{background:#fff;display:grid;place-items:center;padding:32px 20px}
  .auth-card{width:100%;max-width:400px}
  .auth-card h2{font-size:26px;margin-bottom:4px}
  .seg{display:grid;grid-template-columns:1fr 1fr;background:var(--fondo);padding:4px;border-radius:10px;margin:22px 0 20px}
  .seg button{border:0;background:none;padding:9px;border-radius:8px;font:inherit;font-weight:600;color:var(--muted);cursor:pointer}
  .seg button.on{background:#fff;color:var(--pizarra);box-shadow:0 1px 3px rgba(0,0,0,.15)}
  .switch{margin-top:16px;font-size:14px;color:var(--muted)}
  .admin-link{margin-top:36px;padding-top:16px;border-top:1px solid var(--borde);font-size:13px;color:var(--muted);text-align:center}
  @media(max-width:860px){
    .auth{grid-template-columns:1fr}
    .auth-brand{padding:24px;gap:16px}
    .auth-brand h1{font-size:28px}
    .auth-brand p,.pasos{display:none}
    .chalk{margin-bottom:12px}
  }

  /* App */
  .top{background:var(--pizarra);color:#fff;display:flex;justify-content:space-between;align-items:center;padding:14px 24px;gap:12px}
  .top .quien{font-size:13px;color:#bcd0c8;margin-right:10px}
  .tabs{background:var(--pizarra2);display:flex;gap:2px;padding:0 20px;overflow-x:auto}
  .tabs button{background:none;border:0;color:#bcd0c8;padding:12px 16px;font:inherit;font-weight:600;cursor:pointer;border-bottom:3px solid transparent;white-space:nowrap}
  .tabs button:hover{color:#fff}
  .tabs button.on{color:#fff;border-bottom-color:var(--tiza)}
  .wrap{max-width:980px;margin:0 auto;padding:24px 20px}
  .wrap.narrow{max-width:640px}
  .card{background:var(--card);border:1px solid var(--borde);border-radius:10px;padding:22px;margin-bottom:18px}
  .card p.muted{margin:0 0 14px}
  .tw{overflow-x:auto}
  table{width:100%;border-collapse:collapse}
  th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--borde);font-size:14px;vertical-align:middle}
  th{color:var(--muted);font-size:13px;font-weight:600}
  tr:last-child td{border-bottom:0}
  td.acc{text-align:right;white-space:nowrap}
  td.acc .btn{margin-left:6px}
  .badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600}
  .b-presente,.b-si{background:var(--okbg);color:var(--ok)}
  .b-ausente{background:var(--badbg);color:var(--bad)}
  .b-tarde{background:var(--warnbg);color:var(--warn)}
  .b-justificado{background:var(--infobg);color:var(--info)}
  .b-no{background:var(--fondo);color:var(--muted)}
  .estado-btns{display:flex;gap:4px}
  .estado-btns button{flex:1;padding:7px 4px;font-size:12.5px;border-radius:6px;border:1px solid #c5d0cb;background:#fff;cursor:pointer;font:inherit;font-size:12.5px}
  .estado-btns button.sel-presente{background:var(--okbg);border-color:var(--ok);color:var(--ok);font-weight:600}
  .estado-btns button.sel-ausente{background:var(--badbg);border-color:var(--bad);color:var(--bad);font-weight:600}
  .estado-btns button.sel-tarde{background:var(--warnbg);border-color:var(--warn);color:var(--warn);font-weight:600}
  .estado-btns button.sel-justificado{background:var(--infobg);border-color:var(--info);color:var(--info);font-weight:600}
  .actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
  .qrbox{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap;margin-top:16px}
  .qrbox img{border:1px solid var(--borde);border-radius:8px;padding:8px;background:#fff}
  .qrbox .side{flex:1;min-width:220px}
  .curso-est{padding:14px 0;border-bottom:1px solid var(--borde)}
  .curso-est:last-child{border-bottom:0}
  .curso-est .head{display:flex;justify-content:space-between;gap:10px;margin-bottom:8px;font-weight:600}
  .bar{height:8px;background:var(--fondo);border-radius:4px;overflow:hidden;margin-bottom:8px}
  .bar i{display:block;height:100%;background:var(--verde)}
  .chips{display:flex;gap:6px;flex-wrap:wrap}
  dialog{border:0;border-radius:12px;padding:26px;max-width:380px;width:calc(100% - 32px)}
  dialog::backdrop{background:rgba(10,25,20,.55)}
  .clave{font:700 26px/1 ui-monospace,Menlo,Consolas,monospace;background:var(--fondo);padding:14px;border-radius:8px;text-align:center;margin:14px 0;letter-spacing:2px;user-select:all}
  @media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>

<!-- ============ ACCESO ============ -->
<div id="authScreen" class="auth hidden">
  <aside class="auth-brand">
    <div class="wordmark">Asistencia</div>
    <div>
      <div class="chalk"></div>
      <h1>Pasar lista toma segundos.</h1>
      <p>Tu docente muestra un código QR en clase. Lo escaneas con tu celular y tu asistencia queda guardada.</p>
    </div>
    <ol class="pasos">
      <li><b>1</b><span>Escanea el QR que muestra tu docente.</span></li>
      <li><b>2</b><span>Crea tu cuenta la primera vez, o inicia sesión.</span></li>
      <li><b>3</b><span>Listo: quedas marcado como presente.</span></li>
    </ol>
  </aside>

  <main class="auth-main">
    <div class="auth-card">
      <h2 id="authTitle">Bienvenido</h2>
      <div class="muted" id="authSub">Ingresa para continuar.</div>
      <div id="authBanner" class="banner hidden"></div>

      <div class="seg" id="segWrap">
        <button type="button" id="tabEstudiante" class="on" onclick="setTab('estudiante')">Estudiante</button>
        <button type="button" id="tabDocente" onclick="setTab('docente')">Docente</button>
      </div>

      <!-- ESTUDIANTE -->
      <div id="paneEstudiante">
        <form id="estLogin" onsubmit="loginEstudiante();return false">
          <div class="field"><label for="estLoginDoc">Documento</label><input id="estLoginDoc" autocomplete="username" inputmode="numeric" placeholder="Tu número de documento"></div>
          <div class="field"><label for="estLoginPass">Contraseña</label><input id="estLoginPass" type="password" autocomplete="current-password"></div>
          <button class="btn block" type="submit">Entrar</button>
          <p class="switch">¿Primera vez? <a href="#" onclick="estForm('registro');return false">Crea tu cuenta</a><br>
          ¿Olvidaste tu contraseña? <a href="#" onclick="olvide();return false">Qué hacer</a></p>
        </form>
        <form id="estRegistro" class="hidden" onsubmit="registrarEstudiante();return false">
          <div class="field"><label for="estRegNombre">Nombre completo</label><input id="estRegNombre" autocomplete="name"></div>
          <div class="field"><label for="estRegDoc">Documento</label><input id="estRegDoc" inputmode="numeric" placeholder="Sin puntos ni espacios"></div>
          <div class="field"><label for="estRegEmail">Email (opcional)</label><input id="estRegEmail" type="email" autocomplete="email"></div>
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
          <div class="field"><label for="docentePass">Contraseña</label><input id="docentePass" type="password" autocomplete="current-password"></div>
          <button class="btn block" type="submit">Entrar</button>
          <p class="switch">¿No tienes cuenta? <a href="#" onclick="docForm('registro');return false">Regístrate</a><br>
          ¿Olvidaste tu contraseña? Pídele al administrador que la restablezca.</p>
        </form>
        <form id="docRegistro" class="hidden" onsubmit="registrarDocente();return false">
          <div class="field"><label for="docRegNombre">Nombre completo</label><input id="docRegNombre" autocomplete="name"></div>
          <div class="field"><label for="docRegEmail">Email</label><input id="docRegEmail" type="email" autocomplete="email"></div>
          <div class="field"><label for="docRegPass">Contraseña (mínimo 6 caracteres)</label><input id="docRegPass" type="password" autocomplete="new-password"></div>
          <div class="field"><label for="docRegCodigo">Código de invitación (si tu institución lo entregó)</label><input id="docRegCodigo"></div>
          <button class="btn block" type="submit">Crear cuenta</button>
          <p class="switch">¿Ya tienes cuenta? <a href="#" onclick="docForm('login');return false">Inicia sesión</a></p>
        </form>
      </div>

      <!-- ADMIN (separado) -->
      <div id="paneAdmin" class="hidden">
        <form onsubmit="login();return false">
          <div class="field"><label for="apiKeyInput">Clave de administrador</label><input id="apiKeyInput" type="password" autocomplete="current-password"></div>
          <button class="btn block" type="submit">Entrar como administrador</button>
          <p class="switch"><a href="#" onclick="setTab('estudiante');return false">Volver</a></p>
        </form>
      </div>

      <div id="authMsg" class="msg" role="alert"></div>
      <div class="admin-link" id="adminLinkWrap"><a href="#" onclick="mostrarAdmin();return false">Acceso administrativo</a></div>
    </div>
  </main>
</div>

<!-- ============ ESTUDIANTE ============ -->
<div id="studentScreen" class="hidden">
  <header class="top">
    <div class="wordmark">Asistencia</div>
    <div><span class="quien" id="stNombre"></span><button class="btn light" onclick="cerrarSesion()">Salir</button></div>
  </header>
  <div class="wrap narrow">
    <div id="stFlash" class="flash hidden" role="status"></div>
    <section class="card">
      <h2>Mis cursos</h2>
      <div id="stCursos" class="muted">Cargando...</div>
      <p class="muted" style="margin:14px 0 0">Para marcar tu asistencia, escanea el QR que muestre tu docente en clase.</p>
    </section>
    <section class="card">
      <h2>Cambiar contraseña</h2>
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
  </div>
</div>

<!-- ============ ADMIN / DOCENTE ============ -->
<div id="app" class="hidden">
  <header class="top">
    <div class="wordmark">Asistencia</div>
    <div><span class="quien" id="quien"></span><button class="btn light" onclick="cerrarSesion()">Cerrar sesión</button></div>
  </header>
  <nav class="tabs" id="tabsNav">
    <button data-tab="cursos" class="on">Cursos</button>
    <button data-tab="estudiantes">Estudiantes</button>
    <button data-tab="inscripciones">Inscripciones</button>
    <button data-tab="asistencia">Tomar asistencia</button>
    <button data-tab="historial">Historial</button>
    <button data-tab="docentes" id="tabBtnDocentes" class="hidden">Docentes</button>
  </nav>
  <div class="wrap">

    <section id="tab-cursos">
      <div class="card">
        <h2>Nuevo curso</h2>
        <div class="row">
          <div class="field"><label for="cursoNombre">Nombre</label><input id="cursoNombre" placeholder="Ej. Matemáticas 10A"></div>
          <div class="field"><label for="cursoDesc">Descripción (opcional)</label><input id="cursoDesc"></div>
        </div>
        <button class="btn" onclick="crearCurso()">Agregar curso</button>
      </div>
      <div class="card">
        <h2>Cursos registrados</h2>
        <div class="tw"><table><thead><tr><th>Nombre</th><th>Descripción</th><th></th></tr></thead><tbody id="listaCursos"></tbody></table></div>
      </div>
    </section>

    <section id="tab-estudiantes" class="hidden">
      <div class="card">
        <h2>Nuevo estudiante</h2>
        <div class="row">
          <div class="field"><label for="estNombre">Nombre completo</label><input id="estNombre"></div>
          <div class="field"><label for="estDoc">Documento</label><input id="estDoc"></div>
        </div>
        <div class="row">
          <div class="field"><label for="estEmail">Email (opcional)</label><input id="estEmail"></div>
          <div class="field"><label for="estTel">Teléfono (opcional)</label><input id="estTel"></div>
        </div>
        <button class="btn" onclick="crearEstudiante()">Agregar estudiante</button>
      </div>
      <div class="card">
        <h2>Estudiantes registrados</h2>
        <p class="muted">Si un estudiante olvidó su contraseña, usa "Restablecer clave": se genera una clave temporal que debes entregarle, y luego él la cambia desde su perfil.</p>
        <div class="tw"><table><thead><tr><th>Nombre</th><th>Documento</th><th>Cuenta</th><th></th></tr></thead><tbody id="listaEstudiantes"></tbody></table></div>
      </div>
    </section>

    <section id="tab-inscripciones" class="hidden">
      <div class="card">
        <h2>Inscribir estudiante a un curso</h2>
        <div class="row">
          <div class="field"><label for="inscCurso">Curso</label><select id="inscCurso"></select></div>
          <div class="field"><label for="inscEstudiante">Estudiante</label><select id="inscEstudiante"></select></div>
        </div>
        <button class="btn" onclick="inscribir()">Inscribir</button>
        <div id="inscMsg" class="msg"></div>
      </div>
      <div class="card">
        <h2>QR de registro para estudiantes</h2>
        <p class="muted">El estudiante lo escanea, crea su cuenta y, si usas el QR del curso, queda inscrito automáticamente. El QR del curso vale 7 días.</p>
        <div class="field"><label for="verCurso">Curso</label><select id="verCurso" onchange="cargarInscritos()"></select></div>
        <div class="actions">
          <button class="btn" onclick="generarQRRegistro(true)">QR de registro e inscripción al curso</button>
          <button class="btn ghost" onclick="generarQRRegistro(false)">QR de registro general</button>
        </div>
        <div id="qrRegistro"></div>
      </div>
      <div class="card">
        <h2>Estudiantes del curso</h2>
        <div class="tw"><table><thead><tr><th>Nombre</th><th>Documento</th><th></th></tr></thead><tbody id="listaInscritos"></tbody></table></div>
      </div>
    </section>

    <section id="tab-asistencia" class="hidden">
      <div class="card">
        <h2>Tomar asistencia</h2>
        <div class="row">
          <div class="field"><label for="asisCurso">Curso</label><select id="asisCurso" onchange="cargarAsistencia()"></select></div>
          <div class="field"><label for="asisFecha">Fecha</label><input type="date" id="asisFecha" onchange="cargarAsistencia()"></div>
        </div>
        <div class="tw"><table><thead><tr><th>Estudiante</th><th style="min-width:300px">Estado</th></tr></thead><tbody id="listaAsistencia"></tbody></table></div>
        <div class="actions">
          <button class="btn" onclick="guardarAsistencia()">Guardar asistencia</button>
          <button class="btn ghost" onclick="todosPresentes()">Marcar todos presentes</button>
          <button class="btn ghost" onclick="cargarAsistencia()">Actualizar lista</button>
        </div>
        <div id="asisMsg" class="msg"></div>
      </div>
      <div class="card">
        <h2>QR para que los estudiantes marquen solos</h2>
        <p class="muted">Se genera para el curso y la fecha elegidos arriba y vale 3 horas. Quien ya tenga cuenta e inscripción queda marcado como presente al escanearlo. Después pulsa "Actualizar lista" para verlo aquí.</p>
        <button class="btn" onclick="generarQR()">Generar QR de asistencia</button>
        <div id="qrResultado"></div>
      </div>
    </section>

    <section id="tab-historial" class="hidden">
      <div class="card">
        <h2>Historial de asistencia</h2>
        <div class="field"><label for="histCurso">Curso</label><select id="histCurso" onchange="cargarHistorial()"></select></div>
        <div class="tw"><table><thead><tr><th>Estudiante</th><th>Fecha</th><th>Estado</th></tr></thead><tbody id="listaHistorial"></tbody></table></div>
      </div>
    </section>

    <section id="tab-docentes" class="hidden">
      <div class="card">
        <h2>Registrar docente</h2>
        <p class="muted">Los docentes entran con su email y contraseña, sin la clave maestra.</p>
        <div class="row">
          <div class="field"><label for="docNombre">Nombre</label><input id="docNombre"></div>
          <div class="field"><label for="docEmail">Email</label><input id="docEmail" type="email"></div>
        </div>
        <div class="field"><label for="docPass">Contraseña (mínimo 6 caracteres)</label><input id="docPass" type="password"></div>
        <button class="btn" onclick="crearDocente()">Registrar docente</button>
        <div id="docMsg" class="msg"></div>
      </div>
      <div class="card">
        <h2>Docentes registrados</h2>
        <div class="tw"><table><thead><tr><th>Nombre</th><th>Email</th><th></th></tr></thead><tbody id="listaDocentes"></tbody></table></div>
      </div>
    </section>
  </div>
</div>

<dialog id="dlg">
  <h2>Clave temporal</h2>
  <div id="dlgTexto" class="muted"></div>
  <div class="clave" id="dlgClave"></div>
  <p class="muted">Entrégasela a la persona. Esta clave no se vuelve a mostrar.</p>
  <button class="btn block" onclick="document.getElementById('dlg').close()">Entendido</button>
</dialog>

<script>
var ROLE = localStorage.getItem('asistencia_role') || '';
var API_KEY = localStorage.getItem('asistencia_key') || '';
var TOKEN = localStorage.getItem('asistencia_token') || '';
var courses = [], students = [];
var estados = ['presente','ausente','tarde','justificado'];
var P = new URLSearchParams(location.search);
var CHECKIN = P.get('checkin');
var REGISTRO = P.get('registro');

function $(id){ return document.getElementById(id); }
function esc(s){
  return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function ver(id){
  ['authScreen','studentScreen','app'].forEach(function(x){ $(x).classList.toggle('hidden', x !== id); });
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
  ['asistencia_role','asistencia_key','asistencia_token'].forEach(function(k){ localStorage.removeItem(k); });
  ROLE = ''; API_KEY = ''; TOKEN = '';
}
function cerrarSesion(){ limpiarSesion(); location.href = location.pathname; }
function guardarSesion(role, token, key){
  ROLE = role; TOKEN = token || ''; API_KEY = key || '';
  localStorage.setItem('asistencia_role', role);
  if (token) localStorage.setItem('asistencia_token', token); else localStorage.removeItem('asistencia_token');
  if (key) localStorage.setItem('asistencia_key', key); else localStorage.removeItem('asistencia_key');
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
  msg('');
}
function mostrarAdmin(){
  ['paneEstudiante','paneDocente','segWrap','adminLinkWrap'].forEach(function(x){ $(x).classList.add('hidden'); });
  $('paneAdmin').classList.remove('hidden');
  $('authTitle').textContent = 'Acceso administrativo';
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
  $('quien').textContent = role === 'admin' ? 'Administrador' : 'Docente';
  initApp();
}

async function login(){
  var key = $('apiKeyInput').value;
  var d = await post('/login', { apiKey: key });
  if (d.ok) { guardarSesion('admin', '', key); entrarComo('admin'); }
  else msg('Clave incorrecta', 'bad');
}
async function loginDocente(){
  var d = await post('/login-docente', { email: $('docenteEmail').value, password: $('docentePass').value });
  if (d.ok) { guardarSesion('docente', d.token); entrarComo('docente'); }
  else msg(d.error || 'No se pudo iniciar sesión', 'bad');
}
async function registrarDocente(){
  var d = await post('/register-docente', {
    nombre: $('docRegNombre').value.trim(), email: $('docRegEmail').value.trim(),
    password: $('docRegPass').value, codigo: $('docRegCodigo').value.trim()
  });
  if (d.ok) { guardarSesion('docente', d.token); entrarComo('docente'); }
  else msg(d.error || 'No se pudo registrar', 'bad');
}
async function loginEstudiante(){
  var d = await post('/login-estudiante', { documento: $('estLoginDoc').value.trim(), password: $('estLoginPass').value });
  if (d.ok) { guardarSesion('estudiante', d.token); entrarComo('estudiante'); }
  else msg(d.error || 'No se pudo iniciar sesión', 'bad');
}
async function registrarEstudiante(){
  var p1 = $('estRegPass').value, p2 = $('estRegPass2').value;
  if (p1 !== p2) return msg('Las contraseñas no coinciden', 'bad');
  var d = await post('/register-estudiante', {
    nombre: $('estRegNombre').value.trim(), documento: $('estRegDoc').value.trim(),
    email: $('estRegEmail').value.trim(), password: p1
  });
  if (d.ok) { guardarSesion('estudiante', d.token); entrarComo('estudiante'); }
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
    document.querySelectorAll('#app section').forEach(function(s){ s.classList.add('hidden'); });
    $('tab-' + btn.dataset.tab).classList.remove('hidden');
  };
});
async function initApp(){
  $('asisFecha').value = new Date().toISOString().slice(0, 10);
  await Promise.all([cargarCursos(), cargarEstudiantes()]);
  if (ROLE === 'admin') cargarDocentes();
}
function mostrarClave(texto, clave){
  $('dlgTexto').textContent = texto; $('dlgClave').textContent = clave; $('dlg').showModal();
}

// ---------- QR ----------
function mostrarQR(id, url, nota){
  var img = 'https://api.qrserver.com/v1/create-qr-code/?size=240x240&margin=4&data=' + encodeURIComponent(url);
  $(id).innerHTML = '<div class="qrbox"><img src="' + img + '" width="240" height="240" alt="Código QR">' +
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
  $('listaCursos').innerHTML = courses.map(function(c){
    return '<tr><td>' + esc(c.nombre) + '</td><td class="muted">' + esc(c.descripcion || '') + '</td>' +
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
  $('listaEstudiantes').innerHTML = students.map(function(s){
    return '<tr><td>' + esc(s.nombre) + '</td><td class="muted">' + esc(s.documento || '') + '</td>' +
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
    return '<tr><td>' + esc(s.nombre) + '</td><td class="muted">' + esc(s.documento || '') + '</td>' +
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
        return '<button class="' + (r.estado === e ? 'sel-' + e : '') + '" onclick="marcar(this,&quot;' + e + '&quot;)">' + e + '</button>';
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
    return '<tr><td>' + esc(r.nombre) + '</td><td>' + esc(r.fecha) + '</td><td><span class="badge b-' + esc(r.estado) + '">' + esc(r.estado) + '</span></td></tr>';
  }).join('') || '<tr><td class="muted" colspan="3">Sin registros todavía.</td></tr>';
}

// ---------- Docentes (solo administrador) ----------
async function cargarDocentes(){
  if (ROLE !== 'admin') return;
  var list = await api('/teachers');
  $('listaDocentes').innerHTML = list.map(function(d){
    return '<tr><td>' + esc(d.nombre) + '</td><td class="muted">' + esc(d.email) + '</td>' +
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
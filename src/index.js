// ==========================================================
// Sistema de Asistencia - Cloudflare Worker + D1
// ==========================================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function isAuthorized(request, env) {
  const key = request.headers.get("X-API-Key");
  return key && env.API_KEY && key === env.API_KEY;
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
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBuf(saltHex), iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return bufToHex(bits);
}

// ---------- Tokens de sesión (firmados con HMAC) ----------
function b64url(str) { return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function unb64url(str) { return atob(str.replace(/-/g, "+").replace(/_/g, "/")); }
async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function createToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return body + "." + b64url(String.fromCharCode(...new Uint8Array(sig)));
}
async function verifyToken(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const key = await hmacKey(secret);
  const sigBytes = Uint8Array.from(unb64url(sig), (c) => c.charCodeAt(0));
  const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(body));
  if (!valid) return null;
  const payload = JSON.parse(unb64url(body));
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
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

async function handleApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = request.method;

  // Login como administrador (con la clave maestra)
  if (path === "/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (body.apiKey === env.API_KEY) return json({ ok: true, role: "admin" });
    return json({ ok: false, error: "Clave incorrecta" }, 401);
  }

  // Login como docente (email + contraseña) -> devuelve un token de sesión
  if (path === "/login-docente" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const { results } = await env.DB.prepare(
      "SELECT * FROM teachers WHERE email = ?"
    ).bind((body.email || "").toLowerCase().trim()).all();
    const t = results[0];
    if (!t) return json({ ok: false, error: "Usuario o contraseña incorrectos" }, 401);
    const hash = await hashPassword(body.password || "", t.salt);
    if (hash !== t.password_hash) return json({ ok: false, error: "Usuario o contraseña incorrectos" }, 401);
    const token = await createToken(
      { role: "docente", id: t.id, nombre: t.nombre, email: t.email, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 },
      env.SESSION_SECRET
    );
    return json({ ok: true, role: "docente", token, nombre: t.nombre });
  }

  // Registro público de docentes (cualquiera puede crear su propia cuenta)
  if (path === "/register-docente" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.nombre || !b.email || !b.password) return json({ error: "Faltan datos" }, 400);
    if (b.password.length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    const salt = randomHex();
    const hash = await hashPassword(b.password, salt);
    try {
      const r = await env.DB.prepare(
        "INSERT INTO teachers (nombre, email, password_hash, salt) VALUES (?, ?, ?, ?)"
      ).bind(b.nombre, b.email.toLowerCase().trim(), hash, salt).run();
      const token = await createToken(
        { role: "docente", id: r.meta.last_row_id, nombre: b.nombre, email: b.email.toLowerCase().trim(), exp: Date.now() + 7 * 24 * 60 * 60 * 1000 },
        env.SESSION_SECRET
      );
      return json({ ok: true, token, nombre: b.nombre });
    } catch (e) {
      return json({ error: "Ese email ya está registrado, inicia sesión en vez de registrarte" }, 400);
    }
  }

  // Registro público de estudiantes. Si ya existe un registro con el mismo
  // documento pero sin contraseña (lo creó un admin/docente), lo "reclama".
  if (path === "/register-estudiante" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.nombre || !b.documento || !b.password) return json({ error: "Faltan datos (nombre, documento y contraseña)" }, 400);
    if (b.password.length < 6) return json({ error: "La contraseña debe tener al menos 6 caracteres" }, 400);
    const salt = randomHex();
    const hash = await hashPassword(b.password, salt);
    const { results } = await env.DB.prepare("SELECT * FROM students WHERE documento = ?").bind(b.documento).all();
    const existente = results[0];
    let studentId;
    if (existente) {
      if (existente.password_hash) {
        return json({ error: "Ya existe una cuenta con ese documento, inicia sesión en vez de registrarte" }, 400);
      }
      await env.DB.prepare(
        "UPDATE students SET password_hash = ?, salt = ?, nombre = ?, email = COALESCE(?, email) WHERE id = ?"
      ).bind(hash, salt, b.nombre, b.email || null, existente.id).run();
      studentId = existente.id;
    } else {
      const r = await env.DB.prepare(
        "INSERT INTO students (nombre, documento, email, telefono, password_hash, salt) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(b.nombre, b.documento, b.email || null, b.telefono || null, hash, salt).run();
      studentId = r.meta.last_row_id;
    }
    const token = await createToken(
      { role: "estudiante", id: studentId, nombre: b.nombre, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 },
      env.SESSION_SECRET
    );
    return json({ ok: true, token, nombre: b.nombre });
  }

  // Login de estudiante (documento + contraseña)
  if (path === "/login-estudiante" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const { results } = await env.DB.prepare(
      "SELECT * FROM students WHERE documento = ?"
    ).bind(body.documento || "").all();
    const s = results[0];
    if (!s || !s.password_hash) return json({ ok: false, error: "Usuario o contraseña incorrectos" }, 401);
    const hash = await hashPassword(body.password || "", s.salt);
    if (hash !== s.password_hash) return json({ ok: false, error: "Usuario o contraseña incorrectos" }, 401);
    const token = await createToken(
      { role: "estudiante", id: s.id, nombre: s.nombre, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 },
      env.SESSION_SECRET
    );
    return json({ ok: true, role: "estudiante", token, nombre: s.nombre });
  }

  // Nombre de un curso, público (para mostrar en la pantalla de check-in antes de iniciar sesión)
  const publicCourseMatch = path.match(/^\/public\/course\/(\d+)$/);
  if (publicCourseMatch && method === "GET") {
    const { results } = await env.DB.prepare("SELECT nombre FROM courses WHERE id = ?").bind(publicCourseMatch[1]).all();
    return json(results[0] || { nombre: "Curso" });
  }

  // A partir de aquí, todo requiere sesión (admin, docente o estudiante)
  const session = await getSession(request, env);
  if (!session) return json({ error: "No autorizado" }, 401);

  // ---------- CHECK-IN POR QR ----------
  // El administrador o docente genera un código de sesión para un curso+fecha
  if (path === "/attendance/session" && method === "POST") {
    if (session.role === "estudiante") return json({ error: "No autorizado" }, 403);
    const b = await request.json().catch(() => ({}));
    if (!b.course_id || !b.fecha) return json({ error: "Falta course_id o fecha" }, 400);
    const token = await createToken(
      { type: "checkin", course_id: b.course_id, fecha: b.fecha, exp: Date.now() + 3 * 60 * 60 * 1000 },
      env.SESSION_SECRET
    );
    return json({ token });
  }
  // El estudiante marca su propia asistencia usando el código de la sesión
  if (path === "/attendance/self" && method === "POST") {
    if (session.role !== "estudiante") return json({ error: "Solo un estudiante puede marcar su asistencia aquí" }, 403);
    const b = await request.json().catch(() => ({}));
    const payload = await verifyToken(b.token || "", env.SESSION_SECRET);
    if (!payload || payload.type !== "checkin") return json({ error: "Código inválido o vencido" }, 400);
    const { results } = await env.DB.prepare(
      "SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?"
    ).bind(session.id, payload.course_id).all();
    if (!results[0]) return json({ error: "No estás inscrito en ese curso" }, 403);
    await env.DB.prepare(
      `INSERT INTO attendance (enrollment_id, fecha, estado) VALUES (?, ?, 'presente')
       ON CONFLICT(enrollment_id, fecha) DO UPDATE SET estado = 'presente'`
    ).bind(results[0].id, payload.fecha).run();
    const curso = await env.DB.prepare("SELECT nombre FROM courses WHERE id = ?").bind(payload.course_id).all();
    return json({ ok: true, curso: curso.results[0]?.nombre || "curso", fecha: payload.fecha });
  }

  // Un estudiante solo puede usar el check-in (arriba). El resto es para admin/docente.
  if (session.role === "estudiante") return json({ error: "No autorizado" }, 403);

  // ---------- DOCENTES (solo el administrador puede listarlos/eliminarlos) ----------
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
  // El administrador también puede seguir creando docentes manualmente
  if (path === "/teachers" && method === "POST") {
    if (session.role !== "admin") return json({ error: "Solo el administrador puede crear docentes así" }, 403);
    const b = await request.json();
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
    const { results } = await env.DB.prepare(
      "SELECT * FROM courses ORDER BY nombre"
    ).all();
    return json(results);
  }
  if (path === "/courses" && method === "POST") {
    const b = await request.json();
    if (!b.nombre) return json({ error: "Falta el nombre del curso" }, 400);
    const r = await env.DB.prepare(
      "INSERT INTO courses (nombre, descripcion) VALUES (?, ?)"
    ).bind(b.nombre, b.descripcion || null).run();
    return json({ id: r.meta.last_row_id });
  }
  const courseIdMatch = path.match(/^\/courses\/(\d+)$/);
  if (courseIdMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM courses WHERE id = ?")
      .bind(courseIdMatch[1]).run();
    return json({ ok: true });
  }

  // ---------- ESTUDIANTES ----------
  if (path === "/students" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT * FROM students ORDER BY nombre"
    ).all();
    return json(results);
  }
  if (path === "/students" && method === "POST") {
    const b = await request.json();
    if (!b.nombre) return json({ error: "Falta el nombre del estudiante" }, 400);
    try {
      const r = await env.DB.prepare(
        "INSERT INTO students (nombre, documento, email, telefono) VALUES (?, ?, ?, ?)"
      ).bind(b.nombre, b.documento || null, b.email || null, b.telefono || null).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "Ese documento ya está registrado" }, 400);
    }
  }
  const studentIdMatch = path.match(/^\/students\/(\d+)$/);
  if (studentIdMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM students WHERE id = ?")
      .bind(studentIdMatch[1]).run();
    return json({ ok: true });
  }

  // ---------- INSCRIPCIONES ----------
  if (path === "/enrollments" && method === "POST") {
    const b = await request.json();
    try {
      const r = await env.DB.prepare(
        "INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)"
      ).bind(b.student_id, b.course_id).run();
      return json({ id: r.meta.last_row_id });
    } catch (e) {
      return json({ error: "El estudiante ya está inscrito en ese curso" }, 400);
    }
  }
  const enrollDeleteMatch = path.match(/^\/enrollments\/(\d+)$/);
  if (enrollDeleteMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM enrollments WHERE id = ?")
      .bind(enrollDeleteMatch[1]).run();
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
  // Guarda o actualiza asistencia en lote para un curso y fecha
  if (path === "/attendance" && method === "POST") {
    const b = await request.json(); // { fecha, registros: [{enrollment_id, estado}] }
    if (!b.fecha || !Array.isArray(b.registros)) {
      return json({ error: "Datos incompletos" }, 400);
    }
    const stmts = b.registros.map((r) =>
      env.DB.prepare(
        `INSERT INTO attendance (enrollment_id, fecha, estado)
         VALUES (?, ?, ?)
         ON CONFLICT(enrollment_id, fecha) DO UPDATE SET estado = excluded.estado`
      ).bind(r.enrollment_id, b.fecha, r.estado)
    );
    if (stmts.length) await env.DB.batch(stmts);
    return json({ ok: true, guardados: stmts.length });
  }

  // Trae asistencia de un curso en una fecha específica
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

  // Historial de asistencia de un curso (todas las fechas)
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
<title>Asistencia de Cursos</title>
<style>
  :root{
    --bg:#f7f7f9; --card:#fff; --text:#1a1a2e; --muted:#6b7280;
    --accent:#4f46e5; --accent-dark:#4338ca; --border:#e5e7eb;
    --ok:#16a34a; --warn:#d97706; --bad:#dc2626;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
  header{background:var(--accent);color:#fff;padding:18px 20px;font-size:20px;font-weight:700}
  .wrap{max-width:960px;margin:0 auto;padding:20px}
  nav{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
  nav button{padding:10px 16px;border:1px solid var(--border);background:var(--card);border-radius:8px;cursor:pointer;font-weight:600;color:var(--muted)}
  nav button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px}
  h2{margin-top:0;font-size:17px}
  input,select{padding:9px 10px;border:1px solid var(--border);border-radius:8px;font-size:14px;width:100%}
  label{font-size:12px;color:var(--muted);display:block;margin-bottom:4px;font-weight:600}
  .field{margin-bottom:12px}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  button.primary{background:var(--accent);color:#fff;border:none;padding:10px 18px;border-radius:8px;font-weight:700;cursor:pointer}
  button.primary:hover{background:var(--accent-dark)}
  button.danger{background:none;border:1px solid var(--bad);color:var(--bad);padding:6px 10px;border-radius:6px;cursor:pointer;font-size:12px}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th,td{text-align:left;padding:8px;border-bottom:1px solid var(--border);font-size:14px}
  th{color:var(--muted);font-size:12px;text-transform:uppercase}
  .estado-btns{display:flex;gap:4px}
  .estado-btns button{flex:1;padding:6px 4px;font-size:12px;border-radius:6px;border:1px solid var(--border);background:#fff;cursor:pointer}
  .estado-btns button.sel-presente{background:#dcfce7;border-color:var(--ok);color:var(--ok)}
  .estado-btns button.sel-ausente{background:#fee2e2;border-color:var(--bad);color:var(--bad)}
  .estado-btns button.sel-tarde{background:#fef3c7;border-color:var(--warn);color:var(--warn)}
  .estado-btns button.sel-justificado{background:#e0e7ff;border-color:var(--accent);color:var(--accent)}
  .muted{color:var(--muted);font-size:13px}
  #loginScreen{max-width:360px;margin:80px auto;text-align:center}
  .hidden{display:none}
  .msg{font-size:13px;margin-top:8px}
  .msg.ok{color:var(--ok)} .msg.bad{color:var(--bad)}
</style>
</head>
<body>

<div id="loginScreen" class="card">
  <h2>🔑 Acceso</h2>
  <nav style="margin-bottom:16px" id="loginRoleTabs">
    <button id="loginTabEstudiante" class="active" onclick="mostrarLogin('estudiante')">Estudiante</button>
    <button id="loginTabDocente" onclick="mostrarLogin('docente')">Docente</button>
    <button id="loginTabAdmin" onclick="mostrarLogin('admin')">Administrador</button>
  </nav>

  <!-- ESTUDIANTE -->
  <div id="loginEstudiante">
    <div id="estIniciar">
      <div class="field"><label>Documento</label><input id="estLoginDoc" placeholder="Tu número de documento"></div>
      <div class="field"><label>Contraseña</label><input id="estLoginPass" type="password"></div>
      <button class="primary" onclick="loginEstudiante()" style="width:100%">Entrar</button>
      <p class="muted" style="margin-top:10px">¿No tienes cuenta? <a href="#" onclick="toggleEstudianteForm('registro');return false">Regístrate aquí</a></p>
    </div>
    <div id="estRegistro" class="hidden">
      <div class="field"><label>Nombre completo</label><input id="estRegNombre"></div>
      <div class="field"><label>Documento</label><input id="estRegDoc" placeholder="El mismo que usó tu profesor al inscribirte"></div>
      <div class="field"><label>Email (opcional)</label><input id="estRegEmail" type="email"></div>
      <div class="field"><label>Contraseña (mínimo 6 caracteres)</label><input id="estRegPass" type="password"></div>
      <button class="primary" onclick="registrarEstudiante()" style="width:100%">Crear cuenta</button>
      <p class="muted" style="margin-top:10px">¿Ya tienes cuenta? <a href="#" onclick="toggleEstudianteForm('login');return false">Inicia sesión</a></p>
    </div>
  </div>

  <!-- DOCENTE -->
  <div id="loginDocente" class="hidden">
    <div id="docIniciar">
      <div class="field"><label>Email</label><input id="docenteEmail" type="email" placeholder="tu@correo.com"></div>
      <div class="field"><label>Contraseña</label><input id="docentePass" type="password"></div>
      <button class="primary" onclick="loginDocente()" style="width:100%">Entrar</button>
      <p class="muted" style="margin-top:10px">¿No tienes cuenta? <a href="#" onclick="toggleDocenteForm('registro');return false">Regístrate aquí</a></p>
    </div>
    <div id="docRegistro" class="hidden">
      <div class="field"><label>Nombre completo</label><input id="docRegNombre"></div>
      <div class="field"><label>Email</label><input id="docRegEmail" type="email"></div>
      <div class="field"><label>Contraseña (mínimo 6 caracteres)</label><input id="docRegPass" type="password"></div>
      <button class="primary" onclick="registrarDocente()" style="width:100%">Crear cuenta</button>
      <p class="muted" style="margin-top:10px">¿Ya tienes cuenta? <a href="#" onclick="toggleDocenteForm('login');return false">Inicia sesión</a></p>
    </div>
  </div>

  <!-- ADMIN -->
  <div id="loginAdmin" class="hidden">
    <p class="muted">Ingresa la clave de acceso maestra configurada en el Worker.</p>
    <div class="field"><input id="apiKeyInput" type="password" placeholder="Clave de acceso"></div>
    <button class="primary" onclick="login()" style="width:100%">Entrar</button>
  </div>

  <div id="loginMsg" class="msg"></div>
</div>

<!-- PANTALLA DE CHECK-IN (para el QR de asistencia) -->
<div id="checkinScreen" class="card hidden" style="max-width:360px;margin:80px auto;text-align:center">
  <h2 id="checkinTitulo">📷 Registrar asistencia</h2>
  <div id="checkinContenido"></div>
</div>

<div id="app" class="hidden">
  <header style="display:flex;justify-content:space-between;align-items:center">
    <span>📋 Sistema de Asistencia</span>
    <button onclick="cerrarSesion()" style="background:rgba(255,255,255,0.15);color:#fff;border:none;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:13px">Cerrar sesión</button>
  </header>
  <div class="wrap">
    <nav>
      <button data-tab="cursos" class="active">Cursos</button>
      <button data-tab="estudiantes">Estudiantes</button>
      <button data-tab="inscripciones">Inscripciones</button>
      <button data-tab="asistencia">Tomar Asistencia</button>
      <button data-tab="historial">Historial</button>
      <button data-tab="docentes" id="tabBtnDocentes" class="hidden">Docentes</button>
    </nav>

    <section id="tab-cursos">
      <div class="card">
        <h2>Nuevo curso</h2>
        <div class="row">
          <div class="field"><label>Nombre</label><input id="cursoNombre" placeholder="Ej. Matemáticas 10A"></div>
          <div class="field"><label>Descripción (opcional)</label><input id="cursoDesc"></div>
        </div>
        <button class="primary" onclick="crearCurso()">Agregar curso</button>
      </div>
      <div class="card">
        <h2>Cursos registrados</h2>
        <table><thead><tr><th>Nombre</th><th>Descripción</th><th></th></tr></thead>
          <tbody id="listaCursos"></tbody></table>
      </div>
    </section>

    <section id="tab-estudiantes" class="hidden">
      <div class="card">
        <h2>Nuevo estudiante</h2>
        <div class="row">
          <div class="field"><label>Nombre completo</label><input id="estNombre"></div>
          <div class="field"><label>Documento</label><input id="estDoc"></div>
        </div>
        <div class="row">
          <div class="field"><label>Email (opcional)</label><input id="estEmail"></div>
          <div class="field"><label>Teléfono (opcional)</label><input id="estTel"></div>
        </div>
        <button class="primary" onclick="crearEstudiante()">Agregar estudiante</button>
      </div>
      <div class="card">
        <h2>Estudiantes registrados</h2>
        <table><thead><tr><th>Nombre</th><th>Documento</th><th>Email</th><th></th></tr></thead>
          <tbody id="listaEstudiantes"></tbody></table>
      </div>
    </section>

    <section id="tab-inscripciones" class="hidden">
      <div class="card">
        <h2>Inscribir estudiante a un curso</h2>
        <div class="row">
          <div class="field"><label>Curso</label><select id="inscCurso"></select></div>
          <div class="field"><label>Estudiante</label><select id="inscEstudiante"></select></div>
        </div>
        <button class="primary" onclick="inscribir()">Inscribir</button>
        <div id="inscMsg" class="msg"></div>
      </div>
      <div class="card">
        <h2>Estudiantes por curso</h2>
        <div class="field"><label>Selecciona un curso</label><select id="verCurso" onchange="cargarInscritos()"></select></div>
        <table><thead><tr><th>Nombre</th><th>Documento</th><th></th></tr></thead>
          <tbody id="listaInscritos"></tbody></table>
      </div>
    </section>

    <section id="tab-asistencia" class="hidden">
      <div class="card">
        <h2>Tomar asistencia</h2>
        <div class="row">
          <div class="field"><label>Curso</label><select id="asisCurso" onchange="cargarAsistencia()"></select></div>
          <div class="field"><label>Fecha</label><input type="date" id="asisFecha" onchange="cargarAsistencia()"></div>
        </div>
        <table><thead><tr><th>Estudiante</th><th style="width:260px">Estado</th></tr></thead>
          <tbody id="listaAsistencia"></tbody></table>
        <button class="primary" onclick="guardarAsistencia()" style="margin-top:12px">Guardar asistencia</button>
        <div id="asisMsg" class="msg"></div>
      </div>
      <div class="card">
        <h2>📷 Código QR para que los estudiantes marquen solos</h2>
        <p class="muted">Genera un código para el curso y la fecha seleccionados arriba. Los estudiantes lo escanean con su celular, inician sesión (o se registran) y su asistencia queda marcada como "presente" automáticamente.</p>
        <button class="primary" onclick="generarQR()">Generar código QR</button>
        <div id="qrResultado" style="margin-top:16px"></div>
      </div>
    </section>

    <section id="tab-historial" class="hidden">
      <div class="card">
        <h2>Historial de asistencia</h2>
        <div class="field"><label>Curso</label><select id="histCurso" onchange="cargarHistorial()"></select></div>
        <table><thead><tr><th>Estudiante</th><th>Fecha</th><th>Estado</th></tr></thead>
          <tbody id="listaHistorial"></tbody></table>
      </div>
    </section>

    <section id="tab-docentes" class="hidden">
      <div class="card">
        <h2>Registrar docente</h2>
        <p class="muted">Los docentes que registres aquí podrán entrar con su propio email y contraseña, sin necesitar la clave maestra.</p>
        <div class="row">
          <div class="field"><label>Nombre</label><input id="docNombre"></div>
          <div class="field"><label>Email</label><input id="docEmail" type="email"></div>
        </div>
        <div class="field"><label>Contraseña (mínimo 6 caracteres)</label><input id="docPass" type="password"></div>
        <button class="primary" onclick="crearDocente()">Registrar docente</button>
        <div id="docMsg" class="msg"></div>
      </div>
      <div class="card">
        <h2>Docentes registrados</h2>
        <table><thead><tr><th>Nombre</th><th>Email</th><th></th></tr></thead>
          <tbody id="listaDocentes"></tbody></table>
      </div>
    </section>
  </div>
</div>

<script>
let ROLE = localStorage.getItem('asistencia_role') || '';       // 'admin', 'docente' o 'estudiante'
let API_KEY = localStorage.getItem('asistencia_key') || '';     // solo si ROLE === 'admin'
let TOKEN = localStorage.getItem('asistencia_token') || '';     // solo si ROLE === 'docente' o 'estudiante'
let courses = [], students = [];
const estados = ['presente','ausente','tarde','justificado'];
const CHECKIN_TOKEN = new URLSearchParams(location.search).get('checkin');

function authHeaders() {
  if (ROLE === 'admin') return { 'X-API-Key': API_KEY };
  if (ROLE === 'docente') return { 'Authorization': 'Bearer ' + TOKEN };
  return {};
}

async function api(path, opts = {}) {
  const res = await fetch('/api' + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...(opts.headers||{}) }
  });
  if (res.status === 401) { showLogin('Sesión inválida, ingresa de nuevo.'); throw new Error('401'); }
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Error');
  return data;
}

function showLogin(msg) {
  document.getElementById('app').classList.add('hidden');
  document.getElementById('checkinScreen').classList.add('hidden');
  document.getElementById('loginScreen').classList.remove('hidden');
  if (msg) { document.getElementById('loginMsg').textContent = msg; document.getElementById('loginMsg').className='msg bad'; }
}

function mostrarLogin(tipo) {
  document.getElementById('loginTabEstudiante').classList.toggle('active', tipo==='estudiante');
  document.getElementById('loginTabDocente').classList.toggle('active', tipo==='docente');
  document.getElementById('loginTabAdmin').classList.toggle('active', tipo==='admin');
  document.getElementById('loginEstudiante').classList.toggle('hidden', tipo!=='estudiante');
  document.getElementById('loginDocente').classList.toggle('hidden', tipo!=='docente');
  document.getElementById('loginAdmin').classList.toggle('hidden', tipo!=='admin');
  document.getElementById('loginMsg').textContent = '';
}
function toggleEstudianteForm(cual) {
  document.getElementById('estIniciar').classList.toggle('hidden', cual!=='login');
  document.getElementById('estRegistro').classList.toggle('hidden', cual!=='registro');
}
function toggleDocenteForm(cual) {
  document.getElementById('docIniciar').classList.toggle('hidden', cual!=='login');
  document.getElementById('docRegistro').classList.toggle('hidden', cual!=='registro');
}

function entrarComo(role) {
  document.getElementById('loginScreen').classList.add('hidden');
  if (role === 'estudiante') {
    procesarPantallaEstudiante();
    return;
  }
  document.getElementById('app').classList.remove('hidden');
  document.getElementById('tabBtnDocentes').classList.toggle('hidden', role !== 'admin');
  initApp();
}

// Lo que ve un estudiante después de iniciar sesión: si viene de un código QR,
// marca su asistencia automáticamente. Si no, le mostramos un mensaje simple.
async function procesarPantallaEstudiante() {
  document.getElementById('checkinScreen').classList.remove('hidden');
  const cont = document.getElementById('checkinContenido');
  if (!CHECKIN_TOKEN) {
    document.getElementById('checkinTitulo').textContent = '👋 ¡Hola!';
    cont.innerHTML = '<p class="muted">Ya iniciaste sesión. Para marcar tu asistencia, escanea el código QR que te muestre tu profesor en clase.</p>' +
      '<button class="primary" onclick="cerrarSesion()" style="margin-top:10px">Cerrar sesión</button>';
    return;
  }
  cont.innerHTML = '<p class="muted">Registrando tu asistencia...</p>';
  try {
    const data = await api('/attendance/self', { method:'POST', body: JSON.stringify({ token: CHECKIN_TOKEN }) });
    document.getElementById('checkinTitulo').textContent = '✅ ¡Asistencia registrada!';
    cont.innerHTML = \`<p>Quedaste marcado como <b>presente</b> en <b>\${data.curso}</b> el \${data.fecha}.</p>
      <button class="primary" onclick="cerrarSesion()" style="margin-top:10px">Listo</button>\`;
  } catch (e) {
    document.getElementById('checkinTitulo').textContent = '⚠️ No se pudo registrar';
    cont.innerHTML = \`<p class="muted">\${e.message}</p><button class="primary" onclick="cerrarSesion()" style="margin-top:10px">Volver</button>\`;
  }
}

async function login() {
  const key = document.getElementById('apiKeyInput').value;
  const res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({apiKey:key}) });
  const data = await res.json();
  if (data.ok) {
    ROLE = 'admin'; API_KEY = key;
    localStorage.setItem('asistencia_role','admin'); localStorage.setItem('asistencia_key', key);
    localStorage.removeItem('asistencia_token');
    entrarComo('admin');
  } else {
    document.getElementById('loginMsg').textContent = 'Clave incorrecta';
    document.getElementById('loginMsg').className = 'msg bad';
  }
}

async function loginDocente() {
  const email = document.getElementById('docenteEmail').value;
  const password = document.getElementById('docentePass').value;
  const res = await fetch('/api/login-docente', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email,password}) });
  const data = await res.json();
  if (data.ok) {
    ROLE = 'docente'; TOKEN = data.token;
    localStorage.setItem('asistencia_role','docente'); localStorage.setItem('asistencia_token', data.token);
    localStorage.removeItem('asistencia_key');
    entrarComo('docente');
  } else {
    document.getElementById('loginMsg').textContent = data.error || 'No se pudo iniciar sesión';
    document.getElementById('loginMsg').className = 'msg bad';
  }
}

function cerrarSesion() {
  localStorage.removeItem('asistencia_role'); localStorage.removeItem('asistencia_key'); localStorage.removeItem('asistencia_token');
  location.reload();
}

async function loginEstudiante() {
  const documento = document.getElementById('estLoginDoc').value.trim();
  const password = document.getElementById('estLoginPass').value;
  const res = await fetch('/api/login-estudiante', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({documento,password}) });
  const data = await res.json();
  if (data.ok) { guardarSesionEstudiante(data.token); entrarComo('estudiante'); }
  else { document.getElementById('loginMsg').textContent = data.error || 'No se pudo iniciar sesión'; document.getElementById('loginMsg').className = 'msg bad'; }
}
async function registrarEstudiante() {
  const nombre = document.getElementById('estRegNombre').value.trim();
  const documento = document.getElementById('estRegDoc').value.trim();
  const email = document.getElementById('estRegEmail').value.trim();
  const password = document.getElementById('estRegPass').value;
  const res = await fetch('/api/register-estudiante', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({nombre,documento,email,password}) });
  const data = await res.json();
  if (data.ok) { guardarSesionEstudiante(data.token); entrarComo('estudiante'); }
  else { document.getElementById('loginMsg').textContent = data.error || 'No se pudo registrar'; document.getElementById('loginMsg').className = 'msg bad'; }
}
function guardarSesionEstudiante(token) {
  ROLE = 'estudiante'; TOKEN = token;
  localStorage.setItem('asistencia_role','estudiante'); localStorage.setItem('asistencia_token', token);
  localStorage.removeItem('asistencia_key');
}

async function registrarDocente() {
  const nombre = document.getElementById('docRegNombre').value.trim();
  const email = document.getElementById('docRegEmail').value.trim();
  const password = document.getElementById('docRegPass').value;
  const res = await fetch('/api/register-docente', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({nombre,email,password}) });
  const data = await res.json();
  if (data.ok) {
    ROLE = 'docente'; TOKEN = data.token;
    localStorage.setItem('asistencia_role','docente'); localStorage.setItem('asistencia_token', data.token);
    localStorage.removeItem('asistencia_key');
    entrarComo('docente');
  } else { document.getElementById('loginMsg').textContent = data.error || 'No se pudo registrar'; document.getElementById('loginMsg').className = 'msg bad'; }
}

// ---- Código QR de check-in ----
async function generarQR() {
  const course_id = document.getElementById('asisCurso').value;
  const fecha = document.getElementById('asisFecha').value;
  const cont = document.getElementById('qrResultado');
  if (!course_id || !fecha) { cont.innerHTML = '<p class="msg bad">Selecciona un curso y una fecha primero</p>'; return; }
  try {
    const data = await api('/attendance/session', { method:'POST', body: JSON.stringify({ course_id, fecha }) });
    const url = location.origin + '/?checkin=' + encodeURIComponent(data.token);
    const qrImg = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' + encodeURIComponent(url);
    cont.innerHTML = \`
      <img src="\${qrImg}" alt="Código QR" style="border:1px solid var(--border);border-radius:8px">
      <p class="muted" style="margin-top:10px">O comparte este enlace directamente (válido por 3 horas):</p>
      <input readonly value="\${url}" onclick="this.select()" style="margin-top:4px">
    \`;
  } catch (e) { cont.innerHTML = '<p class="msg bad">'+e.message+'</p>'; }
}

document.querySelectorAll('#app nav button').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('#app nav button').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('#app section').forEach(s=>s.classList.add('hidden'));
    document.getElementById('tab-'+btn.dataset.tab).classList.remove('hidden');
  };
});

async function initApp() {
  document.getElementById('asisFecha').value = new Date().toISOString().slice(0,10);
  await Promise.all([cargarCursos(), cargarEstudiantes()]);
}

// ---- Cursos ----
async function cargarCursos() {
  courses = await api('/courses');
  document.getElementById('listaCursos').innerHTML = courses.map(c =>
    \`<tr><td>\${c.nombre}</td><td class="muted">\${c.descripcion||''}</td>
     <td><button class="danger" onclick="borrarCurso(\${c.id})">Eliminar</button></td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="3">Sin cursos aún</td></tr>';
  const opts = courses.map(c => \`<option value="\${c.id}">\${c.nombre}</option>\`).join('');
  ['inscCurso','verCurso','asisCurso','histCurso'].forEach(id => document.getElementById(id).innerHTML = opts);
  if (courses.length) { cargarInscritos(); cargarAsistencia(); cargarHistorial(); }
}
async function crearCurso() {
  const nombre = document.getElementById('cursoNombre').value.trim();
  if (!nombre) return alert('Escribe un nombre de curso');
  await api('/courses', { method:'POST', body: JSON.stringify({ nombre, descripcion: document.getElementById('cursoDesc').value }) });
  document.getElementById('cursoNombre').value=''; document.getElementById('cursoDesc').value='';
  await cargarCursos();
}
async function borrarCurso(id) {
  if (!confirm('¿Eliminar este curso y sus inscripciones/asistencia?')) return;
  await api('/courses/'+id, { method:'DELETE' }); await cargarCursos();
}

// ---- Estudiantes ----
async function cargarEstudiantes() {
  students = await api('/students');
  document.getElementById('listaEstudiantes').innerHTML = students.map(s =>
    \`<tr><td>\${s.nombre}</td><td class="muted">\${s.documento||''}</td><td class="muted">\${s.email||''}</td>
     <td><button class="danger" onclick="borrarEstudiante(\${s.id})">Eliminar</button></td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="4">Sin estudiantes aún</td></tr>';
  document.getElementById('inscEstudiante').innerHTML = students.map(s => \`<option value="\${s.id}">\${s.nombre}</option>\`).join('');
}
async function crearEstudiante() {
  const nombre = document.getElementById('estNombre').value.trim();
  if (!nombre) return alert('Escribe el nombre del estudiante');
  try {
    await api('/students', { method:'POST', body: JSON.stringify({
      nombre, documento: document.getElementById('estDoc').value,
      email: document.getElementById('estEmail').value, telefono: document.getElementById('estTel').value
    })});
    ['estNombre','estDoc','estEmail','estTel'].forEach(id=>document.getElementById(id).value='');
    await cargarEstudiantes();
  } catch(e) { alert(e.message); }
}
async function borrarEstudiante(id) {
  if (!confirm('¿Eliminar este estudiante?')) return;
  await api('/students/'+id, { method:'DELETE' }); await cargarEstudiantes();
}

// ---- Inscripciones ----
async function inscribir() {
  const course_id = document.getElementById('inscCurso').value;
  const student_id = document.getElementById('inscEstudiante').value;
  const msgEl = document.getElementById('inscMsg');
  if (!course_id || !student_id) {
    msgEl.textContent = 'Registra al menos un curso y un estudiante primero'; msgEl.className='msg bad'; return;
  }
  try {
    await api('/enrollments', { method:'POST', body: JSON.stringify({ course_id, student_id }) });
    msgEl.textContent = 'Inscrito correctamente ✓'; msgEl.className='msg ok';
    document.getElementById('verCurso').value = course_id;
    await cargarInscritos();
  } catch(e) { msgEl.textContent = e.message; msgEl.className='msg bad'; }
}
async function cargarInscritos() {
  const courseId = document.getElementById('verCurso').value;
  if (!courseId) return;
  const list = await api('/courses/'+courseId+'/students');
  document.getElementById('listaInscritos').innerHTML = list.map(s =>
    \`<tr><td>\${s.nombre}</td><td class="muted">\${s.documento||''}</td>
     <td><button class="danger" onclick="quitarInscripcion(\${s.enrollment_id})">Quitar</button></td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="3">Nadie inscrito todavía</td></tr>';
}
async function quitarInscripcion(id) {
  await api('/enrollments/'+id, { method:'DELETE' }); await cargarInscritos();
}

// ---- Asistencia ----
async function cargarAsistencia() {
  const courseId = document.getElementById('asisCurso').value;
  const fecha = document.getElementById('asisFecha').value;
  if (!courseId || !fecha) return;
  const list = await api('/attendance?course_id='+courseId+'&fecha='+fecha);
  document.getElementById('listaAsistencia').innerHTML = list.map(r => \`
    <tr data-enrollment="\${r.enrollment_id}">
      <td>\${r.nombre}</td>
      <td><div class="estado-btns">
        \${estados.map(e => \`<button class="\${r.estado===e?'sel-'+e:''}" onclick="marcar(this,\${r.enrollment_id},'\${e}')">\${e}</button>\`).join('')}
      </div></td>
    </tr>\`).join('') || '<tr><td class="muted" colspan="2">Este curso no tiene estudiantes inscritos</td></tr>';
}
function marcar(btn, enrollmentId, estado) {
  const row = btn.closest('tr');
  row.querySelectorAll('button').forEach(b => b.className = '');
  btn.className = 'sel-'+estado;
  row.dataset.estado = estado;
}
async function guardarAsistencia() {
  const fecha = document.getElementById('asisFecha').value;
  const rows = [...document.querySelectorAll('#listaAsistencia tr[data-enrollment]')];
  const registros = rows.filter(r => r.dataset.estado).map(r => ({ enrollment_id: r.dataset.enrollment, estado: r.dataset.estado }));
  const msgEl = document.getElementById('asisMsg');
  if (!registros.length) { msgEl.textContent='Marca al menos un estado'; msgEl.className='msg bad'; return; }
  try {
    await api('/attendance', { method:'POST', body: JSON.stringify({ fecha, registros }) });
    msgEl.textContent = 'Asistencia guardada ✓'; msgEl.className='msg ok';
  } catch(e) { msgEl.textContent = e.message; msgEl.className='msg bad'; }
}

// ---- Historial ----
async function cargarHistorial() {
  const courseId = document.getElementById('histCurso').value;
  if (!courseId) return;
  const list = await api('/courses/'+courseId+'/history');
  document.getElementById('listaHistorial').innerHTML = list.map(r =>
    \`<tr><td>\${r.nombre}</td><td>\${r.fecha}</td><td>\${r.estado}</td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="3">Sin registros aún</td></tr>';
}

// ---- Docentes (solo administrador) ----
async function cargarDocentes() {
  if (ROLE !== 'admin') return;
  const list = await api('/teachers');
  document.getElementById('listaDocentes').innerHTML = list.map(d =>
    \`<tr><td>\${d.nombre}</td><td class="muted">\${d.email}</td>
     <td><button class="danger" onclick="borrarDocente(\${d.id})">Eliminar</button></td></tr>\`
  ).join('') || '<tr><td class="muted" colspan="3">Sin docentes registrados aún</td></tr>';
}
async function crearDocente() {
  const nombre = document.getElementById('docNombre').value.trim();
  const email = document.getElementById('docEmail').value.trim();
  const password = document.getElementById('docPass').value;
  const msgEl = document.getElementById('docMsg');
  if (!nombre || !email || !password) { msgEl.textContent='Completa todos los campos'; msgEl.className='msg bad'; return; }
  try {
    await api('/teachers', { method:'POST', body: JSON.stringify({ nombre, email, password }) });
    msgEl.textContent = 'Docente registrado ✓'; msgEl.className='msg ok';
    ['docNombre','docEmail','docPass'].forEach(id=>document.getElementById(id).value='');
    await cargarDocentes();
  } catch(e) { msgEl.textContent = e.message; msgEl.className='msg bad'; }
}
async function borrarDocente(id) {
  if (!confirm('¿Eliminar este docente?')) return;
  await api('/teachers/'+id, { method:'DELETE' }); await cargarDocentes();
}

// Añade la carga de docentes cuando se entra como admin
const initAppOriginal = initApp;
initApp = async function() {
  await initAppOriginal();
  if (ROLE === 'admin') cargarDocentes();
};

// Si venimos de un enlace de QR, mostramos primero la pestaña de estudiante
if (CHECKIN_TOKEN) mostrarLogin('estudiante');

// Auto-login si ya hay sesión guardada
if (ROLE === 'admin' && API_KEY) {
  fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({apiKey:API_KEY}) })
    .then(r=>r.json()).then(d => { if (d.ok) entrarComo('admin'); });
} else if (ROLE === 'docente' && TOKEN) {
  fetch('/api/courses', { headers: { 'Authorization': 'Bearer ' + TOKEN } })
    .then(r => { if (r.ok) entrarComo('docente'); });
} else if (ROLE === 'estudiante' && TOKEN) {
  entrarComo('estudiante');
}
</script>
</body>
</html>`;